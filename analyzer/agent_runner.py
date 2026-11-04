"""Tác tử kiểm thử chức năng dùng 7 tool MCP trong ``browser_tools``.

Vòng lặp: navigate -> (inspect_page -> LLM chọn 1 hành động -> click/fill/get_text
-> screenshot) lặp lại cho tới khi LLM gọi ``finish`` hoặc hết số bước. Mọi thao
tác đi qua ``browser_tools`` nên được giới hạn scope theo host/CIDR, che password
và theo dõi redirect an toàn.

Kết quả trả về theo đúng shape mà ``_save_functional_run`` và template dashboard
đang dùng (step_id, action, value, expected, status, detail, evidence).
"""
import asyncio
import json
import re
import time

import requests

from browser_tools import tools
from browser_tools.session import BrowserSession


SYSTEM_RULES = (
    "Bạn là bộ điều khiển một trình duyệt ĐÃ MỞ SẴN trang web bên dưới. "
    "Bạn CÓ toàn quyền thao tác trang này thông qua các tool (click/fill/get_text/navigate). "
    "TUYỆT ĐỐI KHÔNG từ chối, KHÔNG nói 'tôi không có quyền truy cập', 'tôi không thể', "
    "'bạn cần tự kiểm tra'. Trang đã tải xong và danh sách phần tử bên dưới là thao tác được NGAY. "
    "Mỗi lượt chọn ĐÚNG MỘT hành động. Chỉ dùng 'ref' có trong danh sách phần tử, không bịa ref, "
    "không dùng CSS selector. "
    "Chỉ gọi 'finish' KHI: (a) đã thực hiện xong các thao tác cần thiết và quan sát được kết quả, "
    "hoặc (b) mục tiêu chỉ là kiểm tra tiêu đề/nội dung và bạn đã có đủ thông tin từ 'tieu_de_trang' "
    "hoặc get_text. Khi mục tiêu là kiểm tra tiêu đề: so sánh từ khóa mong đợi với 'tieu_de_trang' "
    "rồi finish với verdict phù hợp (PASS nếu khớp). "
    "Nếu mục tiêu là đăng nhập/điền form: điền LẦN LƯỢT từng ô (mỗi lượt một ô), rồi CLICK nút "
    "submit/Login, SAU ĐÓ mới finish. Nếu một ô input đã có sẵn giá trị đúng (xem trường 'value' của "
    "phần tử) thì ĐỪNG fill lại ô đó — chuyển sang ô CÒN TRỐNG kế tiếp, hoặc bấm nút submit nếu đã điền đủ. "
    "Ô mật khẩu đã điền sẽ hiển thị value='********' — ĐÓ LÀ ĐÃ ĐIỀN ĐÚNG, tuyệt đối không điền lại. "
    "KHÔNG lặp lại y hệt hành động vừa làm. "
    "KHI finish, PHẢI nêu 'check_value' = chuỗi chứng tỏ thành công (ví dụ 'Logout' sau đăng nhập, "
    "hoặc từ khóa tiêu đề), và 'check_type' = 'title_contains' hoặc 'body_contains'. Hệ thống sẽ TỰ ĐỌC "
    "trang để kiểm chứng: kết luận PASS chỉ được chấp nhận nếu chuỗi đó thực sự xuất hiện trên trang. "
    "Chỉ trả về JSON thuần, không markdown, không văn bản ngoài JSON."
)

FEWSHOT = {
    "vi_du_tieu_de": {
        "muc_tieu": "Xác thực tiêu đề trang chứa 'DVWA'",
        "tieu_de_trang": "Login :: Damn Vulnerable Web Application (DVWA)",
        "tra_ve": {"tool": "finish", "verdict": "PASS",
                   "reason": "tiêu đề chứa DVWA", "evidence": "Login :: ... (DVWA)"},
    },
    "vi_du_dang_nhap": {
        "muc_tieu": "Đăng nhập admin/password",
        "buoc": [
            {"tool": "fill", "ref": "e1", "value": "admin", "reason": "điền username"},
            {"tool": "fill", "ref": "e2", "value": "password", "reason": "điền password"},
            {"tool": "click", "ref": "e3", "reason": "bấm Login"},
        ],
    },
}


class FunctionalAgent:
    def __init__(self, ollama_model, ollama_url, allowed_hosts,
                 max_steps=12, timeout_ms=15000):
        self.ollama_model = ollama_model
        self.ollama_url = ollama_url
        self.allowed_hosts = allowed_hosts
        self.max_steps = max_steps
        self.timeout_ms = timeout_ms

    # ---- LLM ---------------------------------------------------------------
    def _ask_llm(self, prompt: str) -> str:
        payload = {"model": self.ollama_model, "prompt": prompt,
                   "stream": False, "format": "json",
                   "options": {"temperature": 0.1}}
        try:
            resp = requests.post(self.ollama_url, json=payload, timeout=60)
            resp.raise_for_status()
            return resp.json().get("response", "")
        except Exception:
            return ""

    INTERACTIVE_ROLES = {"textbox", "searchbox", "button", "link",
                         "combobox", "checkbox", "radio"}

    @staticmethod
    def _extract_success(goal):
        """Rút từ khóa báo hiệu thành công từ mục tiêu (vd 'Logout') để tự xác nhận."""
        m = re.search(r"(?:chữ|thấy|xuất hiện|hiển thị|text|từ khóa|chứa)\s+['\"]?([A-Za-zÀ-ỹ][\wÀ-ỹ]{1,30})",
                      goal, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"['\"]([A-Za-z][\w]{1,30})['\"]", goal)
        return m.group(1) if m else None

    @staticmethod
    def _sig(decision):
        return (f"{decision.get('tool')}:{decision.get('ref', '')}:"
                f"{str(decision.get('value', ''))[:30]}")

    def _decide(self, goal, page, history, nudge=False, loop=False, filled=None):
        # Ưu tiên phần tử tương tác lên đầu và cắt bớt để prompt gọn, model ít lạc.
        ordered = sorted(page.get("elements", []),
                         key=lambda e: 0 if e.get("role") in self.INTERACTIVE_ROLES else 1)
        elements = [
            {"ref": e.get("ref"), "role": e.get("role"), "name": e.get("name"),
             "type": e.get("type"), "value": e.get("value")}
            for e in ordered[:30]
        ]
        request_body = {
            "muc_tieu": goal,
            "tieu_de_trang": page.get("title"),
            "url_hien_tai": page.get("url"),
            "phan_tu": elements,
            "lich_su": history[-8:],
            "vi_du": FEWSHOT,
            "cac_tool": {
                "navigate": "value = URL (trong scope)",
                "click": "ref",
                "fill": "ref + value",
                "get_text": "ref (để rỗng = đọc toàn trang)",
                "finish": "verdict + check_type + check_value để hệ thống tự kiểm chứng",
            },
            "dinh_dang_tra_ve": {
                "tool": "navigate|click|fill|get_text|finish",
                "ref": "eN (nếu cần)",
                "value": "giá trị (nếu cần)",
                "reason": "lý do ngắn",
                "verdict": "PASS|FAIL (chỉ khi tool=finish)",
                "check_type": "title_contains|body_contains (khi finish)",
                "check_value": "chuỗi cần xuất hiện để coi là thành công (khi finish)",
                "evidence": "bằng chứng text (khi finish)",
            },
        }
        prompt = SYSTEM_RULES + "\n" + json.dumps(request_body, ensure_ascii=False)
        if nudge:
            prompt += ("\nCHÚ Ý: Bạn CHƯA thao tác gì và không được bỏ cuộc. "
                       "Hãy chọn một hành động cụ thể (fill/click/get_text) để tiến tới mục tiêu. "
                       "Nếu mục tiêu chỉ là kiểm tra tiêu đề thì so sánh với 'tieu_de_trang' rồi finish PASS/FAIL. "
                       "KHÔNG được finish FAIL với lý do từ chối truy cập.")
        if loop:
            done = ", ".join(f"{ref}={val}" for ref, val in (filled or {}).items()) or "(chưa điền ô nào)"
            buttons = [e.get("ref") for e in page.get("elements", [])
                       if e.get("role") == "button" or e.get("type") == "submit"]
            btn_hint = f" Các nút có thể bấm: {buttons}." if buttons else ""
            prompt += (f"\nCHÚ Ý: Bạn vừa LẶP LẠI hành động đã làm. Các ô đã điền: {done}.{btn_hint} "
                       "ĐỪNG lặp lại hành động đó. Hãy chọn hành động KHÁC để tiến tới: điền ô CÒN TRỐNG "
                       "tiếp theo, hoặc CLICK nút submit/Login nếu đã điền đủ, hoặc get_text/finish nếu đã xong.")
        raw = self._ask_llm(prompt)
        return self._parse(raw)

    @staticmethod
    def _parse(raw: str) -> dict:
        if not raw:
            return {"tool": "finish", "verdict": "FAIL",
                    "reason": "LLM không phản hồi", "evidence": ""}
        text = raw.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        try:
            data = json.loads(text)
            if isinstance(data, dict) and data.get("tool"):
                return data
        except Exception:
            pass
        return {"tool": "finish", "verdict": "FAIL",
                "reason": "Không phân tích được phản hồi LLM", "evidence": ""}

    # ---- Thực thi ----------------------------------------------------------
    @staticmethod
    def _mk(step_no, action, value, goal, env, shot, reason="", step_status=None,
            duration_ms=None):
        env = env or {}
        ok = bool(env.get("ok"))
        if step_status is None:
            step_status = "PASS" if ok else "FAIL"
        data = env.get("data") or {}
        if ok:
            detail = reason or ""
            if action == "get_text":
                detail += f" | text: {str(data.get('text', ''))[:160]}"
            elif action in ("navigate", "click"):
                detail += f" | url: {data.get('url') or data.get('url_after', '')}"
            elif action == "finish":
                detail += f" | {data.get('evidence', '')}"
        else:
            err = env.get("error") or {}
            detail = f"{reason} | lỗi {err.get('code')}: {err.get('message')}"
        evidence = ""
        if shot and shot.get("ok"):
            evidence = (shot.get("data") or {}).get("path", "")
        return {"step_id": step_no, "action": action, "value": value,
                "expected": goal, "status": step_status,
                "detail": detail.strip(" |"), "evidence": evidence,
                "duration_ms": duration_ms}

    async def _exec(self, session, tool, decision, step_no):
        ref = decision.get("ref", "") or ""
        value = decision.get("value", "") or ""
        if tool == "click":
            env = await tools.click(session, ref)
        elif tool == "fill":
            env = await tools.fill(session, ref, value)
        elif tool == "get_text":
            env = await tools.get_text(session, ref)
        elif tool == "navigate":
            env = await tools.navigate(session, value)
        else:
            env = {"ok": False, "data": None,
                   "error": {"code": "INVALID_ARGUMENT", "message": f"Tool không hợp lệ: {tool}"}}
        shot = await tools.screenshot(session, f"step_{step_no}")
        return env, shot

    async def _verify(self, session, page, check_type, check_value):
        """Tự đọc trang để kiểm chứng khách quan chuỗi thành công do LLM nêu."""
        needle = check_value.lower()
        title = str(page.get("title", "")).lower()
        body = ""
        gt = await tools.get_text(session, "")
        if gt.get("ok"):
            body = str((gt.get("data") or {}).get("text", "")).lower()
        if check_type == "title_contains":
            hay = title
        elif check_type == "body_contains":
            hay = body
        else:
            hay = title + "\n" + body
        found = needle in hay
        note = f"Kiểm chứng '{check_value}': {'khớp trên trang' if found else 'KHÔNG thấy trên trang'}"
        return found, note

    async def _loop(self, session, target_url, goal, initial_navigate=True):
        results = []
        step_no = 0
        if initial_navigate:
            step_no = 1
            t0 = time.perf_counter()
            nav = await tools.navigate(session, target_url)
            shot = await tools.screenshot(session, f"step_{step_no}")
            results.append(self._mk(step_no, "navigate", target_url, goal, nav, shot,
                                    reason="Mở trang mục tiêu",
                                    duration_ms=int((time.perf_counter() - t0) * 1000)))
            if not nav.get("ok"):
                return {"status": "FAIL", "goal": goal, "results": results}
            history = [f"navigate({target_url}) -> ok"]
        else:
            # Tiếp tục từ trang hiện tại (giai đoạn điều hướng sau đăng nhập).
            history = ["(tiếp tục từ trang đang mở)"]
        final_status = "FAIL"
        acted = False
        seen = {}
        filled = {}
        success_kw = self._extract_success(goal)
        for _ in range(self.max_steps):
            insp = await tools.inspect_page(session)
            if not insp.get("ok"):
                step_no += 1
                results.append(self._mk(step_no, "inspect_page", "", goal, insp, None,
                                        reason="Không đọc được phần tử trang"))
                break
            page = insp.get("data") or {}
            # Tự xác nhận: nếu đã thao tác và thấy từ khóa thành công trên trang -> PASS ngay.
            if success_kw and acted:
                hay = (str(page.get("title", "")) + " " +
                       " ".join(str(e.get("name", "")) for e in page.get("elements", []))).lower()
                if success_kw.lower() in hay:
                    step_no += 1
                    env = {"ok": True, "data": {"evidence": f"Thấy '{success_kw}' trên trang"}, "error": None}
                    results.append(self._mk(step_no, "finish", "", goal, env, None,
                                            reason=f"Tự xác nhận mục tiêu: thấy '{success_kw}'",
                                            step_status="PASS"))
                    final_status = "PASS"
                    break
            decision = self._decide(goal, page, history)
            # Chống bỏ cuộc sớm: nếu chưa thao tác gì mà đã finish FAIL -> ép hỏi lại 1 lần.
            if (decision.get("tool") == "finish" and not acted
                    and (decision.get("verdict") or "FAIL").upper() != "PASS"):
                decision = self._decide(goal, page, history, nudge=True)
            # Lặp lại hành động, hoặc điền lại ô đã điền -> đẩy sang hành động khác.
            repeat = seen.get(self._sig(decision), 0) >= 1
            refill = decision.get("tool") == "fill" and decision.get("ref") in filled
            if decision.get("tool") != "finish" and (repeat or refill):
                decision = self._decide(goal, page, history, loop=True, filled=filled)
                # Nếu model VẪN cố điền ô đã điền -> tự chuyển sang bấm nút submit (nếu có).
                if decision.get("tool") == "fill" and decision.get("ref") in filled:
                    btn = next((e.get("ref") for e in page.get("elements", [])
                                if e.get("role") == "button" or e.get("type") == "submit"), None)
                    if btn:
                        decision = {"tool": "click", "ref": btn,
                                    "reason": "Đã điền đủ các ô -> tự bấm nút submit"}
            tool = decision.get("tool")
            reason = decision.get("reason", "")

            if tool == "finish":
                verdict = (decision.get("verdict") or "FAIL").upper()
                check_value = str(decision.get("check_value", "")).strip()
                check_type = str(decision.get("check_type", "")).lower()
                verified, note = await self._verify(session, page, check_type, check_value)
                if check_value:
                    # Kết luận PASS phải được kiểm chứng khách quan từ nội dung trang.
                    final_status = "PASS" if (verdict == "PASS" and verified) else "FAIL"
                    reason = f"{reason} | {note}"
                else:
                    final_status = "PASS" if verdict == "PASS" else "FAIL"
                    reason = f"{reason} | (chưa xác minh khách quan)"
                step_no += 1
                env = {"ok": True, "data": {"evidence": decision.get("evidence", "")},
                       "error": None}
                results.append(self._mk(step_no, "finish", "", goal, env, None,
                                        reason=reason, step_status=final_status))
                break

            # Nếu vẫn lặp lại sau khi đã được đẩy -> dừng để tránh kẹt.
            sig = self._sig(decision)
            if seen.get(sig, 0) >= 2:
                step_no += 1
                results.append(self._mk(step_no, tool, decision.get("value", ""), goal,
                                        {"ok": False, "data": None,
                                         "error": {"code": "LOOP", "message": "Lặp hành động quá nhiều"}},
                                        None, reason="Phát hiện lặp hành động -> dừng", step_status="FAIL"))
                final_status = "FAIL"
                break
            seen[sig] = seen.get(sig, 0) + 1

            step_no += 1
            t_step = time.perf_counter()
            env, shot = await self._exec(session, tool, decision, step_no)
            if tool in ("click", "fill", "get_text", "navigate") and env.get("ok"):
                acted = True
                if tool == "fill":
                    filled[decision.get("ref", "")] = decision.get("value", "")
            results.append(self._mk(step_no, tool, decision.get("value", ""), goal,
                                    env, shot, reason=reason,
                                    duration_ms=int((time.perf_counter() - t_step) * 1000)))
            summary = "ok" if env.get("ok") else (env.get("error") or {}).get("code")
            history.append(f"{tool}(ref={decision.get('ref', '')},value={str(decision.get('value', ''))[:20]}) -> {summary}")
        else:
            # Hết số bước mà chưa finish.
            final_status = "FAIL"

        return {"status": final_status, "goal": goal, "results": results}

    def run(self, run_id, target_url, goal):
        """Điểm vào đồng bộ cho Django view (tự quản vòng lặp asyncio)."""
        async def _main():
            async with BrowserSession(run_id, self.allowed_hosts,
                                      timeout_ms=self.timeout_ms) as session:
                return await self._loop(session, target_url, goal)
        return asyncio.run(_main())

    def run_with_cookies(self, run_id, target_url, goal):
        """Như run() nhưng trả thêm cookie phiên trình duyệt sau khi chạy xong.

        Dùng để nối luồng: Agent đăng nhập -> lấy cookie phiên -> quét bảo mật
        trang cần đăng nhập bằng chính phiên đó.
        """
        async def _main():
            async with BrowserSession(run_id, self.allowed_hosts,
                                      timeout_ms=self.timeout_ms) as session:
                outcome = await self._loop(session, target_url, goal)
                cookies = []
                try:
                    if session._context is not None:
                        cookies = await session._context.cookies()
                except Exception:
                    cookies = []
                return outcome, cookies
        return asyncio.run(_main())

    def run_auth_security(self, run_id, login_url, login_goal, nav_goal):
        """Hai pha trong CÙNG một phiên trình duyệt:
        1) đăng nhập theo login_goal;
        2) tự điều hướng theo nav_goal (prompt bảo mật, vd 'vào mục SQL Injection').
        Trả: (login_outcome, nav_outcome, url_hiện_tại, cookies) để quét tiếp.
        """
        async def _main():
            async with BrowserSession(run_id, self.allowed_hosts,
                                      timeout_ms=self.timeout_ms) as session:
                login_outcome = await self._loop(session, login_url, login_goal)
                nav_outcome = await self._loop(session, None, nav_goal, initial_navigate=False)
                cur = await tools.get_current_url(session)
                url = (cur.get("data") or {}).get("url") if cur.get("ok") else None
                cookies = []
                try:
                    if session._context is not None:
                        cookies = await session._context.cookies()
                except Exception:
                    cookies = []
                return login_outcome, nav_outcome, url, cookies
        return asyncio.run(_main())
