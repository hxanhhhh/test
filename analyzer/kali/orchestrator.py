"""Điều phối chuỗi tool Kali trên một mục tiêu lab.

Hai chế độ:
  * run_pipeline(): PIPELINE CỐ ĐỊNH (lõi, không cần LLM) — ổn định khi demo.
      recon(nmap) -> theo dịch vụ chọn scanner -> vuln -> khai thác (nếu có URL/param)
  * run_agent():  LỚP AGENT chọn tool 2 cấp (nhóm -> tool) bằng LLM (Ollama).
      Nếu LLM lỗi/không có, tự fallback về run_pipeline().

Mọi tool đều đã guard() chỉ chạy host lab. Orchestrator kiểm guard một lần ở đầu.
"""
import json

from analyzer.kali import build_registry
from analyzer.kali.base import guard, target_host

# Cổng/dịch vụ coi là web.
WEB_PORTS = {80, 443, 8080, 8000, 8443, 8888, 3000, 5000}
HTTPS_PORTS = {443, 8443}
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
# Chỉ các tool auto-chạy được (tham số nằm trong tập này) mới cho agent chọn.
AUTO_PARAMS = {"target", "url", "cookie"}


# ----------------------------------------------------------------------------
# Tiện ích
# ----------------------------------------------------------------------------
def _is_web(services):
    for s in services:
        if s.get("port") in WEB_PORTS or "http" in (s.get("name", "") or "").lower():
            return True
    return False


def _is_https(services):
    for s in services:
        name = (s.get("name", "") or "").lower()
        if s.get("port") in HTTPS_PORTS or "https" in name or "ssl" in name:
            return True
    return False


def _default_url(host, https):
    scheme = "https" if https else "http"
    return f"{scheme}://{host}"


def _summary(findings, n_tools):
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev = f.get("severity", "Info")
        counts[sev] = counts.get(sev, 0) + 1
    counts["total"] = len(findings)
    counts["tools_run"] = n_tools
    return counts


def _auto_kwargs(params, host, url, cookie):
    """Điền tham số tự động cho một tool từ ngữ cảnh."""
    kw = {}
    for p in params:
        if p == "target":
            kw[p] = host
        elif p == "url":
            kw[p] = url
        elif p == "cookie":
            kw[p] = cookie or ""
    return kw


# ----------------------------------------------------------------------------
# PIPELINE CỐ ĐỊNH
# ----------------------------------------------------------------------------
def plan_pipeline(services, url, has_param, https, force_web=False):
    """Trả danh sách bước (tool, kwargs) theo dịch vụ phát hiện — test được riêng.

    force_web=True khi người dùng đã nhập URL cụ thể: chạy tool web dù nmap không
    bắt được cổng (vd cổng 3000/8080 ngoài top-ports)."""
    steps = []
    web = force_web or _is_web(services)
    if web:
        steps.append(("whatweb", {"url": url}))
        steps.append(("dirsearch", {"url": url}))
        steps.append(("nuclei", {"url": url}))
        steps.append(("nikto", {"url": url}))
    if https:
        steps.append(("sslscan", {"target": None}))   # host điền sau
    if web and has_param:
        steps.append(("sqlmap", {"url": url}))         # cookie điền sau
        steps.append(("dalfox", {"url": url}))
    return steps


def run_pipeline(target, url=None, cookie="", client=None, on_step=None):
    """Chạy pipeline cố định. on_step(step_dict) được gọi sau mỗi tool (cho UI)."""
    host = target_host(target)
    if not guard(host):
        return {"ok": False, "lab": False, "target": host, "steps": [],
                "findings": [], "summary": _summary([], 0),
                "error": "Mục tiêu không phải host lab (loopback/IP private)."}

    client = client or build_registry().client
    reg = build_registry(client)
    steps, findings = [], []

    def _run(tool, **kw):
        res = reg.call(tool, **kw)
        fs = res.get("findings", []) or []
        step = {"tool": tool, "title": reg.tools.get(tool, {}).get("title", tool),
                "ok": res.get("ok", False), "command": res.get("command", ""),
                "n_findings": len(fs), "findings": fs, "raw": res.get("raw", "")}
        steps.append(step)
        findings.extend(fs)
        if on_step:
            on_step(step)
        return res

    # 1) Recon
    nmap_res = _run("nmap", target=host)
    services = nmap_res.get("services", []) or []
    web_forced = bool(url)  # người dùng nhập URL cụ thể -> chắc chắn có web
    https = _is_https(services) or (url or "").lower().startswith("https")
    target_url = url or _default_url(host, https)
    has_param = "?" in (target_url or "")

    # 2..N) Theo kế hoạch
    for tool, kw in plan_pipeline(services, target_url, has_param, https, web_forced):
        if "target" in kw and kw["target"] is None:
            kw["target"] = host
        if tool == "sqlmap":
            kw["cookie"] = cookie or ""
        _run(tool, **kw)

    ok = any(s["ok"] for s in steps) or bool(services)
    return {"ok": ok, "lab": True, "mode": "pipeline",
            "target": host, "url": target_url, "services": services,
            "steps": steps, "findings": findings,
            "summary": _summary(findings, len(steps))}


# ----------------------------------------------------------------------------
# LỚP AGENT (LLM chọn tool 2 cấp)
# ----------------------------------------------------------------------------
def _auto_catalog(reg):
    """Nhóm -> [(name, title)] cho các tool auto-chạy được (params ⊆ AUTO_PARAMS)."""
    cat = {}
    for t in reg.list():
        if set(t["params"]) <= AUTO_PARAMS:
            cat.setdefault(t["category"], []).append((t["name"], t["title"]))
    return cat


def _ask_llm(prompt, timeout=60):
    from django.conf import settings
    import requests
    r = requests.post(settings.OLLAMA_URL, json={
        "model": settings.OLLAMA_MODEL, "prompt": prompt,
        "stream": False, "format": "json"}, timeout=timeout)
    r.raise_for_status()
    return json.loads(r.json()["response"])


def _agent_prompt(host, url, catalog, ran, findings, has_cookie: bool = False):
    lines = ["Bạn là agent kiểm thử bảo mật web trên LAB được phép.",
             f"Mục tiêu: host={host} url={url}",
             f"Phiên xác thực: {"có cookie đăng nhập (tự động gắn vào sqlmap/dalfox)" if has_cookie else "chưa có cookie"}.",
             "Chọn BƯỚC TIẾP THEO: một tool trong danh mục (theo nhóm).",
             "Quy tắc: recon nhẹ (whatweb), ưu tiên sqlmap/dalfox khi url có tham số truy vấn (?);",
             "tránh wpscan nếu không phải WordPress. Không lặp lại tool đã chạy.",
             "", "Danh mục tool (nhóm -> tool):"]
    for c, items in catalog.items():
        lines.append(f"- {c}: " + ", ".join(n for n, _ in items))
    lines.append("")
    lines.append("Đã chạy: " + (", ".join(ran) if ran else "(chưa có)"))
    lines.append(f"Số phát hiện hiện tại: {len(findings)}")
    lines.append("")
    lines.append('Trả JSON: {"category":"<nhóm>","tool":"<tên tool>","reason":"<ngắn>"}')
    lines.append('Nếu đã đủ thông tin, trả {"done": true}.')
    return "\n".join(lines)


def run_agent(target, url=None, cookie="", client=None, max_steps=6, on_step=None):
    """Agent dùng LLM chọn tool từng bước. Lỗi LLM -> fallback run_pipeline()."""
    host = target_host(target)
    if not guard(host):
        return run_pipeline(target, url=url, cookie=cookie, client=client, on_step=on_step)

    client = client or build_registry().client
    reg = build_registry(client)
    catalog = _auto_catalog(reg)
    valid = {n for items in catalog.values() for n, _ in items}

    # Lấy https từ nmap đầu tiên để dựng URL mặc định.
    nmap_res = reg.call("nmap", target=host)
    services = nmap_res.get("services", []) or []
    target_url = url or _default_url(host, _is_https(services))

    steps, findings, ran = [], [], []

    def _record(tool, res):
        fs = res.get("findings", []) or []
        step = {"tool": tool, "title": reg.tools.get(tool, {}).get("title", tool),
                "ok": res.get("ok", False), "command": res.get("command", ""),
                "n_findings": len(fs), "findings": fs, "raw": res.get("raw", "")}
        steps.append(step); findings.extend(fs); ran.append(tool)
        if on_step:
            on_step(step)

    _record("nmap", nmap_res)

    for _ in range(max_steps - 1):
        try:
            pick = _ask_llm(_agent_prompt(host, target_url, catalog, ran, findings, has_cookie=bool(cookie)))
        except Exception:
            # LLM không dùng được -> chuyển sang pipeline cho phần còn lại.
            pipe = run_pipeline(target, url=target_url, cookie=cookie,
                                client=client, on_step=on_step)
            # gộp các bước pipeline chưa chạy
            for st in pipe["steps"]:
                if st["tool"] not in ran:
                    steps.append(st); findings.extend(st["findings"]); ran.append(st["tool"])
            return {"ok": True, "lab": True, "mode": "agent+fallback",
                    "target": host, "url": target_url, "services": services,
                    "steps": steps, "findings": findings,
                    "summary": _summary(findings, len(steps))}

        if pick.get("done"):
            break
        tool = pick.get("tool")
        if tool not in valid or tool in ran:
            continue
        kw = _auto_kwargs(reg.tools[tool]["params"], host, target_url, cookie)
        _record(tool, reg.call(tool, **kw))

    return {"ok": True, "lab": True, "mode": "agent",
            "target": host, "url": target_url, "services": services,
            "steps": steps, "findings": findings,
            "summary": _summary(findings, len(steps))}
