import re
import asyncio
import os
from pathlib import Path
import sys
from uuid import uuid4
import urllib.error
import urllib.request
import json

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from browser_tools import BrowserSession
from scripts.demo_common import find, step

DVWA_BASE = os.getenv("DVWA_BASE", "http://127.0.0.1:4280")
import urllib.parse

def _set_dvwa_security_low(cookie_header: str) -> str:
    match = re.search(r"PHPSESSID=([^;]+)", cookie_header)
    if not match:
        return cookie_header
    sess_id = match.group(1).strip()
    headers = {"Cookie": f"PHPSESSID={sess_id}", "User-Agent": "Mozilla/5.0"}

    req = urllib.request.Request(f"{DVWA_BASE}/security.php", headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=15) as resp:
        html = resp.read().decode("utf-8", errors="replace")

    token_match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", html)
    payload = {"security": "low", "seclev_submit": "Submit"}
    if token_match:
        payload["user_token"] = token_match.group(1)

    encoded = urllib.parse.urlencode(payload).encode("utf-8")
    post_headers = {
        **headers,
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": f"{DVWA_BASE}/security.php",
    }
    post_req = urllib.request.Request(f"{DVWA_BASE}/security.php", data=encoded, headers=post_headers, method="POST")
    with urllib.request.urlopen(post_req, timeout=15) as resp:
        set_cookies = resp.headers.get_all("Set-Cookie") or []
        resp_body = resp.read().decode("utf-8", errors="replace")
    print(f"[*] security.php token={token_match.group(1) if token_match else None} set_cookies={set_cookies}", flush=True)

    cookies_map = {}
    for part in cookie_header.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            cookies_map[k.strip()] = v.strip()
    cookies_map["PHPSESSID"] = sess_id
    cookies_map["security"] = "low"
    for sc in set_cookies:
        kv = sc.split(";", 1)[0]
        if "=" in kv:
            k, v = kv.split("=", 1)
            if k.strip() in ("PHPSESSID", "security"):
                cookies_map[k.strip()] = v.strip()
    return "; ".join(f"{k}={v}" for k, v in cookies_map.items())

KALI_API = os.getenv("KALI_API", "http://127.0.0.1:5000/api/command")


def send_kali_command(command: str):
    req = urllib.request.Request(
        KALI_API,
        data=json.dumps({"command": command}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        return None, str(exc)


async def login_dvwa(session: BrowserSession):
    await step(session, "navigate", url=f"{DVWA_BASE}/login.php")
    username = await find(session, lambda e: e["role"] == "textbox" and e["type"] != "password")
    password = await find(session, lambda e: e["type"] == "password")
    await step(session, "fill", ref=username, value="admin")
    await step(session, "fill", ref=password, value="password")
    login_btn = await find(session, lambda e: e["role"] == "button" and "login" in e["name"].lower())
    await step(session, "click", ref=login_btn)

    url_info = await step(session, "get_current_url")
    current_url = (url_info.get("data") or {}).get("url", "")
    if "setup.php" in current_url:
        reset_btn = await find(
            session,
            lambda e: e["role"] == "button" and "database" in e["name"].lower(),
        )
        await step(session, "click", ref=reset_btn)
        await asyncio.sleep(3)
        await step(session, "navigate", url=f"{DVWA_BASE}/login.php")
        username2 = await find(session, lambda e: e["role"] == "textbox" and e["type"] != "password")
        password2 = await find(session, lambda e: e["type"] == "password")
        await step(session, "fill", ref=username2, value="admin")
        await step(session, "fill", ref=password2, value="password")
        login_btn2 = await find(session, lambda e: e["role"] == "button" and "login" in e["name"].lower())
        await step(session, "click", ref=login_btn2)

    await find(session, lambda e: e["role"] == "link" and "logout" in e["name"].lower())

    cookie_res = await session.get_cookies(f"{DVWA_BASE}/")
    if not cookie_res["ok"]:
        raise RuntimeError(f"Failed to extract cookies: {cookie_res['error']}")
    return _set_dvwa_security_low(cookie_res["data"]["cookie_header"])


import subprocess
import time

DVWA_CONTAINER = os.getenv("DVWA_CONTAINER", "dvwa-web")
MAX_TARGET_RESTARTS = int(os.getenv("MAX_TARGET_RESTARTS", "2"))


def is_target_alive(url: str = DVWA_BASE, timeout: float = 3.0) -> bool:
    """Kiểm tra nhanh xem mục tiêu lab có phản hồi HTTP/TCP hay đang chết."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 500
    except urllib.error.HTTPError as exc:
        # 302/401/403 vẫn nghĩa là web server đang sống; 502/503/504 coi như chưa sẵn sàng
        return exc.code not in (502, 503, 504)
    except Exception:
        return False


def restart_lab_target(
    container_name: str = DVWA_CONTAINER,
    target_url: str = DVWA_BASE,
    wait_seconds: int = 25,
) -> dict:
    """Khởi động lại container mục tiêu lab và chờ sẵn sàng trở lại."""
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            ["docker", "restart", container_name],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception as exc:
        return {"ok": False, "container": container_name, "error": str(exc), "elapsed_s": round(time.perf_counter() - t0, 2)}

    if proc.returncode != 0:
        return {
            "ok": False,
            "container": container_name,
            "error": (proc.stderr or proc.stdout or f"rc={proc.returncode}").strip(),
            "elapsed_s": round(time.perf_counter() - t0, 2),
        }

    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if is_target_alive(target_url, timeout=2.5):
            time.sleep(1.0)
            return {
                "ok": True,
                "container": container_name,
                "elapsed_s": round(time.perf_counter() - t0, 2),
            }
        time.sleep(1.0)

    return {
        "ok": False,
        "container": container_name,
        "error": f"Timeout {wait_seconds}s chờ {target_url} phản hồi sau restart",
        "elapsed_s": round(time.perf_counter() - t0, 2),
    }


def _response_indicates_target_down(status_code, body_text: str) -> bool:
    txt = (body_text or "").lower()
    if status_code in (None, 0, 502, 503, 504):
        return True
    down_markers = (
        "connection refused",
        "failed to establish a new connection",
        "connection reset",
        "max retries exceeded",
        "empty reply from server",
        "couldn't connect to server",
        "bad gateway",
        "service unavailable",
    )
    return any(m in txt for m in down_markers)


def run_kali_command_with_recovery(
    command: str,
    target_url: str = DVWA_BASE,
    container_name: str = DVWA_CONTAINER,
    max_restarts: int = MAX_TARGET_RESTARTS,
    on_recover=None,
):
    """Chạy lệnh qua Kali API; nếu phát hiện mục tiêu chết giữa chừng thì restart và chạy lại."""
    restarts_used = 0
    recovery_events = []

    while True:
        if not is_target_alive(target_url, timeout=2.5):
            if restarts_used >= max_restarts:
                status_code, body = send_kali_command(command)
                return status_code, body, restarts_used, recovery_events
            restarts_used += 1
            rec = restart_lab_target(container_name=container_name, target_url=target_url)
            recovery_events.append(f"pre-check restart#{restarts_used}: ok={rec['ok']} ({rec.get('elapsed_s')}s)")
            if rec["ok"] and callable(on_recover):
                on_recover()

        status_code, body = send_kali_command(command)
        if not _response_indicates_target_down(status_code, body):
            return status_code, body, restarts_used, recovery_events

        if restarts_used >= max_restarts:
            return status_code, body, restarts_used, recovery_events

        restarts_used += 1
        rec = restart_lab_target(container_name=container_name, target_url=target_url)
        recovery_events.append(f"mid-scan restart#{restarts_used}: ok={rec['ok']} ({rec.get('elapsed_s')}s)")
        if not rec["ok"]:
            return status_code, body, restarts_used, recovery_events
        if callable(on_recover):
            on_recover()
async def main():
    from core_agent.functional_engine import FunctionalTestEngine

    async with BrowserSession(f"auth-{uuid4().hex}", ["127.0.0.1"]) as session:
        cookie_header = await login_dvwa(session)
        cookie_header = re.sub(r"\bsecurity=[^;]+", "security=low", cookie_header)
        print(f"[+] Cookie header: {cookie_header}", flush=True)

    target_url = f"{DVWA_BASE}/vulnerabilities/sqli/?id=1&Submit=Submit"
    if not is_target_alive(target_url):
        rec = restart_lab_target()
        print(f"[!] Pre-scan restart: {rec}", flush=True)
        async with BrowserSession(f"auth-{uuid4().hex}", ["127.0.0.1"]) as session:
            cookie_header = await login_dvwa(session)
            cookie_header = re.sub(r"\bsecurity=[^;]+", "security=low", cookie_header)

    engine = FunctionalTestEngine()
    pentest_res = await asyncio.to_thread(
        engine.run_pentest,
        target="127.0.0.1",
        url=target_url,
        cookie=cookie_header,
        use_agent=True,
        max_steps=4,
        save=True,
        project_name="DVWA Auth Pentest",
    )
    print("[+] Pentest summary:", json.dumps(pentest_res, indent=2, ensure_ascii=False, default=str), flush=True)

if __name__ == "__main__":
    asyncio.run(main())
