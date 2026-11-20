import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from analyzer.agent_runner import FunctionalAgent
from scripts.auth_scan_dvwa import (
    DVWA_BASE,
    _summarize_tool_output,
    send_kali_command,
)


def _format_cookie_header(cookies: list[dict], force_security_low: bool = True) -> str:
    pairs: dict[str, str] = {}
    for c in cookies or []:
        name = c.get("name")
        value = c.get("value")
        if name and value is not None:
            pairs[str(name)] = str(value)
    if force_security_low:
        pairs["security"] = "low"
    header = "; ".join(f"{k}={v}" for k, v in pairs.items())
    return re.sub(r"\bsecurity=[^;]+", "security=low", header)


def main() -> None:
    ollama_model = os.getenv("OLLAMA_MODEL", "qwen2.5:7b-instruct")
    ollama_url = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
    run_id = f"full-agent-{uuid4().hex[:8]}"
    started_at = datetime.now(timezone.utc).isoformat()
    trace: list[dict] = []

    def log_step(stage: str, event: str, payload: dict) -> None:
        item = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "stage": stage,
            "event": event,
            "payload": payload,
        }
        trace.append(item)
        print(f"[FULL_AGENT][{stage}] {event}: {payload}", flush=True)

    agent = FunctionalAgent(
        ollama_model=ollama_model,
        ollama_url=ollama_url,
        allowed_hosts=["127.0.0.1"],
    )

    login_url = f"{DVWA_BASE}/login.php"
    login_goal = (
        "Điền username 'admin', password 'password', bấm Login. "
        "Khi URL đã chuyển sang index.php hoặc thấy 'Logout', NGAY LẬP TỨC gọi tool finish "
        "với verdict='PASS', check_type='body_contains', check_value='Logout'."
    )
    nav_goal = (
        "Bấm link 'SQL Injection' trên menu. "
        "Khi URL đã chứa '/vulnerabilities/sqli/', NGAY LẬP TỨC gọi tool finish "
        "với verdict='PASS', check_type='body_contains', check_value='SQL injection'."
    )

    log_step("auth", "start_run_auth_security", {
        "login_url": login_url,
        "model": ollama_model,
        "nav_goal": nav_goal,
    })

    login_outcome, nav_outcome, current_url, cookies = agent.run_auth_security(
        run_id=run_id,
        login_url=login_url,
        login_goal=login_goal,
        nav_goal=nav_goal,
    )

    cookie_header = _format_cookie_header(cookies, force_security_low=True)
    log_step("auth", "session_ready", {
        "login_status": (login_outcome or {}).get("status"),
        "nav_status": (nav_outcome or {}).get("status"),
        "current_url": current_url,
        "cookie_header": cookie_header,
    })

    targets = [
        (
            "sqlmap",
            f'sqlmap -u "{DVWA_BASE}/vulnerabilities/sqli/?id=1&Submit=Submit" '
            f'--cookie="{cookie_header}" --batch --level=1 --risk=1',
        ),
        (
            "dalfox",
            f'dalfox url "{DVWA_BASE}/vulnerabilities/xss_r/?name=test" '
            f'--cookies "{cookie_header}"',
        ),
    ]

    scan_results: dict[str, dict] = {}
    for name, cmd in targets:
        log_step("scan", "dispatch_command", {"tool": name, "command": cmd})
        status, body = send_kali_command(cmd)
        try:
            parsed = json.loads(body) if isinstance(body, str) else (body or {})
        except Exception as exc:
            parsed = {"parse_error": str(exc), "raw_body": body}

        data_obj = (
            parsed.get("data")
            if isinstance(parsed, dict) and isinstance(parsed.get("data"), dict)
            else parsed
        )
        rc = data_obj.get("return_code") if isinstance(data_obj, dict) else None
        timed_out = bool(data_obj.get("timed_out")) if isinstance(data_obj, dict) else False
        stdout = (data_obj.get("stdout") or "") if isinstance(data_obj, dict) else ""

        execution_ok = (not timed_out) and (rc in (0, 1))
        vulnerability_detected = (
            ("Parameter:" in stdout or "Type:" in stdout)
            if name == "sqlmap"
            else ("[POC" in stdout or "XSS found" in stdout)
        )

        scan_results[name] = {
            "status": status,
            "response": parsed,
            "execution_ok": execution_ok,
            "vulnerability_detected": vulnerability_detected,
        }

        if isinstance(data_obj, dict):
            _summarize_tool_output(name, data_obj)

        log_step("scan", "scanner_result_evaluated", {
            "tool": name,
            "status": status,
            "return_code": rc,
            "timed_out": timed_out,
            "execution_ok": execution_ok,
            "vulnerability_detected": vulnerability_detected,
        })

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    Path("/tmp/dvwa_scan_last.json").write_text(
        json.dumps(scan_results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    audit_path = Path(f"/tmp/dvwa_full_agent_{stamp}.json")
    audit_path.write_text(
        json.dumps(
            {
                "run_id": run_id,
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "login_outcome": login_outcome,
                "nav_outcome": nav_outcome,
                "current_url": current_url,
                "cookie_header": cookie_header,
                "results": scan_results,
                "trace": trace,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    print(f"[+] Saved audit file: {audit_path}", flush=True)


if __name__ == "__main__":
    main()
