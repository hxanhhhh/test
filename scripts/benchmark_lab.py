#!/usr/bin/env python3
"""Đo đạc (benchmark) tác tử kiểm thử chức năng + trinh sát bảo mật trên lab.

Chạy một loạt kịch bản cố định trên DVWA/Juice Shop, thu số liệu định lượng cho
báo cáo đồ án: độ chính xác (status so với kỳ vọng), số bước, thời gian mỗi
kịch bản, và thống kê phát hiện bảo mật theo mức độ.

Yêu cầu: lab đang chạy (docker compose) và Ollama đang chạy.
    python scripts/benchmark_lab.py
    python scripts/benchmark_lab.py --model qwen2.5:7b-instruct --only functional

Kết quả in ra bảng và lưu JSON tại media/benchmarks/.
"""
import argparse
import json
import os
import statistics
import sys
import time
from datetime import datetime

# Cho phép import gói của repo khi chạy trực tiếp từ scripts/.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from analyzer.agent_runner import FunctionalAgent          # noqa: E402
from core_agent.security_engine import SecurityTestEngine  # noqa: E402

DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:3b")
DEFAULT_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")

FUNCTIONAL_SCENARIOS = [
    {"name": "DVWA - tiêu đề trang login",
     "url": "http://127.0.0.1:4280/login.php",
     "goal": "Xác thực tiêu đề trang có chứa 'DVWA'",
     "expect": "PASS", "hosts": ["127.0.0.1"]},
    {"name": "DVWA - đăng nhập admin/password",
     "url": "http://127.0.0.1:4280/login.php",
     "goal": ("Điền 'admin' vào ô Username, 'password' vào ô Password, bấm Login; "
              "xác nhận đăng nhập thành công khi trang có chữ Logout"),
     "expect": "PASS", "hosts": ["127.0.0.1"]},
    {"name": "Juice Shop - tiêu đề trang chủ",
     "url": "http://127.0.0.1:3000/",
     "goal": "Xác thực tiêu đề trang có chứa 'Juice Shop'",
     "expect": "PASS", "hosts": ["127.0.0.1"]},
]

SECURITY_SCENARIOS = [
    {"name": "DVWA", "url": "http://127.0.0.1:4280/"},
    {"name": "Juice Shop", "url": "http://127.0.0.1:3000/"},
]

# Quét chủ động: có đáp án (ground truth) để đo độ chính xác phát hiện.
ACTIVE_SCENARIOS = [
    {"name": "Juice Shop search (có SQLi)",
     "url": "http://127.0.0.1:3000/rest/products/search?q=test", "expect_vuln": True},
    {"name": "Juice Shop trang chủ (sạch)",
     "url": "http://127.0.0.1:3000/?q=test", "expect_vuln": False},
]


def run_functional(model, url):
    agent = FunctionalAgent(ollama_model=model, ollama_url=url, allowed_hosts=["127.0.0.1"])
    rows = []
    for i, sc in enumerate(FUNCTIONAL_SCENARIOS, start=1):
        agent.allowed_hosts = sc["hosts"]
        run_id = f"bench-func-{i}-{int(time.time())}"
        t0 = time.perf_counter()
        try:
            outcome = agent.run(run_id, sc["url"], sc["goal"])
            status = outcome.get("status", "FAIL")
            steps = outcome.get("results", [])
            error = ""
        except Exception as exc:
            status, steps, error = "ERROR", [], str(exc)
        dur = round(time.perf_counter() - t0, 2)
        rows.append({
            "name": sc["name"], "url": sc["url"], "goal": sc["goal"],
            "expect": sc["expect"], "status": status,
            "correct": status == sc["expect"],
            "steps": len(steps), "duration_sec": dur, "error": error,
        })
        print(f"  [{'OK ' if status == sc['expect'] else 'XX '}] {sc['name']}: "
              f"{status} (kỳ vọng {sc['expect']}) · {len(steps)} bước · {dur}s"
              + (f" · lỗi: {error}" if error else ""))
    return rows


def run_security():
    engine = SecurityTestEngine()
    rows = []
    for sc in SECURITY_SCENARIOS:
        t0 = time.perf_counter()
        try:
            report = engine.run_security_scan(sc["url"])
            findings = report.get("findings", [])
            by_sev = {}
            for f in findings:
                by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
            error = ""
        except Exception as exc:
            findings, by_sev, error = [], {}, str(exc)
        dur = round(time.perf_counter() - t0, 2)
        rows.append({
            "name": sc["name"], "url": sc["url"],
            "findings": len(findings), "by_severity": by_sev,
            "duration_sec": dur, "error": error,
        })
        print(f"  [SEC] {sc['name']}: {len(findings)} phát hiện {by_sev} · {dur}s"
              + (f" · lỗi: {error}" if error else ""))
    return rows


def run_active():
    from analyzer.active_scan import ActiveScanner
    scanner = ActiveScanner()
    rows = []
    for sc in ACTIVE_SCENARIOS:
        t0 = time.perf_counter()
        try:
            report = scanner.scan(sc["url"])
            high = [f for f in report.get("findings", [])
                    if f["severity"] == "High" and f["cve"].startswith("ACTIVE-")]
            detected = len(high) > 0
            types = [f["cve"] for f in high]
            error = ""
        except Exception as exc:
            detected, types, error = False, [], str(exc)
        dur = round(time.perf_counter() - t0, 2)
        correct = detected == sc["expect_vuln"]
        rows.append({
            "name": sc["name"], "url": sc["url"], "expect_vuln": sc["expect_vuln"],
            "detected": detected, "types": types, "correct": correct,
            "duration_sec": dur, "error": error,
        })
        print(f"  [{'OK ' if correct else 'XX '}] {sc['name']}: "
              f"phát hiện={detected} (kỳ vọng={sc['expect_vuln']}) {types} · {dur}s"
              + (f" · lỗi: {error}" if error else ""))
    return rows


def summarize(func_rows, sec_rows, active_rows=None):
    summary = {}
    if func_rows:
        done = [r for r in func_rows if r["status"] != "ERROR"]
        correct = sum(1 for r in func_rows if r["correct"])
        summary["functional"] = {
            "so_kich_ban": len(func_rows),
            "do_chinh_xac": round(correct / len(func_rows), 3),
            "so_dung": correct,
            "tb_so_buoc": round(statistics.mean([r["steps"] for r in done]), 2) if done else 0,
            "tb_thoi_gian_sec": round(statistics.mean([r["duration_sec"] for r in done]), 2) if done else 0,
        }
    if sec_rows:
        summary["security"] = {
            "so_muc_tieu": len(sec_rows),
            "tong_phat_hien": sum(r["findings"] for r in sec_rows),
            "tb_thoi_gian_sec": round(statistics.mean([r["duration_sec"] for r in sec_rows]), 2),
        }
    if active_rows:
        correct = sum(1 for r in active_rows if r["correct"])
        summary["active"] = {
            "so_kich_ban": len(active_rows),
            "do_chinh_xac": round(correct / len(active_rows), 3),
            "so_dung": correct,
            "tb_thoi_gian_sec": round(statistics.mean([r["duration_sec"] for r in active_rows]), 2),
        }
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--only", choices=["functional", "security", "active"], default=None)
    ap.add_argument("--out", default=os.path.join(ROOT, "media", "benchmarks"))
    args = ap.parse_args()

    print(f"=== BENCHMARK LAB === model={args.model}")
    func_rows, sec_rows, active_rows = [], [], []
    if args.only in (None, "functional"):
        print("\n[Chức năng] Agent + browser_tools MCP:")
        func_rows = run_functional(args.model, args.url)
    if args.only in (None, "security"):
        print("\n[Bảo mật - thụ động] Trinh sát + RAG:")
        sec_rows = run_security()
    if args.only in (None, "active"):
        print("\n[Bảo mật - chủ động] Phát hiện XSS/SQLi:")
        active_rows = run_active()

    summary = summarize(func_rows, sec_rows, active_rows)
    print("\n=== TỔNG HỢP ===")
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    os.makedirs(args.out, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(args.out, f"benchmark_{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"model": args.model, "thoi_diem": stamp, "tong_hop": summary,
                   "chuc_nang": func_rows, "bao_mat": sec_rows, "chu_dong": active_rows},
                  f, ensure_ascii=False, indent=2)
    print(f"\nĐã lưu kết quả: {path}")


if __name__ == "__main__":
    main()
