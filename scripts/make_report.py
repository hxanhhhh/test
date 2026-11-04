#!/usr/bin/env python3
"""Xuất báo cáo tổng hợp (chức năng + bảo mật + benchmark) ra HTML/PDF.

Gom dữ liệu từ CSDL Django (các lần chạy chức năng, lần quét bảo mật gần nhất) và
file benchmark mới nhất ở media/benchmarks/, nhúng ảnh evidence dạng base64 để báo
cáo HTML tự chứa (gửi đi là mở được, không cần server), rồi tùy chọn in ra PDF
bằng Chromium đã cài sẵn (Playwright).

    python scripts/make_report.py                 # -> media/reports/report_*.html
    python scripts/make_report.py --pdf           # kèm PDF
    python scripts/make_report.py --runs 5
"""
import argparse
import base64
import glob
import json
import mimetypes
import os
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")

import django  # noqa: E402
django.setup()

from django.template.loader import render_to_string  # noqa: E402
from analyzer.models import FunctionalTestRun, SecurityScan  # noqa: E402


def data_uri(rel_path):
    """Đọc ảnh evidence (đường dẫn tương đối gốc repo) -> data URI base64."""
    if not rel_path:
        return ""
    path = rel_path if os.path.isabs(rel_path) else os.path.join(ROOT, rel_path)
    if not os.path.isfile(path):
        return ""
    mime = mimetypes.guess_type(path)[0] or "image/png"
    try:
        with open(path, "rb") as f:
            return f"data:{mime};base64," + base64.b64encode(f.read()).decode("ascii")
    except OSError:
        return ""


def latest_benchmark():
    files = sorted(glob.glob(os.path.join(ROOT, "media", "benchmarks", "*.json")))
    if not files:
        return None
    try:
        with open(files[-1], encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def gather_context(runs_n=3, model="-"):
    functional_runs = []
    runs = (FunctionalTestRun.objects
            .select_related("test_case", "test_case__project")
            .prefetch_related("steps").order_by("-created_at")[:runs_n])
    for run in runs:
        steps = [{
            "step_no": s.step_no, "action": s.action, "status": s.status,
            "duration_ms": s.duration_ms,
            "detail": (s.result or {}).get("detail", "") if isinstance(s.result, dict) else "",
            "image": data_uri(s.screenshot),
        } for s in run.steps.all()]
        functional_runs.append({
            "name": run.test_case.name, "status": run.status,
            "project": run.test_case.project.name,
            "model_name": run.model_name or model,
            "started": run.started_at, "steps": steps,
        })

    scan = (SecurityScan.objects.prefetch_related("findings").order_by("-created_at").first())
    security = None
    if scan:
        findings = [{
            "title": f.title, "severity": f.severity,
            "confidence": f.get_confidence_display(),
            "related_cve": f.related_cve or [],
            "description": f.description, "recommendation": f.recommendation,
        } for f in scan.findings.all()]
        security = {"target": scan.target, "created": scan.created_at, "findings": findings}

    benchmark = latest_benchmark()
    summary = {
        "func_total": len(functional_runs),
        "func_pass": sum(1 for r in functional_runs if r["status"] == "PASS"),
        "sec_findings": len(security["findings"]) if security else 0,
    }
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "model": model,
        "functional_runs": functional_runs,
        "security": security,
        "benchmark": benchmark,
        "summary": summary,
    }


def build_report_html(context):
    return render_to_string("report.html", context)


def to_pdf(html_path, pdf_path):
    """In HTML -> PDF bằng Chromium (Playwright sync)."""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto("file://" + os.path.abspath(html_path), wait_until="networkidle")
        page.pdf(path=pdf_path, format="A4", print_background=True,
                 margin={"top": "14mm", "bottom": "14mm", "left": "12mm", "right": "12mm"})
        browser.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3, help="số lần chạy chức năng gần nhất")
    ap.add_argument("--model", default=os.environ.get("OLLAMA_MODEL", "-"))
    ap.add_argument("--out", default=os.path.join(ROOT, "media", "reports"))
    ap.add_argument("--pdf", action="store_true", help="kèm xuất PDF bằng Chromium")
    args = ap.parse_args()

    context = gather_context(args.runs, args.model)
    html = build_report_html(context)

    os.makedirs(args.out, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = os.path.join(args.out, f"report_{stamp}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"✅ Đã tạo báo cáo HTML: {html_path}")
    print(f"   (chức năng: {context['summary']['func_total']} lần, "
          f"bảo mật: {context['summary']['sec_findings']} phát hiện, "
          f"benchmark: {'có' if context['benchmark'] else 'chưa có'})")

    if args.pdf:
        pdf_path = os.path.join(args.out, f"report_{stamp}.pdf")
        try:
            to_pdf(html_path, pdf_path)
            print(f"✅ Đã tạo báo cáo PDF: {pdf_path}")
        except Exception as exc:
            print(f"⚠️  Không xuất được PDF ({exc}). Mở file HTML rồi In -> Lưu PDF từ trình duyệt.")


if __name__ == "__main__":
    main()
