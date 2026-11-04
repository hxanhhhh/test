import json

from django.shortcuts import render
from django.utils import timezone

from core_agent.functional_engine import FunctionalTestEngine
from core_agent.security_engine import SecurityTestEngine


def _save_functional_run(target_url, user_requirement, test_cases, func_results, model_name):
    """Nối pipeline demo vào DB Django: lưu kịch bản + lần chạy + từng bước.

    Dùng đúng các model có sẵn trong app ``analyzer`` (TestProject,
    FunctionalTestCase, FunctionalTestRun, TestStepResult). Trả về đối tượng
    FunctionalTestRun đã lưu.
    """
    # Import tại đây để tránh phụ thuộc vòng lúc Django nạp app.
    from analyzer.models import (TestProject, FunctionalTestCase,
                                 FunctionalTestRun, TestStepResult)

    project, _ = TestProject.objects.get_or_create(
        target_url=target_url or "",
        defaults={"name": f"Demo: {target_url or 'không rõ URL'}"},
    )
    case = FunctionalTestCase.objects.create(
        project=project,
        name=(user_requirement or "Kịch bản AI")[:255],
        steps=test_cases or [],
        expected_result="",
        source=FunctionalTestCase.Source.AI,
        approved=True,
    )
    overall = (
        FunctionalTestRun.Status.PASS
        if func_results and all(r.get("status") == "PASS" for r in func_results)
        else FunctionalTestRun.Status.FAIL
    )
    run = FunctionalTestRun.objects.create(
        test_case=case,
        status=overall,
        model_name=model_name or "",
        started_at=timezone.now(),
        finished_at=timezone.now(),
    )
    for index, res in enumerate(func_results or [], start=1):
        step_status = (
            TestStepResult.Status.PASS
            if res.get("status") == "PASS"
            else TestStepResult.Status.FAIL
        )
        TestStepResult.objects.create(
            run=run,
            step_no=index,
            action=str(res.get("action", "")),
            tool="browser_mcp",
            input={"value": res.get("value", ""), "expected": res.get("expected", "")},
            result={"detail": res.get("detail", ""), "status": res.get("status", "")},
            screenshot=str(res.get("evidence", "")),
            status=step_status,
        )
    return run


def dashboard_view(request):
    context = {
        "active_tab": "functional",
        "target_url": "https://online.iigvietnam.com/lich-thi-tieng-anh",
        "user_requirement": "Kiểm tra truy cập trang chủ và xác thực tiêu đề trang web",
        "test_cases": None,
        "func_results": None,
        "sec_report": None,
        "saved_run_id": None,
        "save_error": None,
    }

    if request.method == "POST":
        action_type = request.POST.get("action_type")
        target_url = request.POST.get("target_url", "https://online.iigvietnam.com/lich-thi-tieng-anh")
        context["target_url"] = target_url

        if action_type == "generate_functional":
            context["active_tab"] = "functional"
            user_req = request.POST.get("user_requirement", "Kiểm tra truy cập trang web")
            context["user_requirement"] = user_req

            engine = FunctionalTestEngine()
            test_cases = engine.generate_test_cases(user_req, target_url=target_url)
            context["test_cases"] = test_cases

        elif action_type == "run_functional":
            context["active_tab"] = "functional"
            user_req = request.POST.get("user_requirement", "")
            if user_req:
                context["user_requirement"] = user_req
            selected_cases_raw = request.POST.get("selected_cases", "[]")
            try:
                test_cases = json.loads(selected_cases_raw.replace("'", '"'))
            except Exception:
                test_cases = []

            engine = FunctionalTestEngine()
            func_results = engine.execute_functional_test(test_cases, target_url=target_url)
            context["test_cases"] = test_cases
            context["func_results"] = func_results

            # --- Nối pipeline demo vào DB Django ---
            try:
                run = _save_functional_run(
                    target_url, context["user_requirement"], test_cases,
                    func_results, getattr(engine, "ollama_model", ""),
                )
                context["saved_run_id"] = run.pk
            except Exception as exc:
                context["save_error"] = str(exc)

        elif action_type == "run_security":
            context["active_tab"] = "security"
            engine = SecurityTestEngine()
            sec_report = engine.run_security_scan(target_url=target_url)
            context["sec_report"] = sec_report

    return render(request, "dashboard/index.html", context)
