import json
from django.shortcuts import render
from core_agent.functional_engine import FunctionalTestEngine
from core_agent.security_engine import SecurityTestEngine

def dashboard_view(request):
    context = {
        "active_tab": "functional",
        "target_url": "https://online.iigvietnam.com/lich-thi-tieng-anh",
        "user_requirement": "Kiểm tra truy cập trang chủ và xác thực tiêu đề trang web",
        "test_cases": None,
        "func_results": None,
        "sec_report": None
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
            selected_cases_raw = request.POST.get("selected_cases", "[]")
            try:
                test_cases = json.loads(selected_cases_raw.replace("'", '"'))
            except:
                test_cases = []
            
            engine = FunctionalTestEngine()
            func_results = engine.execute_functional_test(test_cases, target_url=target_url)
            context["test_cases"] = test_cases
            context["func_results"] = func_results

        elif action_type == "run_security":
            context["active_tab"] = "security"
            engine = SecurityTestEngine()
            sec_report = engine.run_security_scan(target_url=target_url)
            context["sec_report"] = sec_report

    return render(request, "dashboard/index.html", context)

