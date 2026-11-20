import json
import re
import time

import requests
from django.conf import settings
from django.db import transaction
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib import messages
from django.utils import timezone
from django.shortcuts import get_object_or_404, render
from analyzer.models import TargetAsset, Service, SecurityFinding
from django.views.decorators.http import require_POST
from analyzer.cve_matcher import run_nmap_cve_pipeline
from .models import (TestProject, FunctionalTestCase, FunctionalTestRun, TestStepResult,
                     SecurityScan, TargetAsset, Service, SecurityFinding)
from .forms import NmapImportForm, ProjectForm
from .parse_nmap import parse_nmap_xml
from .analysis import DEFENSIVE_RULES, analyze_scan, plain_text


# ---------------------------------------------------------------------------
# Trang chủ hợp nhất: Dự án + Kiểm thử chức năng + Trinh sát bảo mật
# ---------------------------------------------------------------------------

DEMO_ACTIONS = {'generate_functional', 'run_functional', 'run_agent',
                'run_security', 'run_active_scan', 'run_auth_scan'}


def _demo_defaults():
    return {
        'target_url': 'http://127.0.0.1:4280/login.php',
        'user_requirement': ('Điền admin vào ô Username, password vào ô Password, bấm Login; '
                             'xác nhận đăng nhập thành công khi trang có chữ Logout'),
        'test_cases': None,
        'func_results': None,
        'sec_report': None,
        'saved_run_id': None,
        'save_error': None,
        'scan_url': 'http://127.0.0.1:3000/rest/products/search?q=test',
        'active_scan_mode': False,
        'login_url': 'http://127.0.0.1:4280/login.php',
        'login_goal': ('Điền admin vào ô Username, password vào ô Password, bấm Login; '
                       'xác nhận đăng nhập thành công khi trang có chữ Logout'),
        'sec_prompt': 'Vào mục SQL Injection và kiểm tra lỗ hổng SQLi',
    }


def _save_functional_run(target_url, user_requirement, test_cases, func_results, model_name):
    """Nối pipeline demo vào DB Django: lưu kịch bản + lần chạy + từng bước."""
    project, _ = TestProject.objects.get_or_create(
        target_url=target_url or '',
        defaults={'name': f"Demo: {target_url or 'không rõ URL'}"},
    )
    case = FunctionalTestCase.objects.create(
        project=project,
        name=(user_requirement or 'Kịch bản AI')[:255],
        steps=test_cases or [],
        expected_result='',
        source=FunctionalTestCase.Source.AI,
        approved=True,
    )
    overall = (
        FunctionalTestRun.Status.PASS
        if func_results and all(r.get('status') == 'PASS' for r in func_results)
        else FunctionalTestRun.Status.FAIL
    )
    run = FunctionalTestRun.objects.create(
        test_case=case,
        status=overall,
        model_name=model_name or '',
        started_at=timezone.now(),
        finished_at=timezone.now(),
    )
    for index, res in enumerate(func_results or [], start=1):
        step_status = (
            TestStepResult.Status.PASS
            if res.get('status') == 'PASS'
            else TestStepResult.Status.FAIL
        )
        TestStepResult.objects.create(
            run=run,
            step_no=index,
            action=str(res.get('action', '')),
            tool='browser_mcp',
            input={'value': res.get('value', ''), 'expected': res.get('expected', '')},
            result={'detail': res.get('detail', ''), 'status': res.get('status', '')},
            screenshot=str(res.get('evidence', '')),
            status=step_status,
            duration_ms=res.get('duration_ms'),
        )
    return run


def _demo_dashboard(request, action_type):
    """Xử lý các tab demo (chức năng / bảo mật) trên trang chủ hợp nhất."""
    # Import muộn để Django khởi động không cần playwright.
    from core_agent.functional_engine import FunctionalTestEngine
    from core_agent.security_engine import SecurityTestEngine

    context = {
        'form': ProjectForm(),
        'projects': TestProject.objects.order_by('-created_at'),
    }
    context.update(_demo_defaults())
    target_url = request.POST.get('target_url', context['target_url'])
    context['target_url'] = target_url

    if action_type == 'generate_functional':
        context['active_tab'] = 'functional'
        user_req = request.POST.get('user_requirement', 'Kiểm tra truy cập trang web')
        context['user_requirement'] = user_req
        engine = FunctionalTestEngine()
        context['test_cases'] = engine.generate_test_cases(user_req, target_url=target_url)

    elif action_type == 'run_functional':
        context['active_tab'] = 'functional'
        user_req = request.POST.get('user_requirement', '')
        if user_req:
            context['user_requirement'] = user_req
        raw = request.POST.get('selected_cases', '[]')
        try:
            test_cases = json.loads(raw.replace("'", '"'))
        except Exception:
            test_cases = []
        engine = FunctionalTestEngine()
        func_results = engine.execute_functional_test(test_cases, target_url=target_url)
        context['test_cases'] = test_cases
        context['func_results'] = func_results
        try:
            run = _save_functional_run(
                target_url, context['user_requirement'], test_cases,
                func_results, getattr(engine, 'ollama_model', ''),
            )
            context['saved_run_id'] = run.pk
        except Exception as exc:
            context['save_error'] = str(exc)

    elif action_type == 'run_agent':
        context['active_tab'] = 'functional'
        goal = request.POST.get('user_requirement', '')
        if goal:
            context['user_requirement'] = goal
        func_results, run_status = _run_agent(target_url, goal or 'Kiểm thử truy cập trang')
        context['test_cases'] = None
        context['func_results'] = func_results
        context['agent_mode'] = True
        context['agent_status'] = run_status
        try:
            run = _save_functional_run(target_url, goal, [], func_results, settings.OLLAMA_MODEL)
            context['saved_run_id'] = run.pk
        except Exception as exc:
            context['save_error'] = str(exc)

    elif action_type == 'run_security':
        context['active_tab'] = 'security'
        engine = SecurityTestEngine()
        context['sec_report'] = engine.run_security_scan(target_url=target_url)

    elif action_type == 'run_active_scan':
        context['active_tab'] = 'security'
        scan_url = request.POST.get('scan_url', target_url)
        context['scan_url'] = scan_url
        if request.POST.get('confirm_authorized') != 'on':
            context['sec_report'] = {
                'ai_summary': 'Bạn phải tích xác nhận được phép kiểm thử mục tiêu lab trước khi quét chủ động.',
                'findings': [],
            }
        else:
            from analyzer.active_scan import ActiveScanner
            context['sec_report'] = ActiveScanner().scan(scan_url)
        context['active_scan_mode'] = True

    elif action_type == 'run_auth_scan':
        context['active_tab'] = 'security'
        login_url = request.POST.get('login_url', context['login_url'])
        login_goal = request.POST.get('login_goal', context['login_goal'])
        sec_prompt = request.POST.get('sec_prompt', context['sec_prompt'])
        context['login_url'] = login_url
        context['login_goal'] = login_goal
        context['sec_prompt'] = sec_prompt
        context['active_scan_mode'] = True
        if request.POST.get('confirm_authorized') != 'on':
            context['sec_report'] = {
                'ai_summary': 'Bạn phải tích xác nhận được phép kiểm thử mục tiêu lab trước khi quét.',
                'findings': [],
            }
        else:
            context['sec_report'] = _auth_agent_scan(login_url, login_goal, sec_prompt)

    return render(request, 'dashboard.html', context)

def generate_security_report(request, target_id=None):
    if target_id:
        asset = get_object_or_404(TargetAsset, id=target_id)
        services = Service.objects.filter(asset=asset)
        findings = SecurityFinding.objects.filter(asset=asset)
    else:
        asset = TargetAsset.objects.last()
        services = Service.objects.all()
        findings = SecurityFinding.objects.all()

    context = {
        'asset': asset,
        'services': services,
        'findings': findings,
        'total_findings': findings.count(),
        'high_severity_count': findings.filter(severity__iexact='High').count(),
        'medium_severity_count': findings.filter(severity__iexact='Medium').count(),
        'low_severity_count': findings.filter(severity__iexact='Low').count(),
    }
    return render(request, 'analyzer/report_template.html', context)

def _auth_agent_scan(login_url, login_goal, sec_prompt):
    """Agent đăng nhập -> tự điều hướng theo prompt -> dò & quét trang hiện tại bằng phiên."""
    import json
    from urllib.parse import urlsplit
    from analyzer.agent_runner import FunctionalAgent
    from analyzer.active_scan import ActiveScanner, is_lab_host
    from scripts.auth_scan_dvwa import send_kali_command

    host = urlsplit(login_url).hostname or '127.0.0.1'
    run_id = 'authagent-' + re.sub(r'[^0-9]', '', '%.3f' % time.time())[-14:]
    agent = FunctionalAgent(ollama_model=settings.OLLAMA_MODEL,
                            ollama_url=settings.OLLAMA_URL, allowed_hosts=[host])
    try:
        login_outcome, nav_outcome, url, cookies = agent.run_auth_security(
            run_id, login_url, login_goal, sec_prompt)
    except Exception as exc:
        return {'ai_summary': f'Lỗi khi đăng nhập/điều hướng bằng Agent: {exc}', 'findings': []}
    if not url:
        return {'ai_summary': f"Đăng nhập: {login_outcome.get('status')}; không lấy được URL sau điều hướng.",
                'findings': []}

    normalized_cookies = [dict(c) for c in (cookies or []) if isinstance(c, dict) and c.get("name")]
    if is_lab_host(host):
        has_sec = False
        for c in normalized_cookies:
            if str(c.get("name")).lower() == "security":
                c["value"] = "low"
                has_sec = True
        if not has_sec:
            normalized_cookies.append({
                "name": "security",
                "value": "low",
                "domain": host,
                "path": "/",
            })

    cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in normalized_cookies)
    report = ActiveScanner(cookies=normalized_cookies, use_headless=True, run_id=run_id).scan_page(url)
    findings = list(report.get("findings") or [])

    tool_notes = []
    if is_lab_host(host) and cookie_header:
        parsed_u = urlsplit(url)
        base_origin = f"{parsed_u.scheme}://{parsed_u.netloc}" if parsed_u.scheme and parsed_u.netloc else ""
        scan_targets = []
        if "/vulnerabilities/" in (parsed_u.path or "") and base_origin:
            scan_targets = [
                ("SQLMAP-SQLI", "High", f"{base_origin}/vulnerabilities/sqli/?id=1&Submit=Submit",
                 f'sqlmap -u "{base_origin}/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="{cookie_header}" --batch --level=1 --risk=1'),
                ("DALFOX-XSS", "High", f"{base_origin}/vulnerabilities/xss_r/?name=test",
                 f'dalfox url "{base_origin}/vulnerabilities/xss_r/?name=test" --cookies "{cookie_header}"'),
            ]
        elif parsed_u.query:
            scan_targets = [
                ("SQLMAP-SQLI", "High", url,
                 f'sqlmap -u "{url}" --cookie="{cookie_header}" --batch --level=1 --risk=1'),
                ("DALFOX-XSS", "High", url,
                 f'dalfox url "{url}" --cookies "{cookie_header}"'),
            ]

        for code, sev, t_url, cmd in scan_targets:
            try:
                status_code, body = send_kali_command(cmd)
                parsed_resp = json.loads(body) if isinstance(body, str) else (body or {})
                data_obj = parsed_resp.get("data") if isinstance(parsed_resp, dict) and isinstance(parsed_resp.get("data"), dict) else parsed_resp
                stdout = (data_obj.get("stdout") or "") if isinstance(data_obj, dict) else ""
                detected = (("Parameter:" in stdout or "Type:" in stdout)
                            if code.startswith("SQLMAP")
                            else ("[POC" in stdout or "XSS found" in stdout))
                if detected:
                    findings = [f for f in findings if f.get("cve") != "INFO-ACTIVE-CLEAN"]
                    findings.append({
                        "cve": code,
                        "severity": sev,
                        "description": f"Phát hiện lỗ hổng qua {code.split('-')[0].lower()} với phiên đã xác thực [endpoint: {t_url}]",
                        "recommendation": "Sử dụng prepared statement / parameterized query và escape/sanitize output theo ngữ cảnh.",
                    })
                    tool_notes.append(f"{code}: DETECTED ({t_url})")
                else:
                    tool_notes.append(f"{code}: HTTP {status_code}, no clear finding ({t_url})")
            except Exception as exc:
                tool_notes.append(f"{code}: error ({exc})")

    report["findings"] = findings
    nav_status = nav_outcome.get("status")
    if nav_status != "PASS" and url != login_url:
        nav_label = f"{nav_status} (đã tới trang đích)"
    else:
        nav_label = str(nav_status)

    extra_line = ("Công cụ sau đăng nhập: " + " | ".join(tool_notes) + "\n") if tool_notes else ""
    head = (f"Đăng nhập: {login_outcome.get('status')} | "
            f"Điều hướng theo prompt: {nav_label} | {len(normalized_cookies)} cookie phiên.\n"
            f"{extra_line}")
    report['ai_summary'] = head + report.get('ai_summary', '')
    return report


def _run_agent(target_url, goal):
    """Chạy tác tử LLM + browser_tools MCP, trả (results, status)."""
    from urllib.parse import urlsplit
    from analyzer.agent_runner import FunctionalAgent

    host = urlsplit(target_url).hostname or '127.0.0.1'
    run_id = 'agent-' + re.sub(r'[^0-9]', '', '%.3f' % time.time())[-14:]
    agent = FunctionalAgent(ollama_model=settings.OLLAMA_MODEL,
                            ollama_url=settings.OLLAMA_URL, allowed_hosts=[host])
    try:
        outcome = agent.run(run_id, target_url, goal)
        return outcome.get('results', []), outcome.get('status', 'FAIL')
    except Exception as exc:
        return ([{'step_id': 1, 'action': 'agent', 'value': target_url,
                  'expected': goal, 'status': 'FAIL',
                  'detail': f'Lỗi chạy agent: {exc}', 'evidence': ''}], 'FAIL')


def dashboard_view(request):
    action_type = request.POST.get('action_type') if request.method == 'POST' else None

    # Nhánh demo (kiểm thử chức năng / bảo mật)
    if action_type in DEMO_ACTIONS:
        return _demo_dashboard(request, action_type)

    # Nhánh quản lý dự án (hành vi gốc, giữ nguyên để test pass)
    form = ProjectForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        project = form.save(commit=False)
        if request.user.is_authenticated:
            project.owner = request.user
        project.save()
        messages.success(request, 'Đã tạo dự án.')
        return redirect('project_detail', project_id=project.pk)
    projects = TestProject.objects.order_by('-created_at')
    context = {'projects': projects, 'form': form, 'active_tab': 'project'}
    context.update(_demo_defaults())
    return render(request, 'dashboard.html', context,
                  status=400 if request.method == 'POST' else 200)


def project_context(project, import_form=None, tab='functional'):
    return {'project': project, 'import_form': import_form or NmapImportForm(),
            'tab': tab, 'test_cases': project.test_cases.all(), 'scans': project.scans.all()}


def project_detail(request, project_id):
    project = get_object_or_404(TestProject, pk=project_id)
    tab = 'security' if request.GET.get('tab') == 'security' else 'functional'
    return render(request, 'project_detail.html', project_context(project, tab=tab))


@require_POST
def project_import_nmap(request, project_id):
    project = get_object_or_404(TestProject, pk=project_id)
    form = NmapImportForm(request.POST, request.FILES)
    if form.is_valid():
        try:
            scan = import_nmap_file(form.cleaned_data['nmap_file'], project=project)
        except (ValueError, ValidationError) as exc:
            form.add_error('nmap_file', str(exc))
        else:
            messages.success(request, 'Đã nhập kết quả Nmap.')
            return redirect('scan_detail', scan_id=scan.pk)
    messages.error(request, 'Không thể nhập file Nmap. Vui lòng kiểm tra lỗi bên dưới.')
    return render(request, 'project_detail.html',
                  project_context(project, form, 'security'), status=400)


def scan_detail(request, scan_id):
    scan = get_object_or_404(SecurityScan.objects.select_related('project'), pk=scan_id)
    assets = scan.assets.prefetch_related('services__findings')
    findings_without_service = scan.findings.filter(service__isnull=True).select_related('asset')
    return render(request, 'scan_detail.html', {
        'scan': scan, 'assets': assets, 'findings_without_service': findings_without_service,
    })


@require_POST
def scan_analyze(request, scan_id):
    scan = get_object_or_404(SecurityScan, pk=scan_id)
    result = analyze_scan(scan)
    if result['status'] == SecurityScan.Status.COMPLETED:
        messages.success(request, 'Đánh giá rủi ro hoàn tất.')
    else:
        messages.error(request, f"Trạng thái {result['status']}: {len(result['errors'])} dịch vụ đánh giá lỗi.")
    return redirect('scan_detail', scan_id=scan.pk)


@require_POST
def project_recon(request, project_id):
    """Recon TỰ ĐỘNG: chạy nmap thật trên Kali rồi nạp dịch vụ vào DB (thay upload XML)."""
    project = get_object_or_404(TestProject, pk=project_id)
    target = (request.POST.get('target') or project.target_url or '').strip()
    back = f'/projects/{project_id}/?tab=security'
    if not target:
        messages.error(request, 'Hãy nhập mục tiêu recon (IP/host/URL lab nội bộ).')
        return redirect(back)
    from io import BytesIO
    from analyzer.kali import build_registry
    try:
        res = build_registry().call('nmap', target=target)
    except Exception as exc:
        messages.error(request, f'Không gọi được Kali: {exc}. Kiểm tra kali_server + KALI_URL.')
        return redirect(back)
    if res.get('findings') and res['findings'][0].get('title') == 'Ngoài phạm vi lab':
        messages.error(request, 'Mục tiêu không phải host nội bộ (chỉ recon lab được phép).')
        return redirect(back)
    xml = res.get('xml') or ''
    if '<nmaprun' not in xml:
        messages.error(request, 'nmap qua Kali không trả kết quả. Kiểm tra kali_server đang chạy và mục tiêu đúng.')
        return redirect(back)
    try:
        scan = import_nmap_file(BytesIO(xml.encode('utf-8', 'ignore')),
                                project=project, scan_method='nmap-kali')
    except (ValueError, ValidationError) as exc:
        messages.error(request, f'Không phân tích được kết quả nmap: {exc}')
        return redirect(back)
    
    try:
        from analyzer.cve_matcher import run_nmap_cve_pipeline
        run_nmap_cve_pipeline()
    except Exception as e:
        print(f"Lỗi chạy RAG: {e}")

    messages.success(request, 'Recon tự động (nmap qua Kali) hoàn tất. Bấm "Đánh giá rủi ro bằng AI".')
    return redirect('scan_detail', scan_id=scan.pk)


def kali_status(request):
    """Kiểm tra kết nối tới máy Kali (gọi /health của kali_server). Trả JSON để
    dashboard hiển thị badge 'Kali: online/offline'."""
    from analyzer.kali.client import KaliClient
    client = KaliClient()
    health = client.health()
    ok = isinstance(health, dict) and 'error' not in health
    return JsonResponse({'ok': ok, 'url': client.base_url, 'health': health})


def _shape_result(result):
    """Rút gọn dict kết quả orchestrator thành payload JSON cho UI."""
    steps = [{
        'tool': s['tool'], 'title': s['title'], 'ok': s['ok'],
        'n_findings': s['n_findings'],
        'findings': [{
            'severity': f.get('severity', 'Info'),
            'title': f.get('title', ''),
            'description': (f.get('description') or '')[:400],
        } for f in s['findings']],
    } for s in result['steps']]
    return {
        'ok': result.get('ok', False), 'lab': result.get('lab', True),
        'mode': result.get('mode'), 'target': result.get('target'),
        'url': result.get('url'), 'summary': result['summary'],
        'steps': steps, 'error': result.get('error'),
    }


def _run_and_save(project, target, url, cookie, mode):
    """Chạy orchestrator, LƯU vào DB (SecurityScan) rồi trả payload kèm link scan."""
    from django.urls import reverse
    from analyzer.kali.orchestrator import run_pipeline, run_agent
    from analyzer.kali.persist import save_orchestrator_result
    runner = run_agent if mode == 'agent' else run_pipeline
    result = runner(target, url=url, cookie=cookie)
    payload = _shape_result(result)
    if result.get('lab', True):
        try:
            scan = save_orchestrator_result(project, result)
            payload['scan_id'] = scan.pk
            payload['scan_url'] = reverse('scan_detail', args=[scan.pk])
        except Exception as exc:  # noqa: BLE001
            payload['save_error'] = str(exc)
    return payload


@require_POST
def project_pentest(request, project_id):
    """Chạy orchestrator qua Kali cho một project, lưu DB rồi trả JSON cho UI."""
    project = get_object_or_404(TestProject, pk=project_id)
    target = (request.POST.get('target') or project.target_url or '').strip()
    url = (request.POST.get('url') or '').strip() or None
    cookie = (request.POST.get('cookie') or '').strip()
    if not target:
        return JsonResponse({'ok': False, 'error': 'Thiếu mục tiêu kiểm thử.'}, status=400)
    try:
        return JsonResponse(_run_and_save(project, target, url, cookie, request.POST.get('mode')))
    except Exception as exc:  # noqa: BLE001
        return JsonResponse({'ok': False, 'error': f'Lỗi khi chạy: {exc}'}, status=500)


@require_POST
def kali_pentest_api(request):
    """Chạy orchestrator qua Kali từ Dashboard; lưu vào một project mặc định."""
    target = (request.POST.get('target') or '').strip()
    url = (request.POST.get('url') or '').strip() or None
    cookie = (request.POST.get('cookie') or '').strip()
    if not target and url:
        from urllib.parse import urlparse
        target = urlparse(url).hostname or ''
    if not target:
        return JsonResponse({'ok': False, 'error': 'Thiếu mục tiêu (host hoặc URL lab).'}, status=400)
    project, _ = TestProject.objects.get_or_create(
        name='Kali Orchestrator (Dashboard)',
        defaults={'description': 'Tự tạo để lưu kết quả chạy orchestrator từ Dashboard.'})
    try:
        return JsonResponse(_run_and_save(project, target, url, cookie, request.POST.get('mode')))
    except Exception as exc:  # noqa: BLE001
        return JsonResponse({'ok': False, 'error': f'Lỗi khi chạy: {exc}'}, status=500)


def import_nmap_file(nmap_file, project=None, project_name='Dự án mới', scan_method='nmap-import'):
    hosts = parse_nmap_xml(nmap_file)
    target = ', '.join(host['ip'] for host in hosts)
    if len(target) > 255:
        raise ValueError('Danh sách IP vượt giới hạn 255 ký tự của mục tiêu scan.')
    with transaction.atomic():
        if project is None:
            project = TestProject(name=project_name)
            project.full_clean()
            project.save()
        scan = SecurityScan.objects.create(
            project=project, target=target, scan_method=scan_method,
            status=SecurityScan.Status.COMPLETED,
            started_at=timezone.now(), finished_at=timezone.now(),
        )
        for host in hosts:
            asset = TargetAsset(
                project=project, scan=scan, ip_address=host['ip'],
                hostname=host['hostname'], os_info=host['os'],
            )
            asset.full_clean()
            asset.save()
            for data in host['services']:
                service = Service(
                    asset=asset, port=data['port'], protocol=data['protocol'],
                    service_name=data['name'], product=data['product'],
                    service_version=data['version'], cpe=data['cpe'],
                )
                service.full_clean()
                service.save()
    return scan


@require_POST
def upload_nmap_log(request):
    nmap_file = request.FILES.get('nmap_file')
    if not nmap_file:
        return JsonResponse({'status': 'error', 'message': 'Vui lòng chọn file XML Nmap.'}, status=400)
    project_id = request.POST.get('project_id')
    project = get_object_or_404(TestProject, pk=project_id) if project_id else None
    try:
        scan = import_nmap_file(nmap_file, project, request.POST.get('project_name', 'Dự án mới'))
    except (ValueError, ValidationError) as exc:
        return JsonResponse({'status': 'error', 'message': str(exc)}, status=400)
    return JsonResponse({'status': 'success', 'project_id': scan.project_id, 'scan_id': scan.pk})


@require_POST
def analyze_target_asset(request, asset_id):
    asset = get_object_or_404(TargetAsset, pk=asset_id)
    if asset.scan_id is None:
        return JsonResponse({'status': 'error', 'message': 'Máy chưa gắn với lần quét.'}, status=400)
    result = analyze_scan(asset.scan)
    return JsonResponse(result, status=200 if not result['errors'] else 502)


@require_POST
def chat_with_asset_ai(request, asset_id):
    asset = get_object_or_404(TargetAsset.objects.prefetch_related('services', 'findings'), pk=asset_id)
    try:
        data = json.loads(request.body)
        if not isinstance(data, dict):
            raise ValueError
        text = data.get('message')
        if not isinstance(text, str) or not text.strip() or len(text) > 4000:
            raise ValueError
    except (ValueError, TypeError):
        return JsonResponse({'status': 'error', 'message': 'Câu hỏi không hợp lệ.'}, status=400)
    context = {
        'ip': asset.ip_address,
        'services': list(asset.services.values('port', 'protocol', 'service_name',
                                               'product', 'service_version', 'cpe')),
        'findings': list(asset.findings.values('title', 'severity', 'confidence',
                                               'evidence', 'related_cve',
                                               'description', 'recommendation')),
        'question': text.strip(),
    }
    prompt = (DEFENSIVE_RULES + '\nHỏi đáp chỉ dựa trên máy được chọn. '
              'Trả JSON duy nhất có trường reply là văn bản giải thích rủi ro hoặc khắc phục.\n'
              + json.dumps(context, ensure_ascii=False))
    try:
        response = requests.post(settings.OLLAMA_URL, json={
            'model': settings.OLLAMA_MODEL, 'stream': False, 'format': 'json', 'prompt': prompt,
        }, timeout=60)
        response.raise_for_status()
        result = json.loads(response.json()['response'])
        if not isinstance(result, dict) or set(result) != {'reply'}:
            raise ValueError
        reply = plain_text(result['reply'])
        if not reply:
            raise ValueError
        return JsonResponse({'status': 'success', 'reply': reply})
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return JsonResponse({'status': 'error', 'message': 'Không thể trả lời câu hỏi lúc này.'}, status=502)


def get_asset_detail(request, asset_id):
    asset = get_object_or_404(TargetAsset.objects.prefetch_related('services__findings'), pk=asset_id)
    services = [{
        'port': service.port, 'protocol': service.protocol,
        'service_name': service.service_name, 'product': service.product,
        'service_version': service.service_version, 'cpe': service.cpe,
        'findings': list(service.findings.values(
            'title', 'category', 'severity', 'confidence', 'evidence',
            'related_cve', 'description', 'recommendation')),
    } for service in asset.services.all()]
    return JsonResponse({'ip': asset.ip_address, 'services': services})
