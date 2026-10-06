import json

import requests
from django.conf import settings
from django.db import transaction
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from .models import TestProject, SecurityScan, TargetAsset, Service, SecurityFinding
from .parse_nmap import parse_nmap_xml
from .analysis import DEFENSIVE_RULES, analyze_scan, plain_text

def dashboard_view(request):
    projects = TestProject.objects.prefetch_related('assets__services').order_by('-created_at')
    return render(request, 'dashboard.html', {'projects': projects})


def import_nmap_file(nmap_file, project=None, project_name='Dự án mới'):
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
            project=project, target=target, scan_method='nmap-import',
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
