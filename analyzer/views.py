import json

import chromadb
import requests
from django.db import transaction
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from .models import TestProject, SecurityScan, TargetAsset, Service, SecurityFinding
from .parse_nmap import parse_nmap_xml

CHROMA_PATH = './chroma_data'
OLLAMA_URL = 'http://localhost:11434/api/generate'
MODEL_NAME = 'qwen2.5-coder:3b'


def get_chroma_client():
    return chromadb.PersistentClient(path=CHROMA_PATH)


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
    successes = 0
    errors = []
    services = list(asset.services.all())
    for service in services:
        try:
            response = requests.post(OLLAMA_URL, json={
                'model': MODEL_NAME, 'stream': False, 'format': 'json',
                'prompt': f'Chỉ đánh giá rủi ro và khuyến nghị phòng thủ cho {service}. '
                          'Không hướng dẫn khai thác, không trả mã thực thi. '
                          'Trả JSON gồm title, description, recommendation.',
            }, timeout=60)
            response.raise_for_status()
            result = json.loads(response.json()['response'])
            SecurityFinding.objects.update_or_create(
                scan=asset.scan, asset=asset, service=service, category='service_review',
                defaults={'title': result['title'], 'description': result['description'],
                          'recommendation': result['recommendation']},
            )
            successes += 1
        except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
            errors.append({'service_id': service.pk, 'message': str(exc)})
    scan = asset.scan
    scan.status = (SecurityScan.Status.COMPLETED if not errors else
                   SecurityScan.Status.PARTIAL if successes else SecurityScan.Status.FAILED)
    scan.finished_at = timezone.now()
    scan.save(update_fields=['status', 'finished_at'])
    return JsonResponse({'status': scan.status, 'errors': errors}, status=200 if not errors else 502)


@require_POST
def chat_with_asset_ai(request, asset_id):
    asset = get_object_or_404(TargetAsset, pk=asset_id)
    try:
        data = json.loads(request.body)
        text = data.get('message', '').strip()
        if not text:
            raise ValueError('Vui lòng nhập câu hỏi.')
    except (ValueError, AttributeError):
        return JsonResponse({'status': 'error', 'message': 'Câu hỏi không hợp lệ.'}, status=400)
    try:
        response = requests.post(OLLAMA_URL, json={
            'model': MODEL_NAME, 'stream': False,
            'prompt': f'Chỉ trả lời về rủi ro và khắc phục cho {asset.ip_address}. '
                      f'Không hướng dẫn khai thác hoặc trả mã thực thi. Câu hỏi: {text}',
        }, timeout=60)
        response.raise_for_status()
        return JsonResponse({'status': 'success', 'reply': response.json()['response']})
    except (requests.RequestException, ValueError, KeyError) as exc:
        return JsonResponse({'status': 'error', 'message': str(exc)}, status=502)


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
