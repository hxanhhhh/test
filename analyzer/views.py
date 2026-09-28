import os
import json
import requests
import chromadb
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from .models import SecurityProject, TargetAsset, ExploitSuggestion
from .parse_nmap import parse_nmap_xml

CHROMA_PATH = "./chroma_data"
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5-coder:3b"



def get_chroma_client():
    return chromadb.PersistentClient(path=CHROMA_PATH)

def dashboard_view(request):
    projects = SecurityProject.objects.all().order_by('-created_at')
    return render(request, 'dashboard.html', {'projects': projects})

def upload_nmap_log(request):
    """Bóc tách Nmap XML thành các TargetAsset độc lập trong CSDL"""
    if request.method == "POST" and request.FILES.get('nmap_file'):
        project_name = request.POST.get('project_name', 'Dự án Đánh giá Mới')
        nmap_file = request.FILES['nmap_file']
        
        project = SecurityProject.objects.create(name=project_name)
        parsed_hosts = parse_nmap_xml(nmap_file)
        
        for host in parsed_hosts:
            asset = TargetAsset.objects.create(
                project=project,
                ip_address=host.get('ip', '0.0.0.0'),
                hostname=host.get('hostname', ''),
                os_info=host.get('os', 'Unknown OS')
            )
            
            for service in host.get('services', []):
                ExploitSuggestion.objects.create(
                    asset=asset,
                    port=service.get('port', 0),
                    service_name=service.get('name', 'unknown'),
                    service_version=service.get('version', ''),
                    attack_path_summary="Chưa phân tích (Nhấn nút để kích hoạt AI RAG)",
                    suggested_poc_code="# Chưa sinh mã PoC"
                )
                
        return JsonResponse({'status': 'success', 'project_id': project.id})
    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)


@csrf_exempt
def chat_with_asset_ai(request, asset_id):
    """API Chatbot trao đổi trực tiếp với AI dựa trên ngữ cảnh của Asset"""
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_message = data.get("message", "")
            
            asset = get_object_or_404(TargetAsset, id=asset_id)
            vulns = asset.vulnerabilities.all()
            
            # Gom ngữ cảnh về IP này để Chatbot nắm rõ bối cảnh
            vuln_context = []
            for v in vulns:
                vuln_context.append(f"- Port {v.port} ({v.service_name} {v.service_version}): CVE={v.cve_references}")
            
            context_str = "\n".join(vuln_context)
            
            system_prompt = f"""
            Bạn là Chuyên gia An ninh mạng / Pentest AI thuộc hệ thống.
            Dưới đây là thông tin máy mục tiêu người dùng đang thảo luận:
            - Target IP: {asset.ip_address}
            - Dịch vụ/Cổng mở:
            {context_str}

            Hãy trả lời câu hỏi của người dùng ngắn gọn, chính xác, chuyên nghiệp và mang tính kỹ thuật an ninh mạng.
            """

            full_prompt = f"{system_prompt}\n\nNgười dùng hỏi: {user_message}\nAI trả lời:"

            res = requests.post(OLLAMA_URL, json={
                "model": MODEL_NAME,
                "prompt": full_prompt,
                "stream": False
            }, timeout=60)

            if res.status_code == 200:
                reply = res.json().get("response", "Không thể phản hồi.")
                return JsonResponse({"status": "success", "reply": reply})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=500)

    return JsonResponse({"status": "error", "message": "Method not allowed"}, status=405)

@csrf_exempt
def chat_with_asset_ai(request, asset_id):
    """API Chatbot trao đổi trực tiếp với AI dựa trên ngữ cảnh của Asset"""
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_message = data.get("message", "")
            
            asset = get_object_or_404(TargetAsset, id=asset_id)
            vulns = asset.vulnerabilities.all()
            
            # Gom ngữ cảnh về IP này để Chatbot nắm rõ bối cảnh
            vuln_context = []
            for v in vulns:
                vuln_context.append(f"- Port {v.port} ({v.service_name} {v.service_version}): CVE={v.cve_references}")
            
            context_str = "\n".join(vuln_context)
            
            system_prompt = f"""
            Bạn là Chuyên gia An ninh mạng / Pentest AI thuộc hệ thống.
            Dưới đây là thông tin máy mục tiêu người dùng đang thảo luận:
            - Target IP: {asset.ip_address}
            - Dịch vụ/Cổng mở:
            {context_str}

            Hãy trả lời câu hỏi của người dùng ngắn gọn, chính xác, chuyên nghiệp và mang tính kỹ thuật an ninh mạng.
            """

            full_prompt = f"{system_prompt}\n\nNgười dùng hỏi: {user_message}\nAI trả lời:"

            res = requests.post(OLLAMA_URL, json={
                "model": MODEL_NAME,
                "prompt": full_prompt,
                "stream": False
            }, timeout=60)

            if res.status_code == 200:
                reply = res.json().get("response", "Không thể phản hồi.")
                return JsonResponse({"status": "success", "reply": reply})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=500)

    return JsonResponse({"status": "error", "message": "Method not allowed"}, status=405)

def analyze_target_asset(request, asset_id):
    """Truy vấn RAG song song và sinh kịch bản PoC cho từng Target Asset"""
    asset = get_object_or_404(TargetAsset, id=asset_id)
    vulnerabilities = asset.vulnerabilities.all()
    client = get_chroma_client()
    
    for vuln in vulnerabilities:
        service_kw = f"{vuln.service_name} {vuln.service_version}".strip()
        context_list = []
        
        # 1. Query CVE
        try:
            col_cve = client.get_collection("collection_cve")
            cve_res = col_cve.query(query_texts=[service_kw], n_results=1)
            if cve_res['documents'] and cve_res['documents'][0]:
                context_list.append("=== DỮ LIỆU CVE NVD ===\n" + cve_res['documents'][0][0])
        except Exception: pass
            
        # 2. Query PoC / Exploit
        try:
            col_poc = client.get_collection("collection_exploit_poc")
            poc_res = col_poc.query(query_texts=[service_kw], n_results=1)
            if poc_res['documents'] and poc_res['documents'][0]:
                context_list.append("=== MÃ EXPLOIT / POC THAM KHẢO ===\n" + poc_res['documents'][0][0])
        except Exception: pass

        context_str = "\n\n".join(context_list)
        
        # 3. Prompt gửi AI Ollama
        prompt = f"""
        Bạn là một chuyên gia Pentest an ninh mạng. Hãy phân tích dịch vụ mục tiêu dưới đây:
        - Target IP: {asset.ip_address}
        - Port: {vuln.port}
        - Service: {vuln.service_name} ({vuln.service_version})

        NGỮ CẢNH RAG TRUY VẤN ĐƯỢC:
        {context_str}

        YÊU CẦU TRẢ VỀ ĐỊNH DẠNG JSON DUY NHẤT:
        {{
            "attack_path": "Mô tả ngắn gọn chuỗi các bước tấn công từ Reconnaissance -> Exploitation",
            "poc_code": "Đoạn mã Python kiểm thử an toàn thực tế có xử lý exception",
            "cve": "Mã CVE liên quan nếu có"
        }}
        """
        
        try:
            res = requests.post(OLLAMA_URL, json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False,
                "format": "json"
            }, timeout=60)
            
            if res.status_code == 200:
                ai_output = json.loads(res.json().get('response', '{}'))
                vuln.attack_path_summary = ai_output.get('attack_path', 'Không thể xây dựng chuỗi tấn công.')
                vuln.suggested_poc_code = ai_output.get('poc_code', '# Không tạo được mã PoC')
                vuln.cve_references = ai_output.get('cve', 'N/A')
                vuln.save()
        except Exception as e:
            vuln.attack_path_summary = f"Lỗi kết nối AI: {str(e)}"
            vuln.save()
            
    return JsonResponse({'status': 'completed', 'asset_id': asset.id})
def get_asset_detail(request, asset_id):
    """API trả về JSON thông tin chi tiết dịch vụ và mã PoC của một IP"""
    asset = get_object_or_404(TargetAsset, id=asset_id)
    vulns = asset.vulnerabilities.all()
    
    vuln_list = []
    for v in vulns:
        vuln_list.append({
            'port': v.port,
            'service': v.service_name,
            'version': v.service_version,
            'attack_path': v.attack_path_summary,
            'poc_code': v.suggested_poc_code,
            'cve': v.cve_references
        })
        
    return JsonResponse({
        'ip': asset.ip_address,
        'vulnerabilities': vuln_list
    })