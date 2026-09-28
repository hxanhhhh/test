import requests
import json
import chromadb
# Import hàm parse từ file cùng thư mục
from .parse_nmap import parse_nmap_xml
OLLAMA_API = "http://localhost:11434/api/generate"

def query_rag_knowledge(service_keyword):
    """Hàm chui vào ChromaDB để lục tìm tài liệu liên quan"""
    try:
        # Kết nối tới thư mục lưu trữ ChromaDB
        chroma_client = chromadb.PersistentClient(path="./chroma_data")
        collection = chroma_client.get_collection(name="sec_knowledge")
        
        # Tìm kiếm tài liệu bằng từ khóa (ví dụ: "ssh")
        results = collection.query(
            query_texts=[service_keyword],
            n_results=1
        )
        if results and results['documents'] and len(results['documents'][0]) > 0:
            return results['documents'][0][0]
    except Exception as e:
        print(f"[RAG Note] Chưa tìm thấy tài liệu đặc thù cho '{service_keyword}': {e}")
    return ""

def analyze_security_log(xml_file):
    # 1. Đọc và chắt lọc dữ liệu log Nmap
    log_summary = parse_nmap_xml(xml_file)
    if "File không tồn tại" in log_summary:
        return "Lỗi: Không tìm thấy file log đầu vào."

    # 2. RAG: Tự động đi tìm tài liệu bổ sung dựa trên dịch vụ phát hiện được (ví dụ ở đây là ssh)
    rag_context = ""
    if "ssh" in log_summary.lower():
        print("-> [RAG] Phát hiện dịch vụ SSH. Đang lục kho tri thức...")
        rag_context = query_rag_knowledge("ssh")
        if rag_context:
            print("-> [RAG] Đã tìm thấy tài liệu hướng dẫn Pentest SSH!")

    # 3. Gom Log + Tài liệu RAG vào Prompt gửi cho AI
    prompt = f"""
You are an expert Penetration Tester and Cyber Security Auditor. 
Analyze the following open ports discovered:
{log_summary}

Additional Security Knowledge/Context to help you guide the verification safely:
{rag_context}

You MUST reply ONLY with a valid JSON object matching the structure below. No markdown (NO ```json), no chat text.
Labels in "nodes" MUST contain actual IP and port from the log.
Since you are provided with security knowledge/templates, you MUST write a real conceptual Python PoC code in the "poc_script" field based on the context, DO NOT say 'not applicable'.

Expected JSON Structure:
{{
    "nodes": [
        {{"id": 1, "label": "Attacker (Internal)"}},
        {{"id": 2, "label": "ACTUAL_IP:ACTUAL_PORT (SERVICE_NAME)"}}
    ],
    "edges": [
        {{"from": 1, "to": 2, "label": "Specific method of attack or verification based on context"}}
    ],
    "poc_script": "Pure python code template from the provided knowledge context, replace syntax with proper escape formatting without backticks",
    "remediation": "Clear mitigation steps"
}}
"""

    payload = {
        "model": "qwen2.5-coder:3b",
        "prompt": prompt,
        "stream": False,
        "format": "json"
    }

    print("--- Đang gửi dữ liệu (Log + RAG) sang AI Local phân tích... ---")
    response = requests.post(OLLAMA_API, json=payload)
    if response.status_code == 200:
        return response.json()['response']
    return f"Lỗi từ Ollama API: {response.text}"

if __name__ == "__main__":
    json_result = analyze_security_log("nmap_sample.xml")
    print("\n--- KẾT QUẢ CUỐI CÙNG TỪ HỆ THỐNG RAG ---")
    print(json_result)