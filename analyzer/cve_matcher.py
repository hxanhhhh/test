import os
import chromadb
from analyzer.models import Service, SecurityFinding  # Lưu ý: Thay đổi tên app/model nếu tên trong project của Hùng khác

def query_cve_from_chroma(service_name, version, n_results=3):
    """
    Truy vấn ChromaDB collection_cve dựa trên tên dịch vụ và phiên bản
    """
    # Đường dẫn tới thư mục chroma_db nằm trong thư mục gốc của dự án
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'chroma_db')
    client = chromadb.PersistentClient(path=db_path)
    
    try:
        collection = client.get_collection(name="collection_cve")
    except Exception as e:
        print(f"Không tìm thấy collection_cve: {e}")
        return []

    # Tạo câu truy vấn tìm kiếm lỗ hổng
    search_query = f"vulnerability in {service_name} version {version}"
    
    results = collection.query(
        query_texts=[search_query],
        n_results=n_results
    )
    
    cve_findings = []
    if results and 'documents' in results and results['documents']:
        docs = results['documents'][0]
        metas = results['metadatas'][0] if 'metadatas' in results else [{}] * len(docs)
        
        for doc, meta in zip(docs, metas):
            cve_findings.append({
                "description": doc,
                "cve_id": meta.get("cve_id", "Unknown CVE"),
                "cvss_score": meta.get("cvss_score", 0.0),
                "remediation": meta.get("remediation", "Cập nhật phiên bản mới nhất cho dịch vụ.")
            })
            
    return cve_findings

def run_nmap_cve_pipeline():
    """
    Hàm chính: Lấy toàn bộ Service từ DB, query ChromaDB và lưu vào SecurityFinding
    """
    services = Service.objects.all()
    count_saved = 0
    
    for s in services:
        # Lấy tên dịch vụ và phiên bản từ model Service
        service_name = getattr(s, 'name', getattr(s, 'service_name', ''))
        version = getattr(s, 'version', '')
        
        if service_name and version:
            matched_cves = query_cve_from_chroma(service_name, version)
            
            for cve in matched_cves:
                cvss = float(cve["cvss_score"]) if str(cve["cvss_score"]).replace('.','',1).isdigit() else 0.0
                # Phân loại mức độ nghiêm trọng dựa trên điểm CVSS
                severity = "Critical" if cvss >= 9.0 else ("High" if cvss >= 7.0 else ("Medium" if cvss >= 4.0 else "Low"))
                
                # Lưu hoặc cập nhật vào bảng SecurityFinding để hiển thị lên Dashboard
                SecurityFinding.objects.update_or_create(
                    service=s,
                    cve_id=cve["cve_id"],
                    defaults={
                        "title": f"Phát hiện lỗ hổng {cve['cve_id']} trên {service_name} {version}",
                        "description": cve["description"],
                        "severity": severity,
                        "cvss_score": cvss,
                        "remediation": cve["remediation"]
                    }
                )
                count_saved += 1
                
    print(f"Đã đối chiếu và lưu thành công {count_saved} CVE vào SecurityFinding!")
