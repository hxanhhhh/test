import os
import json
import chromadb

# Định nghĩa đường dẫn gốc dựa trên vị trí của file này
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHROMA_PATH = os.path.join(BASE_DIR, "..", "chroma_data")
KB_DIR = os.path.join(BASE_DIR, "knowledge_base")

print("🚀 Bắt đầu tiến trình nạp RAG vào ChromaDB...")
print(f"📁 Thư mục Tri thức: {KB_DIR}")
print(f"🗄️ Thư mục ChromaDB: {CHROMA_PATH}")

def rebuild_all_collections():
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    
    print("\n🧹 Đang khởi tạo và làm sạch các Collections...")
    
    collections = {
        "collection_cve": "Lưu trữ thông tin chi tiết CVE, CVSS và mô tả",
        "collection_attack_technique": "Lưu trữ kỹ thuật tấn công MITRE ATT&CK",
        "collection_exploit_poc": "Lưu trữ mã khai thác mẫu PoC",
        "collection_service_guide": "Lưu trữ cẩm nang Pentest theo dịch vụ"
    }
    
    active_cols = {}
    for col_name, desc in collections.items():
        try:
            client.delete_collection(name=col_name)
            print(f" -> Đã xóa Collection cũ: {col_name}")
        except Exception:
            pass
        
        active_cols[col_name] = client.create_collection(
            name=col_name,
            metadata={"hnsw:space": "cosine", "description": desc}
        )
        print(f" -> Đã tạo thành công Collection: [ {col_name} ]")

    # 1. NẠP DỮ LIỆU CVE (.json)
    cve_dir = os.path.join(KB_DIR, "cve_data")
    if os.path.exists(cve_dir):
        print("\n📦 Đang nạp dữ liệu CVE...")
        cve_count = 0
        for file in os.listdir(cve_dir):
            if file.endswith(".json"):
                file_path = os.path.join(cve_dir, file)
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data.get("CVE_Items", []):
                        cve_id = item.get("cve_id", f"CVE_UNK_{cve_count}")
                        desc = item.get("description", "")
                        sev = item.get("severity", "UNKNOWN")
                        
                        doc = f"CVE-ID: {cve_id}\nSeverity: {sev}\nDescription: {desc}"
                        active_cols["collection_cve"].upsert(
                            documents=[doc],
                            metadatas=[{"cve_id": cve_id, "severity": sev}],
                            ids=[cve_id]
                        )
                        cve_count += 1
        print(f" -> Hoàn thành nạp {cve_count} bản ghi CVE!")

# 2. NẠP DỮ LIỆU POC / EXPLOITS (.py, .md, .rb, .txt)
    poc_dir = os.path.join(KB_DIR, "exploits_poc")
    if os.path.exists(poc_dir):
        print("\n📦 Đang nạp dữ liệu Exploit / PoC...")
        poc_count = 0
        MAX_POC = 300  # <--- THÊM DÒNG NÀY ĐỂ GIỚI HẠN 300 FILE DEMO
        
        for root, _, files in os.walk(poc_dir):
            if poc_count >= MAX_POC:
                break
            for file in files:
                if poc_count >= MAX_POC:
                    break
                if file.endswith((".py", ".md", ".rb", ".txt")):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        if content.strip():
                            poc_count += 1
                            active_cols["collection_exploit_poc"].upsert(
                                documents=[content[:2000]],
                                metadatas=[{"filename": file}],
                                ids=[f"poc_{poc_count}"]
                            )
                    except Exception:
                        continue
        print(f" -> Hoàn thành nạp {poc_count} mã PoC!")

    # 3. NẠP TÀI LIỆU CẨM NANG DỊCH VỤ (.md)
    guide_dir = os.path.join(KB_DIR, "service_guides")
    if os.path.exists(guide_dir):
        print("\n📦 Đang nạp dữ liệu Service Guides...")
        guide_count = 0
        for file in os.listdir(guide_dir):
            if file.endswith((".md", ".txt")):
                file_path = os.path.join(guide_dir, file)
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                guide_count += 1
                active_cols["collection_service_guide"].upsert(
                    documents=[content],
                    metadatas=[{"filename": file}],
                    ids=[f"guide_{guide_count}"]
                )
        print(f" -> Hoàn thành nạp {guide_count} cẩm nang dịch vụ!")

if __name__ == "__main__":
    rebuild_all_collections()