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
        "collection_service_guide": "Lưu trữ hướng dẫn cấu hình và khắc phục theo dịch vụ"
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
                        metadata = {"cve_id": cve_id, "severity": sev}
                        for key in ("product", "version", "cpe"):
                            if isinstance(item.get(key), str) and item[key]:
                                metadata[key] = item[key]
                        active_cols["collection_cve"].upsert(
                            documents=[doc],
                            metadatas=[metadata],
                            ids=[cve_id]
                        )
                        cve_count += 1
        print(f" -> Hoàn thành nạp {cve_count} bản ghi CVE!")

    # 2. NẠP TÀI LIỆU CẨM NANG DỊCH VỤ (.md)
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