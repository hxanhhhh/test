import chromadb
import os

def init_vector_db():
    # Khởi tạo ChromaDB lưu dưới dạng file local trong thư mục 'chroma_data'
    chroma_client = chromadb.PersistentClient(path="./chroma_data")
    
    # Tạo hoặc lấy một bảng (Collection) tên là 'sec_knowledge'
    collection = chroma_client.get_or_create_collection(name="sec_knowledge")
    
    # Đọc file tài liệu pentest từ thư mục knowledge_base
    file_path = "analyzer/knowledge_base/ssh_pentest.txt"
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Nạp dữ liệu vào DB (ChromaDB sẽ tự động dùng mô hình mặc định để biến chữ thành vector)
        collection.add(
            documents=[content],
            metadatas=[{"source": "ssh_pentest.txt"}],
            ids=["ssh_001"]
        )
        print("--- Đã nạp tài liệu Pentest vào Vector DB thành công! ---")
    else:
        print("Chưa có file tài liệu trong thư mục knowledge_base")

if __name__ == "__main__":
    init_vector_db()