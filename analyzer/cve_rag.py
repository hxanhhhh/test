import chromadb
from chromadb.utils import embedding_functions

class CVERAGDatabase:
    def __init__(self, db_path="./chroma_db"):
        # Khởi tạo ChromaDB client lưu cục bộ
        self.client = chromadb.PersistentClient(path=db_path)
        
        # Sử dụng default embedding function của ChromaDB
        self.embedding_fn = embedding_functions.DefaultEmbeddingFunction()
        
        # Tạo hoặc lấy collection lưu trữ CVE
        self.collection = self.client.get_or_create_collection(
            name="web_vulnerabilities",
            embedding_function=self.embedding_fn
        )
        
        # Nạp dữ liệu mẫu nếu collection đang trống
        if self.collection.count() == 0:
            self._seed_sample_data()

    def _seed_sample_data(self):
        """Nạp sẵn một số dữ liệu lỗ hổng web và hướng dẫn khắc phục mẫu."""
        documents = [
            "Thiếu Content-Security-Policy (CSP) header giúp kẻ tấn công dễ dàng thực hiện tấn công Cross-Site Scripting (XSS) và chèn mã độc.",
            "Thiếu X-Frame-Options header khiến website có nguy cơ bị tấn công Clickjacking bằng cách nhúng trang web vào iframe độc hại.",
            "Lộ file robots.txt có thể vô tình làm lộ các đường dẫn quản trị nhạy cảm hoặc thư mục riêng tư của hệ thống web.",
            "Thiếu Strict-Transport-Security (HSTS) header dẫn đến việc kết nối qua HTTP không được mã hóa tự động, dễ bị tấn công MitM.",
            "Lỗ hổng CVE-2020-25213 liên quan đến Divi Booster Plugin trong WordPress cho phép kẻ tấn công thực hiện PHP Object Injection."
        ]
        metadatas = [
            {"cve": "MISC-XSS", "severity": "Medium", "fix": "Thêm header Content-Security-Policy phù hợp vào HTTP response."},
            {"cve": "MISC-CLICKJACK", "severity": "Medium", "fix": "Thêm header X-Frame-Options: SAMEORIGIN."},
            {"cve": "INFO-DISCLOSE", "severity": "Low", "fix": "Kiểm tra kỹ nội dung file robots.txt, tránh để lộ thông tin nhạy cảm."},
            {"cve": "MISC-HSTS", "severity": "Medium", "fix": "Bật cấu hình HSTS header với max-age tối thiểu 6 tháng."},
            {"cve": "CVE-2020-25213", "severity": "High", "fix": "Cập nhật plugin Divi Booster lên phiên bản mới nhất đã vá lỗi."}
        ]
        ids = ["doc_1", "doc_2", "doc_3", "doc_4", "doc_5"]

        self.collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        print("📥 Đã nạp thành công dữ liệu mẫu CVE vào ChromaDB!")

    def query_vulnerability(self, query_text: str, n_results: int = 2):
        """Truy vấn các lỗ hổng liên quan từ ChromaDB dựa trên ngữ cảnh."""
        results = self.collection.query(
            query_texts=[query_text],
            n_results=n_results
        )
        return results
