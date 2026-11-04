import os
import chromadb

# Thống nhất đường dẫn kho vector với phần Django (settings.CHROMA_PATH).
# Mặc định "chroma_data" (cùng thư mục mà rebuild_rag.py và analysis.py dùng),
# có thể ghi đè bằng biến môi trường CHROMA_PATH.
CHROMA_PATH = os.environ.get("CHROMA_PATH", "chroma_data")


class CVERAGDatabase:
    def __init__(self):
        self.client = chromadb.PersistentClient(path=CHROMA_PATH)
        self.collection = self.client.get_or_create_collection(name="web_cve_knowledge")
        self._seed_data()

    def _seed_data(self):
        if self.collection.count() == 0:
            self.collection.add(
                documents=[
                    "Thiếu Strict-Transport-Security (HSTS) dẫn đến tấn công downgrade HTTP, kẻ tấn công có thể chặn bắt lưu lượng.",
                    "Thiếu Content-Security-Policy (CSP) làm tăng nguy cơ bị tấn công Cross-Site Scripting (XSS) và chèn mã độc.",
                    "Thiếu X-Frame-Options khiến website dễ bị tấn công Clickjacking bằng cách nhúng vào thẻ iframe độc hại."
                ],
                metadatas=[
                    {"cve": "SEC-HDR-01", "severity": "Medium", "fix": "Thêm header Strict-Transport-Security: max-age=31536000; includeSubDomains"},
                    {"cve": "SEC-HDR-02", "severity": "High", "fix": "Thêm header Content-Security-Policy: default-src 'self'"},
                    {"cve": "SEC-HDR-03", "severity": "Medium", "fix": "Thêm header X-Frame-Options: SAMEORIGIN"}
                ],
                ids=["doc1", "doc2", "doc3"]
            )

    def query_vulnerability(self, query_text: str, n_results=2):
        try:
            results = self.collection.query(
                query_texts=[query_text],
                n_results=n_results
            )
            return results
        except Exception as e:
            return None
