import requests
import ssl
import socket
from urllib.parse import urlparse

class SecurityMCPTools:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.domain = self.parsed_url.netloc or self.parsed_url.path

    def check_security_headers(self) -> dict:
        """Kiểm tra các HTTP Security Headers quan trọng."""
        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection"
        ]
        results = {}
        try:
            response = requests.get(self.target_url, timeout=10)
            headers = response.headers
            for header in security_headers:
                if header in headers:
                    results[header] = {"status": "Present", "value": headers[header]}
                else:
                    results[header] = {"status": "Missing", "value": None}
            return {"success": True, "headers_analysis": results}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def check_robots_txt(self) -> str:
        """Kiểm tra file robots.txt để tìm đường dẫn ẩn."""
        robots_url = f"{self.parsed_url.scheme}://{self.domain}/robots.txt"
        try:
            response = requests.get(robots_url, timeout=5)
            if response.status_code == 200:
                return f"✅ Tìm thấy robots.txt:\n{response.text}"
            else:
                return f"⚠️ Không tìm thấy file robots.txt (Mã phản hồi: {response.status_code})"
        except Exception as e:
            return f"❌ Lỗi khi kiểm tra robots.txt: {str(e)}"
