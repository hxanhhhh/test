"""Client HTTP tới MCP-Kali-Server (kali_server.py chạy trên máy Kali).

Dùng endpoint chung ``POST /api/command`` để chạy công cụ pentest thật (nmap,
nikto, sqlmap, nuclei, sslscan, whatweb...) và ``GET /health`` để kiểm tra kết nối.

Cấu hình địa chỉ Kali qua biến môi trường ``KALI_URL`` (mặc định
http://127.0.0.1:5000 — đúng khi Django chạy CÙNG máy Kali; nếu khác máy thì đặt
KALI_URL=http://<ip-kali>:5000).
"""
import os

import requests

DEFAULT_URL = "http://127.0.0.1:5000"


def resolve_url():
    """Lấy địa chỉ máy Kali: ưu tiên settings.KALI_URL (Django), rồi biến môi
    trường KALI_URL, cuối cùng mặc định localhost:5000."""
    try:
        from django.conf import settings
        url = getattr(settings, "KALI_URL", None)
        if url:
            return url
    except Exception:
        pass
    return os.environ.get("KALI_URL", DEFAULT_URL)


# Giữ tên cũ cho tương thích (một số chỗ import KALI_URL).
KALI_URL = resolve_url()


class KaliClient:
    def __init__(self, base_url=None, timeout=300):
        self.base_url = (base_url or resolve_url()).rstrip("/")
        self.timeout = timeout

    def health(self):
        try:
            r = requests.get(f"{self.base_url}/health", timeout=10)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"error": str(e)}

    def run(self, command, timeout=None):
        """Chạy một lệnh trên Kali qua /api/command. Trả dict chuẩn của server."""
        try:
            r = requests.post(f"{self.base_url}/api/command",
                              json={"command": command}, timeout=timeout or self.timeout)
            r.raise_for_status()
            data = r.json()
            data.setdefault("command", command)
            return data
        except Exception as e:
            return {"success": False, "stdout": "", "stderr": str(e),
                    "error": str(e), "command": command, "return_code": -1}
