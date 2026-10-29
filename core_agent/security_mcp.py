import requests

class SecurityMCPTools:
    def __init__(self, target_url: str):
        self.target_url = target_url

    def check_security_headers(self):
        try:
            response = requests.get(self.target_url, timeout=10)
            headers = response.headers
            security_headers = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "X-XSS-Protection"
            ]
            analysis = {}
            for h in security_headers:
                if h in headers:
                    analysis[h] = {"status": "Present", "value": headers[h]}
                else:
                    analysis[h] = {"status": "Missing", "value": None}
            return {"success": True, "headers_analysis": analysis}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def check_robots_txt(self):
        try:
            url = self.target_url.rstrip('/') + '/robots.txt'
            res = requests.get(url, timeout=5)
            if res.status_code == 200:
                return res.text[:500]
            return "Không tìm thấy file robots.txt (Status: 404)"
        except Exception as e:
            return f"Lỗi kiểm tra robots.txt: {str(e)}"
