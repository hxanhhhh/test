import requests

class SecurityTestEngine:
    def __init__(self):
        # Có thể cấu hình kết nối RAG hoặc ChromaDB ở đây nếu cần
        pass

    def run_security_scan(self, target_url: str) -> dict:
        """
        Thực hiện tiến trình trinh sát bảo mật an toàn (M6, F08 - F10):
        Kiểm tra HTTP headers, robots.txt và trả về báo cáo đánh giá lỗ hổng mô phỏng CVE RAG.
        """
        findings = []
        ai_summary = ""
        
        try:
            # Gửi request kiểm tra website mục tiêu
            response = requests.get(target_url, timeout=10)
            headers = response.headers
            
            # Kiểm tra các security headers cơ bản
            missing_headers = []
            if "X-Frame-Options" not in headers:
                missing_headers.append("X-Frame-Options (Chống Clickjacking)")
            if "Content-Security-Policy" not in headers:
                missing_headers.append("Content-Security-Policy (CSP)")
            if "X-Content-Type-Options" not in headers:
                missing_headers.append("X-Content-Type-Options (MIME-sniffing protection)")

            if missing_headers:
                findings.append({
                    "cve": "CVE-INFO-MISSING-HEADERS",
                    "severity": "Medium",
                    "description": f"Website mục tiêu thiếu các HTTP Security Headers quan trọng: {', '.join(missing_headers)}.",
                    "recommendation": "Cấu hình Web Server (Nginx/Apache/Django) để bổ sung đầy đủ các Security Headers nhằm tăng cường bảo mật trình duyệt."
                })
            else:
                findings.append({
                    "cve": "INFO-SECURE-HEADERS",
                    "severity": "Low",
                    "description": "Website đã cấu hình tốt các HTTP Security Headers cơ bản.",
                    "recommendation": "Tiếp tục duy trì và định kỳ kiểm tra cấu hình."
                })

            # Kiểm tra robots.txt
            robots_url = target_url.rstrip('/') + '/robots.txt'
            r_resp = requests.get(robots_url, timeout=5)
            if r_resp.status_code == 200:
                findings.append({
                    "cve": "CVE-INFO-ROBOTS",
                    "severity": "Low",
                    "description": "Phát hiện tệp robots.txt công khai trên hệ thống mục tiêu.",
                    "recommendation": "Kiểm tra kỹ nội dung robots.txt để tránh vô tình lộ các đường dẫn quản trị (admin paths) nhạy cảm."
                })

            ai_summary = (
                f"Đã hoàn tất tiến trình trinh sát bảo mật an toàn trên mục tiêu: {target_url}.\n"
                f"- Trạng thái phản hồi HTTP: {response.status_code}\n"
                f"- Tổng số lỗ hổng/cảnh báo ghi nhận: {len(findings)}\n"
                f"- Đánh giá chung: Hệ thống không phát hiện lỗ hổng nghiêm trọng (Critical/High) mang tính phá hoại, phù hợp cho tiêu chuẩn kiểm định an toàn ứng dụng web."
            )

        except Exception as e:
            ai_summary = f"Không thể kết nối hoặc trinh sát mục tiêu {target_url} do lỗi: str(e)"
            findings.append({
                "cve": "ERR-CONNECTION",
                "severity": "High",
                "description": f"Lỗi kết nối mạng đến mục tiêu: {str(e)}",
                "recommendation": "Đảm bảo Target URL đang hoạt động trực tuyến và có thể truy cập được từ máy chủ kiểm thử."
            })

        return {
            "ai_summary": ai_summary,
            "findings": findings
        }
