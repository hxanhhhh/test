"""Trinh sát bảo mật an toàn (chỉ đọc) + tra cứu RAG thật.

Các kiểm tra đều thụ động: không gửi payload tấn công, không thử đăng nhập.
- HTTP security headers
- Cookie flags (Secure / HttpOnly / SameSite)
- Cấu hình TLS (phiên bản giao thức, hạn chứng chỉ) cho mục tiêu HTTPS
- robots.txt
Mỗi phát hiện được đối chiếu với kho tri thức RAG (collection_service_guide /
collection_cve tại CHROMA_PATH) để gợi ý khắc phục; thiếu RAG thì bỏ qua êm.
"""
import os
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

CHROMA_PATH = os.environ.get("CHROMA_PATH", "chroma_data")

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]
WEAK_TLS = {"SSLv3", "TLSv1", "TLSv1.1"}


class SecurityTestEngine:
    def __init__(self):
        pass

    # ---- RAG thật ----------------------------------------------------------
    def _rag_recommend(self, query):
        try:
            import chromadb
            client = chromadb.PersistentClient(path=CHROMA_PATH)
            for name in ("collection_service_guide", "collection_cve"):
                try:
                    res = client.get_collection(name).query(query_texts=[query], n_results=1)
                    docs = (res.get("documents") or [[]])[0]
                    if docs and docs[0]:
                        return " ".join(str(docs[0]).split())[:280]
                except Exception:
                    continue
        except Exception:
            return ""
        return ""

    def _finish(self, finding):
        rag = self._rag_recommend(finding["description"])
        if rag:
            finding["recommendation"] += f" | Tri thức KB: {rag}"
        return finding

    # ---- Các kiểm tra thụ động --------------------------------------------
    def _check_headers(self, headers):
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        if missing:
            return self._finish({
                "cve": "CONFIG-MISSING-HEADERS",
                "severity": "Medium",
                "description": "Thiếu các HTTP Security Header: " + ", ".join(missing) + ".",
                "recommendation": "Bổ sung các header thiếu ở tầng web server/ứng dụng (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).",
            })
        return None

    def _check_cookies(self, response):
        raw = response.headers.get("Set-Cookie", "")
        try:
            raw = "\n".join(response.raw.headers.getlist("Set-Cookie")) or raw
        except Exception:
            pass
        if not raw:
            return None
        low = raw.lower()
        flags = []
        if "secure" not in low:
            flags.append("Secure")
        if "httponly" not in low:
            flags.append("HttpOnly")
        if "samesite" not in low:
            flags.append("SameSite")
        if flags:
            return self._finish({
                "cve": "CONFIG-COOKIE-FLAGS",
                "severity": "Low",
                "description": "Cookie phiên thiếu thuộc tính bảo vệ: " + ", ".join(flags) + ".",
                "recommendation": "Đặt cookie với Secure, HttpOnly và SameSite=Lax/Strict để giảm nguy cơ đánh cắp phiên và CSRF.",
            })
        return None

    def _check_tls(self, parsed):
        if parsed.scheme != "https":
            return None
        host = parsed.hostname
        port = parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    version = ssock.version() or ""
                    cert = ssock.getpeercert()
            if version in WEAK_TLS:
                return self._finish({
                    "cve": "CONFIG-WEAK-TLS",
                    "severity": "High",
                    "description": f"Máy chủ thương lượng giao thức TLS yếu: {version}.",
                    "recommendation": "Tắt SSLv3/TLSv1.0/1.1, chỉ bật TLS 1.2+ và bộ mã hiện đại.",
                })
            not_after = cert.get("notAfter") if cert else None
            if not_after:
                expire = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (expire - datetime.now(timezone.utc)).days
                if days < 0:
                    return self._finish({
                        "cve": "CONFIG-TLS-CERT-EXPIRED",
                        "severity": "High",
                        "description": f"Chứng chỉ TLS đã hết hạn ({not_after}).",
                        "recommendation": "Gia hạn/thay chứng chỉ ngay và tự động hóa việc gia hạn.",
                    })
                if days < 15:
                    return self._finish({
                        "cve": "CONFIG-TLS-CERT-NEAR-EXPIRY",
                        "severity": "Low",
                        "description": f"Chứng chỉ TLS sắp hết hạn trong {days} ngày.",
                        "recommendation": "Lên lịch gia hạn chứng chỉ trước hạn.",
                    })
            return None
        except ssl.SSLCertVerificationError as exc:
            return self._finish({
                "cve": "CONFIG-TLS-CERT-INVALID",
                "severity": "High",
                "description": f"Xác minh chứng chỉ TLS thất bại: {exc}.",
                "recommendation": "Dùng chứng chỉ hợp lệ, đúng tên miền và còn hiệu lực từ CA tin cậy.",
            })
        except Exception as exc:
            return {
                "cve": "INFO-TLS-UNREACHABLE",
                "severity": "Low",
                "description": f"Không kiểm tra được TLS: {exc}.",
                "recommendation": "Kiểm tra lại cổng 443 và cấu hình TLS của máy chủ.",
            }

    def _check_robots(self, parsed):
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            res = requests.get(robots_url, timeout=5)
            if res.status_code == 200:
                return {
                    "cve": "INFO-ROBOTS",
                    "severity": "Low",
                    "description": "Phát hiện robots.txt công khai.",
                    "recommendation": "Rà soát robots.txt để tránh vô tình lộ đường dẫn quản trị nhạy cảm.",
                }
        except Exception:
            return None
        return None

    # ---- Điểm vào ----------------------------------------------------------
    def run_security_scan(self, target_url: str) -> dict:
        parsed = urlparse(target_url)
        findings = []
        try:
            response = requests.get(target_url, timeout=10)
        except Exception as e:
            return {
                "ai_summary": f"Không thể kết nối mục tiêu {target_url}: {e}",
                "findings": [{
                    "cve": "ERR-CONNECTION", "severity": "High",
                    "description": f"Lỗi kết nối mạng đến mục tiêu: {e}",
                    "recommendation": "Đảm bảo mục tiêu đang chạy và truy cập được từ máy kiểm thử.",
                }],
            }

        for check in (self._check_headers(response.headers),
                      self._check_cookies(response),
                      self._check_tls(parsed),
                      self._check_robots(parsed)):
            if check:
                findings.append(check)

        if not findings:
            findings.append({
                "cve": "INFO-OK", "severity": "Low",
                "description": "Không phát hiện vấn đề cấu hình thụ động cơ bản.",
                "recommendation": "Tiếp tục rà soát định kỳ; cân nhắc quét chủ động trong môi trường được phép.",
            })

        high = sum(1 for f in findings if f["severity"] == "High")
        ai_summary = (
            f"Đã hoàn tất trinh sát thụ động trên: {target_url}.\n"
            f"- Mã phản hồi HTTP: {response.status_code}\n"
            f"- Tổng phát hiện/cảnh báo: {len(findings)} (mức Cao: {high})\n"
            f"- Khuyến nghị kèm tri thức khắc phục truy hồi từ RAG (nếu có kho dữ liệu)."
        )
        return {"ai_summary": ai_summary, "findings": findings}
