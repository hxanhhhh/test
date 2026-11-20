"""Quét lỗ hổng CHỦ ĐỘNG, giới hạn chặt trong môi trường lab được phép.

Nguyên tắc an toàn (bắt buộc):
- Chỉ chạy với host nội bộ (loopback / dải IP private). Mục tiêu công khai bị từ chối.
- Payload BENIGN, không phá hoại: chỉ chèn chuỗi đánh dấu / một dấu nháy để phát
  hiện *dấu hiệu*; không khai thác, không gửi câu lệnh phá dữ liệu (DROP/UPDATE...),
  không stacked query, chỉ dùng HTTP GET trên tham số sẵn có.
- Chỉ PHÁT HIỆN và báo cáo (reflected XSS, SQLi error-based) + khuyến nghị phòng thủ.

Đây là kiểm thử bảo mật hộp đen tối thiểu phục vụ học tập trên lab của chính người
dùng (ví dụ Juice Shop /rest/products/search?q=), tương tự bước active-scan cơ bản
của công cụ DAST.
"""
import ipaddress
import re
import secrets
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

# Dấu hiệu lỗi SQL thường gặp (để phát hiện error-based, không nhằm khai thác).
SQL_ERROR_PATTERNS = [
    r"you have an error in your SQL syntax",
    r"warning.*\bmysqli?\b",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)|PostgreSQL.*ERROR",
    r"SQLITE_ERROR|SQLite3?::|SQLSTATE\[",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider for SQL Server",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)


def is_lab_host(host):
    """Chỉ cho phép loopback / private (RFC1918) / localhost."""
    if not host:
        return False
    host = host.lower()
    if host in ("localhost", "localhost.localdomain"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


class ActiveScanner:
    def __init__(self, timeout=8, cookies=None, use_headless=False, run_id=None):
        self.timeout = timeout
        self.use_headless = bool(use_headless)
        self.run_id = run_id
        self.cookies = list(cookies or [])
        # Dùng Session để tái sử dụng cookie phiên (vd phiên đăng nhập lấy từ Agent),
        # nhờ đó quét được trang cần đăng nhập.
        self.http = requests.Session()
        for c in self.cookies:
            try:
                self.http.cookies.set(c.get("name"), c.get("value"),
                                      domain=c.get("domain"), path=c.get("path", "/"))
            except Exception:
                continue

    def _fetch(self, url):
        """Trả (text, content_type). Tách riêng để test dễ mock. Chỉ GET."""
        resp = self.http.get(url, timeout=self.timeout)
        return resp.text or "", resp.headers.get("Content-Type", "")

    @staticmethod
    def _with_param(parsed, params, name, value):
        q = {k: v[:] for k, v in params.items()}
        q[name] = [value]
        return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))

    def _test_reflected_xss(self, parsed, params, name):
        token = "zxq" + secrets.token_hex(4)
        probe = token + "<x>\"'"
        body, ctype = self._fetch(self._with_param(parsed, params, name, probe))
        if token not in body:
            return None
        idx = body.find(token)
        snippet = body[max(0, idx - 20):idx + 40].replace("\n", " ")
        raw_angle = (token + "<x>") in body
        is_html = "html" in (ctype or "").lower()
        if raw_angle and is_html:
            return {
                "cve": "ACTIVE-XSS-REFLECTED", "severity": "High",
                "description": (f"Tham số '{name}' phản chiếu ký tự '<' '>' chưa mã hóa trong HTML "
                                f"(nguy cơ Reflected XSS). Trích: ...{snippet}..."),
                "recommendation": "Mã hóa đầu ra theo ngữ cảnh (HTML entity encode), bật CSP, "
                                  "kiểm tra/khử trùng dữ liệu đầu vào.",
            }
        return {
            "cve": "ACTIVE-XSS-REFLECT-INPUT", "severity": "Low",
            "description": (f"Tham số '{name}' được phản chiếu vào phản hồi "
                            f"({'HTML' if is_html else 'không phải HTML'}); cần kiểm tra ngữ cảnh. "
                            f"Trích: ...{snippet}..."),
            "recommendation": "Xác thực đầu vào và mã hóa đầu ra ở mọi ngữ cảnh hiển thị.",
        }

    def _test_sqli(self, parsed, params, name, baseline):
        base_value = params[name][0] if params.get(name) and params[name] else "1"
        body, _ = self._fetch(self._with_param(parsed, params, name, base_value + "'"))
        match = SQL_ERROR_RE.search(body)
        if match and not SQL_ERROR_RE.search(baseline):
            return {
                "cve": "ACTIVE-SQLI-ERROR", "severity": "High",
                "description": (f"Tham số '{name}' làm lộ lỗi SQL khi chèn một dấu nháy "
                                f"(dấu hiệu SQL Injection). Dấu hiệu: '{match.group(0)[:80]}'."),
                "recommendation": "Dùng truy vấn tham số hóa (prepared statements), không ghép chuỗi "
                                  "đầu vào vào câu lệnh SQL; ẩn thông báo lỗi chi tiết.",
            }
        return None

    def scan(self, target_url):
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            return self._wrap(target_url, [_f("ERR-INPUT", "Low",
                "URL phải dùng http/https.", "Nhập URL hợp lệ.")], blocked=True)
        if not is_lab_host(parsed.hostname):
            return self._wrap(target_url, [_f("BLOCKED-SCOPE", "Low",
                "Quét chủ động chỉ cho phép mục tiêu LAB nội bộ (localhost / IP private). Mục tiêu này bị từ chối.",
                "Chỉ quét chủ động trên hệ thống bạn được phép (DVWA/Juice Shop cục bộ).")], blocked=True)

        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return self._wrap(target_url, [_f("INFO-NO-PARAM", "Low",
                "URL không có tham số GET để kiểm (thêm ?param=value để quét).",
                "Cung cấp URL có tham số, ví dụ http://127.0.0.1:3000/rest/products/search?q=test.")])

        try:
            baseline, _ = self._fetch(target_url)
        except Exception as e:
            return self._wrap(target_url, [_f("ERR-CONNECTION", "High",
                f"Không kết nối được mục tiêu: {e}", "Kiểm tra mục tiêu lab đang chạy.")], blocked=True)

        findings = []
        for name in params:
            try:
                xss = self._test_reflected_xss(parsed, params, name)
                if xss:
                    findings.append(xss)
                sqli = self._test_sqli(parsed, params, name, baseline)
                if sqli:
                    findings.append(sqli)
            except Exception:
                continue

        if not findings:
            findings.append(_f("INFO-ACTIVE-CLEAN", "Low",
                "Không phát hiện dấu hiệu XSS phản chiếu / SQLi error-based ở các tham số đã thử.",
                "Đây là kiểm thử cơ bản; nên bổ sung rà soát thủ công và DAST đầy đủ."))
        return self._wrap(target_url, findings)

    @staticmethod
    def _discover(page_url, html):
        """Tự dò các endpoint có tham số trên trang: link ?a=b và form method=GET."""
        candidates = set()
        for m in re.finditer(r'href=["\']([^"\']+\?[^"\']+)["\']', html, re.IGNORECASE):
            candidates.add(urljoin(page_url, m.group(1)))
        for form in re.finditer(r'<form\b[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL):
            tag = form.group(0)
            method = re.search(r'method=["\']?(\w+)', tag, re.IGNORECASE)
            if method and method.group(1).lower() != "get":
                continue  # chỉ dò form GET (không submit POST để tránh thay đổi dữ liệu)
            action = re.search(r'action=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            act = action.group(1) if action else ""
            action_url = urljoin(page_url, act) if act and act != "#" else page_url
            params = {}
            for inp in re.findall(r'<(?:input|select|textarea)\b[^>]*>', tag, re.IGNORECASE):
                name = re.search(r'name=["\']([^"\']+)["\']', inp, re.IGNORECASE)
                if not name:
                    continue
                val = re.search(r'value=["\']([^"\']*)["\']', inp, re.IGNORECASE)
                params[name.group(1)] = val.group(1) if val else "1"
            if params:
                sep = "&" if "?" in action_url else "?"
                candidates.add(action_url + sep + urlencode(params))
        return list(candidates)[:6]

    def scan_page(self, page_url):
        """Dò tham số trên MỘT trang (vd trang sau đăng nhập mà Agent điều hướng tới)
        rồi quét từng endpoint. Dùng phiên hiện tại (cookie) nên quét được vùng auth."""
        parsed = urlparse(page_url)
        if parsed.scheme not in ("http", "https") or not is_lab_host(parsed.hostname):
            return self._wrap(page_url, [_f("BLOCKED-SCOPE", "Low",
                "Chỉ quét chủ động mục tiêu lab nội bộ.",
                "Chỉ quét hệ thống bạn được phép.")], blocked=True)
        try:
            html, _ = self._fetch(page_url)
        except Exception as e:
            return self._wrap(page_url, [_f("ERR-CONNECTION", "High",
                f"Không tải được trang: {e}", "Kiểm tra mục tiêu/đăng nhập.")], blocked=True)
        candidates = self._discover(page_url, html)
        if parsed.query:
            candidates = [page_url] + [c for c in candidates if c != page_url]

        added_dynamic = 0
        if self.use_headless:
            try:
                from .spa_crawler import crawl_spa_endpoints
                spa_res = crawl_spa_endpoints(
                    page_url, cookies=self.cookies, run_id=self.run_id
                )
                seen = set(candidates)
                for dyn_url in (spa_res.get("dynamic_urls") or []):
                    if dyn_url and dyn_url not in seen:
                        seen.add(dyn_url)
                        candidates.append(dyn_url)
                        added_dynamic += 1
            except Exception:
                added_dynamic = 0

        findings = []
        for cand in candidates:
            rep = self.scan(cand)
            for f in rep.get("findings", []):
                if f["cve"].startswith("ACTIVE-") and f["severity"] in ("High", "Low") and f["cve"] != "INFO-ACTIVE-CLEAN":
                    f["description"] += f" [endpoint: {cand}]"
                    findings.append(f)
        if not findings:
            findings.append(_f("INFO-ACTIVE-CLEAN", "Low",
                f"Dò {len(candidates)} endpoint trên trang, chưa thấy dấu hiệu XSS/SQLi.",
                "Kiểm thử cơ bản; nên rà soát thủ công + DAST đầy đủ."))
        spa_line = (
            f"- Headless SPA Crawler: +{added_dynamic} route/endpoint động (DOM/XHR).\n"
            if self.use_headless else ""
        )
        wrapped = self._wrap(page_url, findings)
        wrapped["ai_summary"] = (f"Quét chủ động sau đăng nhập trên trang: {page_url}\n"
                                 f"- Đã dò {len(candidates)} endpoint có tham số.\n"
                                 f"{spa_line}" + wrapped["ai_summary"])
        return wrapped

    @staticmethod
    def _wrap(target_url, findings, blocked=False):
        high = sum(1 for f in findings if f["severity"] == "High")
        if blocked:
            summary = f"Không thực hiện quét chủ động cho {target_url} (xem lý do bên dưới)."
        else:
            summary = (f"Quét chủ động (benign) trên lab: {target_url}.\n"
                       f"- Tổng phát hiện: {len(findings)} (mức Cao: {high}).\n"
                       f"- Phạm vi: chỉ host nội bộ, chỉ phát hiện dấu hiệu, không khai thác.")
        return {"ai_summary": summary, "findings": findings}


def _f(cve, severity, description, recommendation):
    return {"cve": cve, "severity": severity,
            "description": description, "recommendation": recommendation}
