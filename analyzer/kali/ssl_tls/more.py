import shlex

from analyzer.kali.base import make_adder


def register(reg, client):
    add = make_adder(reg, client, "ssl_tls")
    add("testssl", "testssl.sh – kiểm tra TLS toàn diện", "Kiểm tra giao thức, cipher, lỗ hổng TLS.",
        lambda h: f"testssl --quiet --color 0 {shlex.quote(h)}", timeout=300)
    add("sslyze", "SSLyze – phân tích cấu hình TLS", "Phân tích cấu hình/chứng chỉ TLS.",
        lambda h: f"sslyze {shlex.quote(h)}", timeout=180)
    add("nmap_ssl", "Nmap NSE – liệt kê cipher TLS", "Liệt kê cipher/giao thức SSL-TLS qua Nmap.",
        lambda h: f"nmap --script ssl-enum-ciphers -p 443 {shlex.quote(h)}", timeout=180)
    add("tlssled", "TLSSLed – kiểm tra TLS", "Kiểm tra nhanh cấu hình SSL/TLS của dịch vụ HTTPS.",
        lambda h: f"tlssled {shlex.quote(h)} 443", timeout=180)
