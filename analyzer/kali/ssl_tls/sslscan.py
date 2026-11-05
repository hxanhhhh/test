import re
import shlex

from analyzer.kali.base import guard, blocked, finding, target_host, run_tool


def register(reg, client):
    @reg.tool(name="sslscan", title="sslscan – kiểm tra TLS", category="ssl_tls",
              description="Kiểm tra giao thức TLS yếu và bộ mã yếu.", params=["target"])
    def sslscan(target):
        if not guard(target):
            return blocked("sslscan", target)
        host = target_host(target)
        cmd = f"sslscan --no-colour {shlex.quote(host)}"

        def parse(stdout):
            out = []
            for proto in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
                if re.search(rf"{re.escape(proto)}\s+enabled", stdout):
                    out.append(finding("sslscan", "High", f"Giao thức TLS yếu bật: {proto}",
                                       f"{host} còn bật {proto}.",
                                       "Tắt SSLv2/3, TLS 1.0/1.1; chỉ bật TLS 1.2+."))
            if re.search(r"(RC4|3?DES|NULL|EXPORT)", stdout):
                out.append(finding("sslscan", "Medium", "Bộ mã yếu",
                                   "Phát hiện cipher yếu (RC4/DES/NULL/EXPORT).",
                                   "Chỉ dùng bộ mã hiện đại (AEAD)."))
            if not out and stdout:
                out.append(finding("sslscan", "Info", "TLS ổn", "Không thấy giao thức/cipher yếu rõ ràng."))
            return out
        return run_tool(client, "sslscan", cmd, 120, parse)
