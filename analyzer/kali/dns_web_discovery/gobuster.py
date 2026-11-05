import re
import shlex

from analyzer.kali.base import guard, blocked, finding, run_tool

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


def register(reg, client):
    @reg.tool(name="gobuster", title="Gobuster – dò thư mục/đường dẫn", category="dns_web_discovery",
              description="Brute-force thư mục/đường dẫn web bằng wordlist để tìm trang ẩn.",
              params=["url", "wordlist"])
    def gobuster(url, wordlist=DEFAULT_WORDLIST):
        if not guard(url):
            return blocked("gobuster", url)
        cmd = (f"gobuster dir -u {shlex.quote(url)} -w {shlex.quote(wordlist)} "
               f"-q -t 20 --timeout 10s --no-error")

        def parse(stdout):
            out = []
            for line in stdout.splitlines():
                m = re.search(r"^(/\S+)\s+\(Status:\s*(\d+)\)", line.strip())
                if m:
                    out.append(finding("gobuster", "Low", f"Đường dẫn: {m.group(1)}",
                                       f"Tìm thấy {m.group(1)} (HTTP {m.group(2)}).",
                                       "Kiểm tra quyền truy cập các đường dẫn lộ ra."))
            if not out and stdout:
                out.append(finding("gobuster", "Info", "gobuster hoàn tất",
                                   "Không tìm thấy đường dẫn nào (hoặc thiếu wordlist)."))
            return out[:40]
        return run_tool(client, "gobuster", cmd, 300, parse)
