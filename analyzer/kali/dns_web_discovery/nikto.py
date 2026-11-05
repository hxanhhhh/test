import shlex

from analyzer.kali.base import guard, blocked, finding, run_tool


def register(reg, client):
    @reg.tool(name="nikto", title="Nikto – quét web server", category="dns_web_discovery",
              description="Rà lỗ hổng/misconfig web server, file nhạy cảm, header.",
              params=["url"])
    def nikto(url):
        if not guard(url):
            return blocked("nikto", url)
        cmd = f"nikto -host {shlex.quote(url)} -maxtime 120 -ask no -nointeractive"

        def parse(stdout):
            out = []
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("+ ") and len(line) > 10 and "Target" not in line and "Start Time" not in line:
                    out.append(finding("nikto", "Medium", "Phát hiện (nikto)", line[2:][:300],
                                       "Rà soát cấu hình/web server theo cảnh báo nikto."))
            if not out and stdout:
                out.append(finding("nikto", "Info", "nikto hoàn tất", "Không có mục '+' đáng chú ý."))
            return out[:20]
        return run_tool(client, "nikto", cmd, 200, parse)
