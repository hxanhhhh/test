import re
import shlex

from analyzer.kali.base import guard, blocked, finding, run_tool

SEV = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


def register(reg, client):
    @reg.tool(name="nuclei", title="Nuclei – quét lỗ hổng theo template", category="vuln_scanners",
              description="Quét lỗ hổng dựa trên template cộng đồng (CVE, misconfig, exposure).",
              params=["url"])
    def nuclei(url):
        if not guard(url):
            return blocked("nuclei", url)
        cmd = (f"nuclei -u {shlex.quote(url)} -severity low,medium,high,critical "
               f"-rate-limit 100 -timeout 10 -no-color -silent")

        def parse(stdout):
            out = []
            for line in stdout.splitlines():
                m = re.search(r"\[(critical|high|medium|low)\]", line, re.IGNORECASE)
                if m:
                    out.append(finding("nuclei", SEV[m.group(1).lower()], "Phát hiện (nuclei)",
                                       line.strip()[:300], "Khắc phục theo template nuclei đã khớp."))
            if not out and stdout:
                out.append(finding("nuclei", "Info", "nuclei hoàn tất", "Không khớp template nào."))
            return out[:20]
        return run_tool(client, "nuclei", cmd, 360, parse)
