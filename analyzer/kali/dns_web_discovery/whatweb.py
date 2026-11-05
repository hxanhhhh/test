import shlex

from analyzer.kali.base import guard, blocked, finding, run_tool


def register(reg, client):
    @reg.tool(name="whatweb", title="WhatWeb – nhận diện công nghệ", category="dns_web_discovery",
              description="Nhận diện web server, framework, CMS, ngôn ngữ.", params=["url"])
    def whatweb(url):
        if not guard(url):
            return blocked("whatweb", url)
        cmd = f"whatweb --no-errors --color=never {shlex.quote(url)}"

        def parse(stdout):
            return [finding("whatweb", "Info", "Nhận diện công nghệ",
                            stdout.strip()[:400] or "(không có dữ liệu)",
                            "Giảm tiết lộ phiên bản/banner nếu không cần.")]
        return run_tool(client, "whatweb", cmd, 90, parse)
