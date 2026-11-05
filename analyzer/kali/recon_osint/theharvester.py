"""theHarvester – OSINT email/subdomain

Tool Kali độc lập (1 file = 1 tool) để dễ debug. Chỉ chạy trên host lab
(loopback/IP private) nhờ guard(); sửa lệnh tại build_command().
"""
import shlex

from analyzer.kali.base import guard, blocked, run_tool, raw_parse, target_host

NAME = "theharvester"
TITLE = "theHarvester – OSINT email/subdomain"
DESCRIPTION = "Thu thập email, subdomain, host từ nguồn mở."
CATEGORY = "recon_osint"
PARAM = "target"          # tên tham số đầu vào
TIMEOUT = 180        # giây
SEVERITY = "Info"
DO_GUARD = True      # True = chỉ cho host lab


def build_command(value):
    """Dựng lệnh shell. value = host (PARAM='target') hoặc URL/chuỗi nguyên văn."""
    a = value
    qa = shlex.quote(a)
    return f"theHarvester -d {qa} -b bing,duckduckgo -l 100"


def register(reg, client):
    @reg.tool(name=NAME, title=TITLE, category=CATEGORY,
              description=DESCRIPTION, params=[PARAM])
    def _run(**kw):
        value = str(kw.get(PARAM, "") or "")
        if DO_GUARD and not guard(value):
            return blocked(NAME, value)
        arg = target_host(value) if PARAM == "target" else value
        return run_tool(client, NAME, build_command(arg), TIMEOUT,
                        raw_parse(NAME, SEVERITY))
    return _run
