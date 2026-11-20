"""Dalfox – quét XSS

Tool Kali độc lập (1 file = 1 tool) để dễ debug. Chỉ chạy trên host lab
(loopback/IP private) nhờ guard(); sửa lệnh tại build_command().
"""
import shlex

from analyzer.kali.base import guard, blocked, run_tool, raw_parse, target_host

NAME = "dalfox"
TITLE = "Dalfox – quét XSS"
DESCRIPTION = "Quét lỗ hổng XSS tự động (tham số URL)."
CATEGORY = "vuln_scanners"
PARAM = "url"          # tên tham số đầu vào
TIMEOUT = 240        # giây
SEVERITY = "Medium"
DO_GUARD = True      # True = chỉ cho host lab


def build_command(value, cookie: str = ""):
    """Dựng lệnh shell. value = host (PARAM='target') hoặc URL/chuỗi nguyên văn."""
    qa = shlex.quote(value)
    cmd = f"dalfox url {qa} --silence --no-color"
    if cookie:
        cmd += f" -b {shlex.quote(cookie)}"
    return cmd


def register(reg, client):
    @reg.tool(name=NAME, title=TITLE, category=CATEGORY,
              description=DESCRIPTION, params=[PARAM, "cookie"])
    def _run(**kw):
        value = str(kw.get(PARAM, "") or "")
        cookie = str(kw.get("cookie", "") or "").strip()
        if DO_GUARD and not guard(value):
            return blocked(NAME, value)
        arg = target_host(value) if PARAM == "target" else value
        return run_tool(client, NAME, build_command(arg, cookie=cookie), TIMEOUT,
                        raw_parse(NAME, SEVERITY))
    return _run
