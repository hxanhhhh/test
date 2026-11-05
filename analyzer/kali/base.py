"""Tiện ích dùng chung cho các tool Kali: giới hạn host lab, finding, chạy lệnh."""
from urllib.parse import urlparse

from analyzer.active_scan import is_lab_host


def target_host(target):
    parsed = urlparse(target if "://" in target else "http://" + target)
    return parsed.hostname or target


def guard(target):
    """Chỉ cho phép host nội bộ (loopback/IP private). An toàn bắt buộc."""
    return is_lab_host(target_host(target))


def finding(tool, severity, title, description, recommendation=""):
    return {"tool": tool, "severity": severity, "title": title,
            "description": description, "recommendation": recommendation}


def blocked(tool, target):
    return {"ok": False, "tool": tool, "command": "", "raw": "",
            "findings": [finding(tool, "Low", "Ngoài phạm vi lab",
                                 f"'{target}' không phải host nội bộ (loopback/IP private) nên bị từ chối.",
                                 "Chỉ chạy công cụ tấn công trên lab bạn được phép.")]}


def run_tool(client, tool, cmd, timeout, parse):
    """Chạy lệnh qua KaliClient rồi parse stdout -> findings."""
    res = client.run(cmd, timeout=timeout)
    stdout = res.get("stdout", "") or ""
    findings = parse(stdout) or []
    return {"ok": res.get("success", False), "tool": tool, "command": cmd,
            "findings": findings, "raw": stdout[:4000]}


def raw_parse(tool, severity="Info", title=None):
    """Parser mặc định: gói output thành một finding (giống Kali_MCP trả raw)."""
    def parse(stdout):
        txt = (stdout or "").strip()
        if not txt:
            return [finding(tool, severity, title or f"{tool} hoàn tất", "(không có output)")]
        return [finding(tool, severity, title or f"Kết quả {tool}", txt[:600])]
    return parse


def make_adder(reg, client, category):
    """Trả hàm add(...) để đăng ký tool wrapper gọn trong một nhóm.

    cmd_fn nhận giá trị tham số đã xử lý (host nếu param='target', nguyên văn nếu khác)
    và trả về chuỗi lệnh. do_guard=False cho tool không nhắm host (vd searchsploit).
    """
    def add(name, title, desc, cmd_fn, param="target", timeout=60, severity="Info", do_guard=True):
        @reg.tool(name=name, title=title, category=category, description=desc, params=[param])
        def _tool(**kw):
            val = str(kw.get(param, "") or "")
            if do_guard and not guard(val):
                return blocked(name, val)
            arg = target_host(val) if param == "target" else val
            return run_tool(client, name, cmd_fn(arg), timeout, raw_parse(name, severity))
        return _tool
    return add
