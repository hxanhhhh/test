"""Registry gom các tool bảo mật (mô phỏng cách FastMCP đăng ký tool của Kali_MCP).

Mỗi tool đăng ký qua decorator ``@reg.tool(name=..., title=..., category=...)``.
Agent/UI dùng ``reg.list()`` để liệt kê và ``reg.call(name, **kwargs)`` để chạy.
"""


class ToolRegistry:
    def __init__(self, client):
        self.client = client
        self.tools = {}

    def tool(self, name, title="", description="", category="", params=None):
        def deco(fn):
            self.tools[name] = {
                "name": name, "title": title, "description": description,
                "category": category, "params": params or [], "fn": fn,
            }
            return fn
        return deco

    def list(self, category=None):
        out = []
        for t in self.tools.values():
            if category and t["category"] != category:
                continue
            out.append({k: v for k, v in t.items() if k != "fn"})
        return out

    def categories(self):
        return sorted({t["category"] for t in self.tools.values()})

    def call(self, name, **kwargs):
        t = self.tools.get(name)
        if not t:
            return {"ok": False, "tool": name, "findings": [],
                    "error": f"Không có tool '{name}'."}
        return t["fn"](**kwargs)
