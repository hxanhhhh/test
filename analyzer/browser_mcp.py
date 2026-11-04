"""Module trùng lặp đã được gộp.

Toàn bộ logic trình duyệt demo nay dùng chung một nguồn duy nhất tại
``core_agent.browser_mcp``. File này chỉ chuyển tiếp để các import cũ
(``from analyzer.browser_mcp import BrowserMCPTools``) vẫn hoạt động.
"""
from core_agent.browser_mcp import *  # noqa: F401,F403
from core_agent.browser_mcp import BrowserMCPTools  # noqa: F401
