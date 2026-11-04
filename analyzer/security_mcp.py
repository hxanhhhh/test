"""Module trùng lặp đã được gộp.

Công cụ kiểm tra bảo mật demo nay dùng chung một nguồn duy nhất tại
``core_agent.security_mcp``. File này chỉ chuyển tiếp để các import cũ
(``from analyzer.security_mcp import SecurityMCPTools``) vẫn hoạt động.
"""
from core_agent.security_mcp import *  # noqa: F401,F403
from core_agent.security_mcp import SecurityMCPTools  # noqa: F401
