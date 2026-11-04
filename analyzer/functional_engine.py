"""Module trùng lặp đã được gộp.

Engine kiểm thử chức năng demo nay dùng chung một nguồn duy nhất tại
``core_agent.functional_engine``. File này chỉ chuyển tiếp để các import cũ
(``from analyzer.functional_engine import FunctionalTestEngine``) vẫn hoạt động.
"""
from core_agent.functional_engine import *  # noqa: F401,F403
from core_agent.functional_engine import FunctionalTestEngine  # noqa: F401
