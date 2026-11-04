"""Module trùng lặp đã được gộp.

Bản RAG CVE demo nay dùng chung một nguồn duy nhất tại
``core_agent.cve_rag``. File này chỉ chuyển tiếp để các import cũ
(``from analyzer.cve_rag import CVERAGDatabase``) vẫn hoạt động.

Lưu ý: hệ RAG "chính thức" của Django (``analyzer.analysis`` +
``analyzer.rebuild_rag``) dùng các collection ``collection_cve`` /
``collection_service_guide`` tại ``settings.CHROMA_PATH`` (thư mục
``chroma_data``). Bản demo này dùng collection riêng nhưng đã được trỏ về
cùng thư mục ``chroma_data`` để không còn tách đôi kho vector.
"""
from core_agent.cve_rag import *  # noqa: F401,F403
from core_agent.cve_rag import CVERAGDatabase  # noqa: F401
