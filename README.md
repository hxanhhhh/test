# Web Sec Test — Kiểm thử Web Tự động bằng AI Agent & MCP

Hệ thống Django kết hợp **AI Agent + MCP** để **kiểm thử chức năng** web (tự điều
hướng, đăng nhập, điền form) và **kiểm thử bảo mật** (trinh sát thụ động + quét chủ
động XSS/SQLi trong lab + đối chiếu CVE qua RAG). LLM chạy cục bộ bằng **Ollama**,
kho tri thức CVE/hướng dẫn lưu trong **ChromaDB**. Đồ án tốt nghiệp — ngành An toàn
thông tin, PTIT.

## Kiến trúc thư mục

```
core/            Cấu hình Django (settings, urls)
analyzer/        App chính:
  views.py         Trang chủ hợp nhất (3 tab) + API
  models.py        TestProject, FunctionalTestCase/Run, TestStepResult,
                   SecurityScan, TargetAsset, Service, SecurityFinding
  agent_runner.py  Tác tử LLM điều khiển trình duyệt qua browser_tools (Chế độ B)
  functional_... → engine kịch bản tĩnh (Chế độ A) nằm trong core_agent
  analysis.py      Đánh giá rủi ro nmap bằng Ollama + RAG (version/CPE + range,
                   lọc CVE grounded chống "ảo")
  active_scan.py   Quét chủ động XSS/SQLi, GIỚI HẠN host nội bộ, payload benign
  parse_nmap.py    Parser Nmap XML
  fetch_nvd_cve.py Tải CVE thật từ NVD (kèm product/version/CPE + khoảng phiên bản)
  rebuild_rag.py   Nạp knowledge_base/ vào ChromaDB (2 collection)
  knowledge_base/  Dữ liệu CVE (.json) + cẩm nang dịch vụ (.md)
core_agent/      Engine demo dùng chung: functional_engine, browser_mcp,
                 security_engine (trinh sát thụ động + RAG)
browser_tools/   MCP server độc lập: 7 tool trình duyệt có giới hạn scope
scripts/         run_all.sh, benchmark_lab.py, make_report.py, demo_*, smoke_lab.py
```

## Cài đặt

Python 3.12+, chạy từ thư mục chứa `manage.py`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python manage.py migrate
```

SQLite lưu tại `db.sqlite3`; kho vector tại `chroma_data/`.

## Ollama (LLM cục bộ)

```bash
ollama serve                 # terminal riêng
ollama pull qwen2.5-coder:3b # hoặc model mạnh hơn: qwen2.5:7b-instruct
```

Đổi model không cần sửa code: đặt biến môi trường `OLLAMA_MODEL`. Cấu hình khác:
`OLLAMA_URL`, `CHROMA_PATH` (mặc định trong `core/settings.py`).

## Nạp RAG (CVE + hướng dẫn)

```bash
python -m analyzer.fetch_nvd_cve   # tải CVE thật từ NVD (cần mạng; đặt NVD_API_KEY để đỡ rate-limit)
python -m analyzer.rebuild_rag     # nạp vào collection_cve + collection_service_guide
```

Chạy lại `rebuild_rag` sẽ tạo lại 2 collection. CVE từ RAG chỉ là tham khảo; khớp
phiên bản/CPE **không** đồng nghĩa máy đã bị lỗ hổng (finding ghi rõ độ tin cậy).

## Chạy

```bash
python manage.py runserver          # mở http://127.0.0.1:8000/
# hoặc một lệnh khởi động tất cả (venv + Ollama + lab + migrate + server):
bash scripts/run_all.sh
```

### Trang chủ có 3 tab

1. **Quản lý dự án** — tạo dự án, import `nmap_sample.xml`, bấm *Đánh giá rủi ro
   bằng AI* (Ollama + RAG) rồi hỏi–đáp phòng thủ theo từng máy.
2. **Kiểm thử chức năng**
   - **Chế độ B — Agent tự động (khuyến nghị)**: nhập URL + mục tiêu tiếng Việt →
     agent tự `inspect_page → fill/click/get_text`, **tự kiểm chứng trên trang** để
     kết luận PASS/FAIL; mỗi bước có ảnh. Hợp luồng đăng nhập/điền form.
   - **Chế độ A — Kịch bản tĩnh**: chỉ `navigate + check_title` (không đăng nhập).
   - Mọi lần chạy lưu vào CSDL (xem `/admin/`).
3. **Trinh sát & bảo mật**
   - **Thụ động (chỉ đọc)**: header bảo mật, cookie flags, TLS, robots.txt + khuyến
     nghị từ RAG.
   - **Chủ động trong lab**: phát hiện reflected XSS / SQLi error-based trên tham số
     GET. **Chỉ chạy với host nội bộ** (localhost/IP private), payload benign, có ô
     xác nhận được phép. Mục tiêu công khai bị từ chối.

## Lab (DVWA + OWASP Juice Shop)

Yêu cầu Docker Engine + Compose v2:

```bash
docker compose -f docker-compose.lab.yml up -d
```

| Site | URL |
| --- | --- |
| DVWA | http://127.0.0.1:4280/ (lần đầu: `/setup.php` → Create/Reset Database, `admin`/`password`) |
| Juice Shop | http://127.0.0.1:3000/ |

Quét chủ động nên nhắm Juice Shop (`/rest/products/search?q=`) vì không cần đăng nhập.

## Browser MCP (7 tool)

`browser_tools` là MCP server độc lập, phiên Chromium riêng mỗi run, giới hạn scope
theo host/CIDR, che password, theo dõi redirect an toàn. 7 tool: `navigate`,
`inspect_page`, `click`, `fill`, `get_text`, `get_current_url`, `screenshot`.

```bash
python -m browser_tools.server --run-id run-01 --allowed-hosts 127.0.0.1 localhost
# kiểm tra bằng MCP Inspector:
npx @modelcontextprotocol/inspector@2.9.0 --config mcp-inspector.json
```

## Benchmark & Báo cáo

```bash
python scripts/benchmark_lab.py            # chức năng + bảo mật thụ động + chủ động -> media/benchmarks/*.json
python scripts/benchmark_lab.py --only active
python scripts/make_report.py --pdf        # gộp DB + benchmark -> media/reports/*.html (+ .pdf)
```

## Kiểm thử

```bash
python manage.py check
python manage.py test analyzer             # test Django + đào sâu (range CVE, grounded, agent, active scan)
python -m unittest tests.test_browser_tools -v   # test 7 tool MCP (cần Chromium + loopback)
```

Phân tích bảo mật chỉ mô tả rủi ro, bằng chứng, CVE và khuyến nghị phòng thủ; quét
chủ động chỉ phát hiện dấu hiệu trong lab được phép, không khai thác.
