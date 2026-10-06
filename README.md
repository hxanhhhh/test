# Web Sec Test

Hệ thống Django kiểm thử web theo mô hình AI Agent + MCP. Phạm vi hiện tại là cấu trúc dữ liệu Functional Web Testing và nhập, đánh giá rủi ro từ kết quả Nmap bằng Ollama + ChromaDB. Chưa triển khai thực thi kiểm thử chức năng tự động. Phân tích bảo mật chỉ mô tả rủi ro, bằng chứng, CVE và khuyến nghị phòng thủ.

## Dựng môi trường

Chạy các lệnh từ thư mục chứa `manage.py`, dùng Python 3.12:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py showmigrations analyzer
```

Các migration cần có dấu `[X]`. SQLite lưu tại `db.sqlite3`, kho vector tại `chroma_data/`; hai thư mục dữ liệu độc lập.

## Ollama

Cài theo [hướng dẫn Linux](https://docs.ollama.com/linux) hoặc [bản tải cho hệ điều hành](https://ollama.com/download). Nếu dịch vụ chưa chạy, mở terminal riêng:

```bash
ollama serve
```

Trong terminal khác:

```bash
ollama pull qwen2.5-coder:3b
ollama list
```

Kiểm tra API:

```bash
curl --fail http://localhost:11434/api/generate \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen2.5-coder:3b","prompt":"Say hello briefly.","stream":false}'
```

Dịch vụ cần tiếp tục chạy trong khi sử dụng phân tích/chat. Xem [Ollama Quickstart](https://docs.ollama.com/quickstart).

## Nạp ChromaDB

```bash
python -m analyzer.rebuild_rag
```

Script tạo lại `collection_cve` và `collection_service_guide` từ `analyzer/knowledge_base/`. Việc chạy lại xóa dữ liệu cũ trong hai collection này. Lần đầu có thể cần Internet để tải embedding; không cần server Chroma riêng.

Cập nhật nguồn CVE từ NVD là bước tùy chọn:

```bash
python -m analyzer.fetch_nvd_cve
python -m analyzer.rebuild_rag
```

Script tải tối đa 20 kết quả mỗi từ khóa. CVE từ truy vấn vector chỉ là thông tin tham khảo; khớp phiên bản không xác nhận máy có lỗ hổng.

## Chạy và kiểm tra

```bash
python manage.py check
python manage.py runserver
```

Mở <http://127.0.0.1:8000/>. File `nmap_sample.xml` chứa localhost với SSH cổng 22 và CUPS cổng 631.

```bash
python manage.py makemigrations --check --dry-run
python manage.py test
```

Migration đã được tạo lại theo model BA, dành cho DB mới. Model gồm `TestProject`, `FunctionalTestCase`, `FunctionalTestRun`, `TestStepResult`, `SecurityScan`, `TargetAsset`, `Service` và `SecurityFinding`.
