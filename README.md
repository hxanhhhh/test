# Web Sec AI

Ứng dụng Django hỗ trợ phân tích kết quả quét Nmap bằng AI chạy cục bộ qua Ollama. Hệ thống lưu các máy mục tiêu và dịch vụ theo dự án, truy xuất tài liệu từ ChromaDB (RAG), rồi gợi ý CVE, chuỗi tấn công và mã kiểm thử PoC.

## Chức năng

- Nhập file Nmap XML, trích xuất IP, hostname, hệ điều hành và các cổng đang mở.
- Quản lý máy mục tiêu và dịch vụ theo từng dự án.
- Phân tích từng máy bằng mô hình `qwen2.5-coder:3b`, kết hợp dữ liệu CVE và PoC trong kho tri thức.
- Hiển thị kết quả phân tích, mã PoC và đồ thị trên dashboard.
- Chat với AI theo ngữ cảnh dịch vụ và CVE của máy đang chọn.

## Công nghệ

| Thành phần | Công nghệ |
| --- | --- |
| Backend | Python, Django |
| Cơ sở dữ liệu ứng dụng | SQLite |
| AI cục bộ | Ollama, `qwen2.5-coder:3b` |
| Kho vector | ChromaDB |
| Giao diện | Django Templates, Bootstrap, vis-network |
| Dữ liệu đầu vào | Nmap XML, dữ liệu CVE từ NVD, tài liệu và PoC |

## Cài đặt và chạy

Các lệnh dưới đây dành cho Linux/macOS và chạy tại thư mục gốc của dự án, nơi chứa `manage.py`. Môi trường phát triển hiện có sử dụng Python 3.12.

### 1. Cài thư viện Python

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### 2. Chuẩn bị Ollama

Cài Ollama và khởi động dịch vụ. Nếu dịch vụ chưa chạy, mở một terminal riêng:

```bash
ollama serve
```

Tải mô hình trong terminal khác:

```bash
ollama pull qwen2.5-coder:3b
```

Ứng dụng mặc định gọi Ollama tại `http://localhost:11434/api/generate`.

### 3. Khởi tạo cơ sở dữ liệu và kho tri thức

```bash
python manage.py migrate
python -m analyzer.rebuild_rag
```

Lệnh `rebuild_rag` đọc dữ liệu trong `analyzer/knowledge_base/` và tạo kho vector tại `chroma_data/`. Lần đầu chạy có thể cần kết nối Internet để ChromaDB tải mô hình embedding mặc định.

**Lưu ý:** mỗi lần chạy `rebuild_rag` sẽ xóa và tạo lại bốn collection: `collection_cve`, `collection_attack_technique`, `collection_exploit_poc` và `collection_service_guide`.

### 4. Chạy ứng dụng

```bash
python manage.py runserver
```

Mở dashboard tại <http://127.0.0.1:8000/>.

## Sử dụng

1. Nhập tên dự án và chọn file `nmap_sample.xml` có sẵn hoặc file Nmap XML của bạn.
2. Nhấn **Import Log Nmap** để lưu máy mục tiêu và các dịch vụ.
3. Chọn một máy trong dự án để xem chi tiết.
4. Nhấn **Chạy AI RAG Phân tích** để phân tích các dịch vụ của máy đó.
5. Xem CVE, chuỗi tấn công, mã PoC hoặc đặt câu hỏi trong khung chat.

Ứng dụng nhận kết quả quét có sẵn; không cần cài Nmap để thử bằng file mẫu. Kết quả AI là gợi ý cần được kiểm chứng; ứng dụng không tự thực thi mã PoC.

## Quản lý dữ liệu RAG

Kho tri thức hiện có:

```text
analyzer/knowledge_base/
├── cve_data/            # File JSON chứa dữ liệu CVE theo dịch vụ
├── service_guides/      # Tài liệu hướng dẫn dạng Markdown hoặc text
└── ssh_pentest.txt      # Tài liệu dùng cho script init_rag riêng
```

Để tải lại dữ liệu CVE theo các từ khóa `openssh`, `apache`, `mysql`, `vsftpd`, `nginx` rồi cập nhật kho vector:

```bash
python -m analyzer.fetch_nvd_cve
python -m analyzer.rebuild_rag
```

Script tải tối đa 20 kết quả cho mỗi từ khóa và ghi đè file JSON tương ứng khi yêu cầu thành công; đây không phải bản sao đầy đủ của NVD.

Có thể bổ sung tài liệu PoC vào `analyzer/knowledge_base/exploits_poc/` trước khi chạy lại `rebuild_rag`. Script đọc tối đa 300 file `.py`, `.md`, `.rb`, `.txt`, lấy tối đa 2.000 ký tự mỗi file.

Luồng phân tích trên dashboard hiện truy vấn `collection_cve` và `collection_exploit_poc`. Collection hướng dẫn dịch vụ đã được nạp nhưng chưa được truy vấn trong luồng này; collection kỹ thuật tấn công mới được tạo, chưa có bước nạp dữ liệu. `init_rag.py` sử dụng collection riêng tên `sec_knowledge`, không thay thế cho `rebuild_rag` khi chạy dashboard.

## Cấu trúc dự án

```text
web_sec_ai/
├── core/                       # Cấu hình Django và URL gốc
├── analyzer/
│   ├── models.py               # Dự án, máy mục tiêu, gợi ý phân tích
│   ├── views.py                # Dashboard, API phân tích và chat
│   ├── urls.py                 # Định tuyến API
│   ├── parse_nmap.py           # Bộ đọc Nmap XML
│   ├── rebuild_rag.py          # Tạo lại và nạp các collection RAG
│   ├── fetch_nvd_cve.py        # Tải dữ liệu CVE từ NVD
│   ├── knowledge_base/        # Nguồn dữ liệu tri thức
│   ├── migrations/            # Migration cơ sở dữ liệu
│   └── templates/dashboard.html
├── manage.py
├── requirements.txt
└── nmap_sample.xml
```

SQLite lưu dữ liệu tại `db.sqlite3`; ChromaDB lưu tại `chroma_data/`. Hai đường dẫn này được bỏ qua bởi Git.

## Cấu hình và xử lý lỗi

- **Đổi mô hình hoặc địa chỉ Ollama:** sửa `MODEL_NAME` và `OLLAMA_URL` trong `analyzer/views.py`.
- **Đổi thư mục ChromaDB:** đồng bộ `CHROMA_PATH` trong `analyzer/views.py` và `analyzer/rebuild_rag.py`. Chạy ứng dụng từ thư mục gốc để đường dẫn tương đối được xử lý đúng.
- **Lỗi kết nối AI hoặc timeout:** kiểm tra dịch vụ Ollama, mô hình đã tải và tài nguyên máy. Các yêu cầu phân tích/chat hiện đặt timeout 60 giây cho mỗi lần gọi Ollama.
- **Thiếu bảng SQLite:** chạy `python manage.py migrate`.
- **Thiếu dữ liệu RAG:** kiểm tra nguồn trong `knowledge_base/`, sau đó chạy lại `python -m analyzer.rebuild_rag`.
- **Giao diện thiếu định dạng hoặc đồ thị:** kiểm tra kết nối đến CDN; Bootstrap và vis-network đang được tải từ Internet.

Cấu hình hiện nằm trực tiếp trong mã nguồn; ứng dụng chưa tự đọc file `.env`. `core/settings.py` đang dùng cấu hình phát triển với `DEBUG = True`.

Có thể kiểm tra cấu hình Django bằng:

```bash
python manage.py check
```
