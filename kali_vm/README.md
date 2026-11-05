# kali_vm — server chạy TRÊN máy ảo Kali

Django (`web_sec_test`) chạy trên máy chính và gửi lệnh pentest qua HTTP tới
máy Kali. Phần chạy tool thật nằm ở đây, phải đặt **trên VM Kali**.

## Cài đặt trên VM Kali
1. Chép file `server.py` sang VM Kali (scp / thư mục chia sẻ / USB). Chỉ cần 1 file này.
2. Cài Flask:
   ```bash
   pip install flask          # hoặc: sudo apt install python3-flask
   ```
3. Chạy server, mở ra mạng để máy chính gọi được:
   ```bash
   python3 server.py --ip 0.0.0.0 --port 5000
   ```
4. Lấy IP của VM:
   ```bash
   ip -4 addr show | grep inet
   ```

## Trỏ Django sang Kali (trên máy chính)
```bash
cd ~/web_sec_test && source .venv/bin/activate
export KALI_URL=http://<IP-VM-Kali>:5000
python manage.py kali_health            # kỳ vọng: [OK] /health
```

## Ghi chú
- Không cần cài `web_sec_test` hay `analyzer/kali/` trên Kali — chúng ở máy chính.
- Server này tương đương `/api/command` của MCP-Kali-Server nhưng chỉ 1 file,
  không phụ thuộc `server_tools/`.
- `/api/command` chạy lệnh shell tùy ý → **chỉ dùng trên VM lab nội bộ**.
  Giới hạn mục tiêu (chỉ host lab) do phía Django kiểm (`guard()`).
- Tool nào Kali chưa có thì `/health` sẽ báo `false` — cài thêm bằng `apt install`.
