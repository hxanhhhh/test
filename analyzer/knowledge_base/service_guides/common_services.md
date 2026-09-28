# HƯỚNG DẪN KIỂM THỬ DỊCH VỤ SSH (PORT 22)
## Kỹ thuật kiểm thử:
- Thực hiện dò quét thuật toán mã hóa yếu.
- Thử nghiệm tấn công từ điển (Brute-force) với hydra/medusa nếu cấu hình cho phép Password Authentication.
- Kiểm tra các lỗ hổng RCE trên các bản OpenSSH cũ (vd: CVE-2018-15473, CVE-2024-6387).

# HƯỚNG DẪN KIỂM THỬ DỊCH VỤ HTTP/HTTPS (PORT 80/443)
## Kỹ thuật kiểm thử:
- Quét dò đường dẫn ẩn bằng ffuf/gobuster.
- Phân tích thông tin Header server (Apache, Nginx, IIS).
- Kiểm tra các lỗ hổng phổ biến: SQLi, XSS, Path Traversal, File Upload.
