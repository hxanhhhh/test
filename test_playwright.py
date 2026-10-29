from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    # Mở trình duyệt Chromium (để headless=False để bạn nhìn thấy cửa sổ trình duyệt bật lên)
    browser = p.chromium.launch(headless=False)
    page = browser.new_page()

    # Truy cập thử vào Google
    page.goto("https://google.com")
    print("✅ Đã truy cập thành công! Tiêu đề trang là:", page.title())

    # Chụp ảnh màn hình kiểm thử
    page.screenshot(path="test_evidence.png")
    print("📸 Đã chụp ảnh màn hình và lưu file thành công: test_evidence.png")

    # Đóng trình duyệt
    browser.close()
