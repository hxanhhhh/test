import os
from playwright.sync_api import sync_playwright

class BrowserMCPTools:
    def __init__(self, headless=True):
        self.headless = headless
        self.playwright = None
        self.browser = None
        self.page = None

    def start_browser(self):
        if not self.playwright:
            self.playwright = sync_playwright().start()
            self.browser = self.playwright.chromium.launch(headless=self.headless)
            self.page = self.browser.new_page()

    def close_browser(self):
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()
        self.playwright = None
        self.browser = None
        self.page = None

    def navigate(self, url: str) -> str:
        """Điều hướng trình duyệt đến một URL chỉ định."""
        try:
            self.start_browser()
            self.page.goto(url)
            return f"✅ Đã truy cập thành công tới: {url} | Tiêu đề: {self.page.title()}"
        except Exception as e:
            return f"❌ Lỗi khi navigate: {str(e)}"

    def click(self, selector: str) -> str:
        """Click vào một phần tử trên trang dựa vào CSS selector."""
        try:
            self.page.click(selector)
            return f"✅ Đã click thành công vào phần tử: {selector}"
        except Exception as e:
            return f"❌ Lỗi khi click phần tử {selector}: {str(e)}"

    def fill(self, selector: str, text: str) -> str:
        """Điền văn bản vào trường input dựa vào CSS selector."""
        try:
            self.page.fill(selector, text)
            return f"✅ Đã điền text vào {selector}"
        except Exception as e:
            return f"❌ Lỗi khi điền text vào {selector}: {str(e)}"

    def screenshot(self, filename: str = "evidence.png") -> str:
        """Chụp ảnh màn hình trang web hiện tại để làm bằng chứng."""
        try:
            evidence_path = os.path.join("media", "evidence")
            os.makedirs(evidence_path, exist_ok=True)
            full_path = os.path.join(evidence_path, filename)
            
            self.page.screenshot(path=full_path)
            return f"📸 Đã chụp ảnh màn hình lưu tại: {full_path}"
        except Exception as e:
            return f"❌ Lỗi khi chụp ảnh: {str(e)}"

    def get_text(self, selector: str) -> str:
        """Lấy nội dung text của một phần tử trên trang."""
        try:
            content = self.page.inner_text(selector)
            return f"📄 Nội dung tại {selector}: {content}"
        except Exception as e:
            return f"❌ Lỗi khi lấy text từ {selector}: {str(e)}"
