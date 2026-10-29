from playwright.sync_api import sync_playwright
import os

class BrowserMCPTools:
    def __init__(self, headless=True):
        self.headless = headless
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(headless=self.headless)
        self.page = self.browser.new_page()

    def navigate(self, url: str):
        try:
            self.page.goto(url, timeout=30000)
            return f"Đã truy cập thành công {url}"
        except Exception as e:
            return f"Lỗi truy cập {url}: {str(e)}"

    def screenshot(self, filename="evidence.png"):
        os.makedirs("media/evidence", exist_ok=True)
        path = os.path.join("media/evidence", filename)
        self.page.screenshot(path=path)
        return path

    def close_browser(self):
        self.browser.close()
        self.playwright.stop()
