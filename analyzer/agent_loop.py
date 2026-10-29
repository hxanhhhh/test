import json
import requests
from analyzer.browser_mcp import BrowserMCPTools

class TestingAgent:
    def __init__(self, ollama_model="qwen2.5-coder:3b"):
        self.ollama_model = ollama_model
        self.ollama_url = "http://localhost:11434/api/generate"
        self.browser_tools = BrowserMCPTools(headless=False) # Hiện trình duyệt để quan sát

    def ask_ollama(self, prompt: str) -> str:
        """Gửi prompt tới Ollama để nhận phản hồi phân tích từ AI."""
        payload = {
            "model": self.ollama_model,
            "prompt": prompt,
            "stream": False
        }
        try:
            response = requests.post(self.ollama_url, json=payload, timeout=60)
            if response.status_code == 200:
                return response.json().get("response", "")
            else:
                return f"❌ Lỗi kết nối Ollama: {response.status_code}"
        except Exception as e:
            return f"❌ Không thể kết nối tới Ollama: {str(e)}"

    def run_test_flow(self, target_url: str, test_requirement: str):
        """Thực thi chuỗi kiểm thử tự động cơ bản qua Agent."""
        print(f"🚀 [Agent] Bắt đầu kiểm thử URL: {target_url}")
        print(f"🎯 [Agent] Yêu cầu kiểm thử: {test_requirement}")

        # Bước 1: Điều hướng tới trang web
        nav_result = self.browser_tools.navigate(target_url)
        print(nav_result)

        # Bước 2: Chụp ảnh màn hình trạng thái ban đầu
        shot_result = self.browser_tools.screenshot("initial_state.png")
        print(shot_result)

        # Bước 3: Dùng Ollama phân tích trang và đưa ra đánh giá sơ bộ
        prompt = f"""
        Bạn là một AI Testing Agent chuyên nghiệp. 
        Tôi vừa truy cập vào website: {target_url}
        Yêu cầu kiểm thử từ người dùng là: "{test_requirement}"
        
        Hãy viết một báo cáo ngắn gọn đánh giá trạng thái ban đầu của trang web này và gợi ý bước kiểm thử tiếp theo.
        """
        
        print("🤖 [AI Analyzer] Đang phân tích kết quả...")
        ai_analysis = self.ask_ollama(prompt)
        print("\n--- KẾT QUẢ PHÂN TÍCH TỪ AI ---")
        print(ai_analysis)
        print("--------------------------------\n")

        # Đóng trình duyệt sau khi hoàn tất
        self.browser_tools.close_browser()
        print("🏁 [Agent] Hoàn thành phiên kiểm thử!")
