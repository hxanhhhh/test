import json
import requests
from core_agent.browser_mcp import BrowserMCPTools

class FunctionalTestEngine:
    def __init__(self, ollama_model="qwen2.5-coder:3b"):
        self.ollama_model = ollama_model
        self.ollama_url = "http://localhost:11434/api/generate"

    def generate_test_cases(self, user_requirement: str, target_url: str) -> list:
        prompt = f"""
        Bạn là QA Engineer. Dựa trên Target URL là '{target_url}' và yêu cầu: '{user_requirement}', hãy tạo danh sách test steps dưới dạng mảng JSON thuần túy (chỉ trả về JSON, không markdown).
        Mỗi phần tử gồm: 
        - "step_id" (int)
        - "action" ("navigate" hoặc "check_title")
        - "value" (str - QUAN TRỌNG: nếu action là 'navigate' thì value PHẢI là '{target_url}', nếu action là 'check_title' thì value PHẢI là từ khóa tiêu đề cần kiểm tra, tuyệt đối KHÔNG ĐỂ TRỐNG).
        - "expected" (str)
        """
        payload = {"model": self.ollama_model, "prompt": prompt, "stream": False}
        try:
            response = requests.post(self.ollama_url, json=payload, timeout=30)
            if response.status_code == 200:
                text = response.json().get("response", "[]")
                if "```json" in text:
                    text = text.split("```json")[1].split("```")[0].strip()
                elif "```" in text:
                    text = text.split("```")[1].split("```")[0].strip()
                return json.loads(text)
            return []
        except:
            return []

    def execute_functional_test(self, test_cases: list, target_url: str) -> list:
        browser = BrowserMCPTools(headless=True)
        results = []
        for tc in test_cases:
            step_id = tc.get("step_id")
            action = tc.get("action")
            value = tc.get("value", target_url)
            expected = tc.get("expected")
            status, detail, evidence = "FAIL", "", ""

            try:
                if action == "navigate":
                    res = browser.navigate(value)
                    status = "PASS" if "thành công" in res else "FAIL"
                    detail = res
                    evidence = browser.screenshot(f"func_step_{step_id}.png")
                elif action == "check_title":
                    title = browser.page.title()
                    # Nếu value trống thì gán mặc định target_url hoặc dùng luôn expected để so sánh linh hoạt
                    check_val = value if value else expected
                    if check_val.lower() in title.lower():
                        status = "PASS"
                        detail = f"Tiêu đề khớp: '{title}'"
                    else:
                        detail = f"Tiêu đề lệch (Thực tế: '{title}', Kỳ vọng: '{check_val}')"
                    evidence = browser.screenshot(f"func_step_{step_id}.png")
            except Exception as e:
                status = "FAIL"
                detail = str(e)
                evidence = browser.screenshot(f"func_step_{step_id}_err.png")

            results.append({"step_id": step_id, "action": action, "expected": expected, "status": status, "detail": detail, "evidence": evidence})
        browser.close_browser()
        return results
