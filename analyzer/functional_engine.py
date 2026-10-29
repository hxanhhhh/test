import json
import requests
from analyzer.browser_mcp import BrowserMCPTools

class FunctionalTestEngine:
    def __init__(self, ollama_model="qwen2.5-coder:3b"):
        self.ollama_model = ollama_model
        self.ollama_url = "http://localhost:11434/api/generate"

    def generate_test_cases(self, user_requirement: str) -> list:
        """M2 - AI Test Generation: Tự động sinh kịch bản test từ yêu cầu tự nhiên."""
        prompt = f"""
        Bạn là một chuyên gia kiểm thử phần mềm (QA Engineer). Dựa trên yêu cầu kiểm thử: '{user_requirement}', hãy tạo ra danh sách các bước kiểm thử (test steps) dưới dạng mảng JSON thuần túy (chỉ trả về JSON, không kèm giải thích hay markdown rườm rà).
        Mỗi phần tử JSON gồm các trường: 
        - "step_id": số thứ tự (int)
        - "action": hành động (chọn một trong các giá trị: "navigate", "check_title")
        - "value": giá trị tham số (ví dụ URL hoặc tiêu đề kỳ vọng)
        - "expected": mô tả kết quả kỳ vọng

        Ví dụ định dạng:
        [
          {{"step_id": 1, "action": "navigate", "value": "https://example.com", "expected": "Truy cập trang thành công"}},
          {{"step_id": 2, "action": "check_title", "value": "Example Domain", "expected": "Tiêu đề trang khớp với yêu cầu"}}
        ]
        """
        payload = {
            "model": self.ollama_model,
            "prompt": prompt,
            "stream": False
        }
        try:
            response = requests.post(self.ollama_url, json=payload, timeout=40)
            if response.status_code == 200:
                text_response = response.json().get("response", "[]")
                # Làm sạch chuỗi JSON nếu có định dạng markdown block
                if "```json" in text_response:
                    text_response = text_response.split("```json")[1].split("```")[0].strip()
                elif "```" in text_response:
                    text_response = text_response.split("```")[1].split("```")[0].strip()
                return json.loads(text_response)
            else:
                print(f"❌ Lỗi gọi Ollama sinh test case: {response.status_code}")
                return []
        except Exception as e:
            print(f"❌ Lỗi phân tích test case: {str(e)}")
            return []

    def execute_functional_test(self, test_cases: list, target_url: str) -> list:
        """M5 - Functional Execution: Thực thi test case trên trình duyệt, lưu evidence và chấm PASS/FAIL."""
        browser = BrowserMCPTools(headless=True)
        results = []

        print(f"\n⚙️ [Functional Engine] Bắt đầu thực thi {len(test_cases)} bước kiểm thử...")
        for tc in test_cases:
            step_id = tc.get("step_id")
            action = tc.get("action")
            value = tc.get("value", target_url)
            expected = tc.get("expected")
            
            status = "FAIL"
            evidence_path = ""
            detail = ""

            try:
                if action == "navigate":
                    nav_res = browser.navigate(value)
                    if "thành công" in nav_res:
                        status = "PASS"
                        detail = nav_res
                    else:
                        detail = "Không thể điều hướng đến URL"
                    evidence_path = browser.screenshot(f"func_step_{step_id}.png")
                
                elif action == "check_title":
                    current_title = browser.page.title()
                    if value.lower() in current_title.lower():
                        status = "PASS"
                        detail = f"Tiêu đề thực tế khớp: '{current_title}'"
                    else:
                        detail = f"Tiêu đề không khớp (Thực tế: '{current_title}', Kỳ vọng: '{value}')"
                    evidence_path = browser.screenshot(f"func_step_{step_id}.png")
                
            except Exception as e:
                status = "FAIL"
                detail = f"Lỗi ngoại lệ: {str(e)}"
                evidence_path = browser.screenshot(f"func_step_{step_id}_error.png")

            results.append({
                "step_id": step_id,
                "action": action,
                "expected": expected,
                "status": status,
                "detail": detail,
                "evidence": evidence_path
            })

        browser.close_browser()
        return results
