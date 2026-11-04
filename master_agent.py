import sys
import json
from analyzer.browser_mcp import BrowserMCPTools
from analyzer.security_mcp import SecurityMCPTools
from analyzer.cve_rag import CVERAGDatabase
from analyzer.functional_engine import FunctionalTestEngine
import requests

class MasterSecurityAgent:
    def __init__(self, ollama_model="qwen2.5-coder:3b"):
        self.ollama_model = ollama_model
        self.ollama_url = "http://localhost:11434/api/generate"
        self.rag_db = CVERAGDatabase()
        self.func_engine = FunctionalTestEngine(ollama_model)

    def ask_ollama(self, prompt: str) -> str:
        payload = {"model": self.ollama_model, "prompt": prompt, "stream": False}
        try:
            response = requests.post(self.ollama_url, json=payload, timeout=60)
            if response.status_code == 200:
                return response.json().get("response", "")
            return f"❌ Lỗi Ollama: {response.status_code}"
        except Exception as e:
            return f"❌ Không thể kết nối Ollama: {str(e)}"

    def run_full_assessment(self, target_url: str, user_requirement: str):
        print(f"\n🚀 [Master Agent] Bắt đầu quy trình kiểm thử tự động toàn diện cho: {target_url}\n")

        # --- M2: AI TEST GENERATION ---
        print("🤖 [Phase 1 - M2] AI đang phân tích yêu cầu và sinh kịch bản kiểm thử chức năng...")
        test_cases = self.func_engine.generate_test_cases(user_requirement)
        print(f"📋 Danh sách Test Cases được sinh tự động:")
        for tc in test_cases:
            print(f"   - Bước {tc.get('step_id')}: [{tc.get('action')}] -> Kỳ vọng: {tc.get('expected')}")

        # --- M5: FUNCTIONAL EXECUTION ---
        print("\n⚙️ [Phase 2 - M5] Thực thi kịch bản chức năng trên trình duyệt & chấm điểm PASS/FAIL...")
        func_results = self.func_engine.execute_functional_test(test_cases, target_url)
        for res in func_results:
            icon = "✅" if res['status'] == "PASS" else "❌"
            print(f"   {icon} [Bước {res['step_id']}] {res['action']} -> Trạng thái: {res['status']} ({res['detail']}) | Ảnh: {res['evidence']}")

        # --- M6 & M7: SECURITY MCP & ANALYSIS (RAG) ---
        print("\n🔍 [Phase 3 - M6 & M7] Trinh sát bảo mật & đối chiếu CVE qua ChromaDB RAG...")
        sec_tools = SecurityMCPTools(target_url)
        headers_report = sec_tools.check_security_headers()
        robots_report = sec_tools.check_robots_txt()

        missing_headers = []
        if headers_report.get("success"):
            for h, info in headers_report["headers_analysis"].items():
                if info['status'] == "Missing":
                    missing_headers.append(h)

        rag_results = self.rag_db.query_vulnerability(f"website thiếu các header bảo mật: {', '.join(missing_headers)}", n_results=2)
        retrieved_fixes = []
        if rag_results and "documents" in rag_results and rag_results["documents"]:
            for doc, meta in zip(rag_results["documents"][0], rag_results["metadatas"][0]):
                retrieved_fixes.append(f"- [{meta['cve']}] Mức độ: {meta['severity']} | Khắc phục: {meta['fix']}")
        rag_context = "\n".join(retrieved_fixes)

        # --- M8: BÁO CÁO TỔNG HỢP TỪ AI ---
        print("\n📝 [Phase 4 - M8] Đang tổng hợp báo cáo kết hợp chức năng và bảo mật...")
        prompt = f"""
        Bạn là Chuyên gia Kiểm thử Hệ thống Web. Hãy lập một báo cáo tổng hợp chi tiết dựa trên:
        1. Kết quả kiểm thử chức năng (Functional Execution): {json.dumps(func_results, ensure_ascii=False)}
        2. Kết quả kiểm thử bảo mật (Security Headers thiếu): {missing_headers}
        3. Khuyến nghị lỗ hổng từ RAG: {rag_context}

        Hãy viết báo cáo chuyên nghiệp gồm:
        - Tổng quan kết quả Kiểm thử Chức năng (PASS/FAIL từng bước).
        - Đánh giá trạng thái An toàn Bảo mật.
        - Đề xuất khắc phục cụ thể cho nhà phát triển.
        """
        final_report = self.ask_ollama(prompt)

        print("\n" + "="*60)
        print("📋 BÁO CÁO KIỂM THỬ TỰ ĐỘNG TOÀN DIỆN (FUNCTIONAL & SECURITY)")
        print("="*60)
        print(final_report)
        print("="*60)
        print("🏁 [Master Agent] Hoàn thành toàn bộ quy trình từ M1 đến M7 thành công xuất sắc!\n")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    req = sys.argv[2] if len(sys.argv) > 2 else "Kiểm tra truy cập trang web mẫu và xác thực tiêu đề trang Example Domain"
    agent = MasterSecurityAgent()
    agent.run_full_assessment(target, req)
