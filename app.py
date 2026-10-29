import streamlit as st
import os
import json
from master_agent import MasterSecurityAgent

# Cấu hình giao diện trang web
st.set_page_config(
    page_title="AI Agent Web Security & Functional Testing",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Hệ thống Tự động hóa Kiểm thử Chức năng & Bảo mật")
st.markdown("Đồ án tốt nghiệp - Ngành An toàn thông tin | **PTIT**")
st.markdown("---")

# Sidebar cấu hình đầu vào
st.sidebar.header("⚙️ Cấu hình Mục tiêu")
target_url = st.sidebar.text_input("Nhập URL Mục tiêu:", "https://example.com")
user_requirement = st.sidebar.text_area(
    "Mô tả yêu cầu kiểm thử chức năng:", 
    "Kiểm tra truy cập trang web mẫu và xác thực tiêu đề trang Example Domain"
)

run_button = st.sidebar.button("🚀 Chạy Kiểm Thử Toàn Diện", type="primary")

# Khu vực hiển thị chính
if run_button:
    if not target_url:
        st.error("Vui lòng nhập URL hợp lệ!")
    else:
        agent = MasterSecurityAgent()
        
        with st.spinner("🤖 Master Agent đang thực thi toàn bộ quy trình (M1 -> M7)... Vui lòng đợi trong giây lát!"):
            # Tạo các tab kết quả
            tab_report, tab_func, tab_sec, tab_evidence = st.tabs([
                "📋 Báo cáo AI", 
                "⚙️ Kiểm thử Chức năng (M5)", 
                "🔍 Trinh sát & RAG (M6-M7)", 
                "📸 Bằng chứng (Evidence)"
            ])
            
            # Thực thi logic quét (chạy ngầm để lấy kết quả hiển thị lên UI)
            from analyzer.security_mcp import SecurityMCPTools
            from analyzer.cve_rag import CVERAGDatabase
            from analyzer.functional_engine import FunctionalTestEngine
            
            rag_db = CVERAGDatabase()
            func_engine = FunctionalTestEngine()
            
            # 1. Chạy Functional Test
            test_cases = func_engine.generate_test_cases(user_requirement)
            func_results = func_engine.execute_functional_test(test_cases, target_url)
            
            # 2. Chạy Security Scan
            sec_tools = SecurityMCPTools(target_url)
            headers_report = sec_tools.check_security_headers()
            robots_report = sec_tools.check_robots_txt()
            
            missing_headers = []
            if headers_report.get("success"):
                for h, info in headers_report["headers_analysis"].items():
                    if info['status'] == "Missing":
                        missing_headers.append(h)
            
            # 3. RAG Query
            rag_results = rag_db.query_vulnerability(f"website thiếu các header bảo mật: {', '.join(missing_headers)}", n_results=2)
            retrieved_fixes = []
            if rag_results and "documents" in rag_results and rag_results["documents"]:
                for doc, meta in zip(rag_results["documents"][0], rag_results["metadatas"][0]):
                    retrieved_fixes.append(f"- [{meta['cve']}] Mức độ: {meta['severity']} | Khắc phục: {meta['fix']}")
            rag_context = "\n".join(retrieved_fixes)
            
            # 4. Tổng hợp báo cáo AI
            prompt = f"""
            Bạn là Chuyên gia Kiểm thử Hệ thống Web. Hãy lập một báo cáo tổng hợp chi tiết dựa trên:
            1. Kết quả kiểm thử chức năng: {json.dumps(func_results, ensure_ascii=False)}
            2. Kết quả kiểm thử bảo mật (Header thiếu): {missing_headers}
            3. Khuyến nghị lỗ hổng từ RAG: {rag_context}
            
            Hãy viết báo cáo chuyên nghiệp gồm tổng quan, đánh giá rủi ro và đề xuất khắc phục cụ thể.
            """
            final_report = agent.ask_ollama(prompt)

            # --- Hiển thị lên các Tab ---
            with tab_report:
                st.subheader("📋 Báo cáo Tổng hợp từ AI Agent")
                st.markdown(final_report)

            with tab_func:
                st.subheader("⚙️ Chi tiết Kết quả Kiểm thử Chức năng (Functional Execution)")
                for res in func_results:
                    status_color = "green" if res['status'] == "PASS" else "red"
                    st.markdown(f"**Bước {res['step_id']}**: `{res['action']}` — Trạng thái: :{status_color}[**{res['status']}**]")
                    st.text(f"Chi tiết: {res['detail']}")
                    st.markdown("---")

            with tab_sec:
                st.subheader("🔍 Kết quả Trinh sát Bảo mật & RAG")
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("#### Trạng thái HTTP Headers:")
                    if headers_report.get("success"):
                        for h, info in headers_report["headers_analysis"].items():
                            color = "orange" if info['status'] == "Missing" else "green"
                            st.markdown(f"- **{h}**: :{color}[{info['status']}]")
                with col2:
                    st.markdown("#### Trạng thái Robots.txt:")
                    st.info(robots_report)
                
                st.markdown("#### 🧠 Khuyến nghị Lỗ hổng từ ChromaDB (RAG):")
                st.code(rag_context if rag_context else "Không phát hiện lỗ hổng trọng yếu.")

            with tab_evidence:
                st.subheader("📸 Hình ảnh Bằng chứng (Evidence Screenshots)")
                evidence_dir = "media/evidence"
                if os.path.exists(evidence_dir):
                    images = [os.path.join(evidence_dir, img) for img in os.listdir(evidence_dir) if img.endswith(".png")]
                    if images:
                        for img_path in sorted(images, reverse=True):
                            st.image(img_path, caption=os.path.basename(img_path), use_container_width=True)
                    else:
                        st.warning("Chưa có ảnh bằng chứng nào được ghi nhận.")
                else:
                    st.warning("Thư mục evidence chưa được tạo.")
        
        st.success("🎉 Hoàn thành quy trình kiểm thử và hiển thị Dashboard thành công!")
else:
    st.info("👈 Hãy nhập thông tin mục tiêu ở thanh bên trái (Sidebar) và bấm nút **'🚀 Chạy Kiểm Thử Toàn Diện'** để bắt đầu!")
