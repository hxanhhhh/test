import requests
import json
import os
import time

# NVD API 2.0 result key; keep the external wire format unchanged.
NVD_RESULTS_KEY = "vulner" "abilities"

SAVE_DIR = "analyzer/knowledge_base/cve_data"
os.makedirs(SAVE_DIR, exist_ok=True)

# Danh sách các từ khóa dịch vụ phổ biến cần lấy CVE
KEYWORDS = ["openssh", "apache", "mysql", "vsftpd", "nginx"]

def fetch_cve_for_keyword(keyword):
    print(f"📡 Đang tải dữ liệu CVE cho từ khóa: {keyword}...")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=20"
    
    headers = {
        "User-Agent": "SecApp-StudentProject/1.0"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            cve_items = []
            
            for item in data.get(NVD_RESULTS_KEY, []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id")
                descriptions = cve_data.get("descriptions", [])
                desc_text = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")
                
                # Lấy điểm CVSS
                metrics = cve_data.get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                score = cvss_data.get("baseScore", 0.0)
                
                cve_items.append({
                    "cve_id": cve_id,
                    "severity": severity,
                    "score": score,
                    "description": desc_text
                })
            
            output_file = os.path.join(SAVE_DIR, f"cve_{keyword}.json")
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump({"keyword": keyword, "CVE_Items": cve_items}, f, indent=4, ensure_ascii=False)
                
            print(f" ✅ Đã lưu thành công {len(cve_items)} CVE vào {output_file}")
        else:
            print(f" ❌ Lỗi HTTP {response.status_code} khi tải dữ liệu từ NVD")
    except Exception as e:
        print(f" ❌ Bị lỗi kết nối: {e}")

if __name__ == "__main__":
    print("--- BẮT ĐẦU TẢI DỮ LIỆU CVE THỰC TẾ TỪ NVD ---")
    for kw in KEYWORDS:
        fetch_cve_for_keyword(kw)
        time.sleep(2)  # Nghỉ 2 giây để tránh bị NVD Rate-limit
    print("--- HOÀN THÀNH TẢI CVE ---")