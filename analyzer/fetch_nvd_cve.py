"""Tải CVE thật từ NVD API 2.0 về kho tri thức cho RAG.

So với bản cũ, bản này trích thêm **product / version / cpe** từ phần
``configurations`` và có **fallback CVSS** (v3.1 -> v3.0 -> v2). Nhờ đó
``analyzer.analysis.matching_cves`` mới có thể đối chiếu phiên bản/CPE và nâng
độ tin cậy finding lên VERSION_INFERRED thay vì chỉ LLM_SUGGESTED.

Chạy trên máy có mạng (sandbox chặn NVD):
    python -m analyzer.fetch_nvd_cve
    python -m analyzer.rebuild_rag
Có thể đặt biến môi trường NVD_API_KEY để nâng rate-limit.
"""
import json
import os
import time

import requests

# NVD API 2.0 result key; keep the external wire format unchanged.
NVD_RESULTS_KEY = "vulner" "abilities"

SAVE_DIR = "analyzer/knowledge_base/cve_data"
os.makedirs(SAVE_DIR, exist_ok=True)

KEYWORDS = ["openssh", "apache", "mysql", "vsftpd", "nginx"]


def extract_severity(cve_data):
    """CVSS v3.1 -> v3.0 -> v2, trả (severity, score)."""
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if arr:
            data = arr[0].get("cvssData", {})
            return data.get("baseSeverity", "UNKNOWN"), data.get("baseScore", 0.0)
    arr = metrics.get("cvssMetricV2") or []
    if arr:
        return arr[0].get("baseSeverity", "UNKNOWN"), arr[0].get("cvssData", {}).get("baseScore", 0.0)
    return "UNKNOWN", 0.0


def extract_cpe(cve_data):
    """Lấy CPE/product/version + KHOẢNG phiên bản bị ảnh hưởng (nếu có)."""
    for cfg in cve_data.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria")
                if match.get("vulnerable") and criteria:
                    parts = criteria.split(":")
                    product = parts[4] if len(parts) > 4 else ""
                    version = parts[5] if len(parts) > 5 else ""
                    if version in ("*", "-"):
                        version = ""
                    info = {"cpe": criteria, "product": product, "version": version}
                    # Khoảng phiên bản: NVD dùng versionStart/End Including/Excluding.
                    if match.get("versionStartIncluding"):
                        info["version_start"] = match["versionStartIncluding"]
                        info["version_start_op"] = "ge"
                    elif match.get("versionStartExcluding"):
                        info["version_start"] = match["versionStartExcluding"]
                        info["version_start_op"] = "gt"
                    if match.get("versionEndIncluding"):
                        info["version_end"] = match["versionEndIncluding"]
                        info["version_end_op"] = "le"
                    elif match.get("versionEndExcluding"):
                        info["version_end"] = match["versionEndExcluding"]
                        info["version_end_op"] = "lt"
                    return info
    return {}


def parse_cve_item(item):
    """Chuyển 1 phần tử NVD thô -> bản ghi gọn cho RAG."""
    cve_data = item.get("cve", {})
    descriptions = cve_data.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description")
    severity, score = extract_severity(cve_data)
    record = {
        "cve_id": cve_data.get("id"),
        "severity": severity,
        "score": score,
        "description": desc,
    }
    info = extract_cpe(cve_data)
    for key in ("product", "version", "cpe", "version_start", "version_start_op",
                "version_end", "version_end_op"):
        if info.get(key):
            record[key] = info[key]
    return record


def fetch_cve_for_keyword(keyword):
    print(f"📡 Đang tải dữ liệu CVE cho từ khóa: {keyword}...")
    url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?keywordSearch={keyword}&resultsPerPage=20")
    headers = {"User-Agent": "SecApp-StudentProject/1.0"}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            cve_items = [parse_cve_item(item) for item in data.get(NVD_RESULTS_KEY, [])]
            output_file = os.path.join(SAVE_DIR, f"cve_{keyword}.json")
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump({"keyword": keyword, "CVE_Items": cve_items}, f,
                          indent=4, ensure_ascii=False)
            with_cpe = sum(1 for c in cve_items if c.get("cpe"))
            print(f" ✅ Đã lưu {len(cve_items)} CVE ({with_cpe} có CPE) vào {output_file}")
        else:
            print(f" ❌ Lỗi HTTP {response.status_code} khi tải dữ liệu từ NVD")
    except Exception as e:
        print(f" ❌ Bị lỗi kết nối: {e}")


if __name__ == "__main__":
    print("--- BẮT ĐẦU TẢI DỮ LIỆU CVE THỰC TẾ TỪ NVD ---")
    for kw in KEYWORDS:
        fetch_cve_for_keyword(kw)
        time.sleep(2)  # tránh NVD rate-limit (nghỉ ít hơn nếu có NVD_API_KEY)
    print("--- HOÀN THÀNH TẢI CVE ---")
