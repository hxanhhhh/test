import shlex

from analyzer.kali.base import make_adder


def register(reg, client):
    add = make_adder(reg, client, "web_crawling_content")
    # --- crawler ---
    add("katana", "Katana – crawler", "Thu thập URL/endpoint của website.",
        lambda u: f"katana -u {shlex.quote(u)} -silent", param="url", timeout=180)
    add("hakrawler", "hakrawler – crawler nhanh", "Thu thập link trong trang.",
        lambda u: f"echo {shlex.quote(u)} | hakrawler", param="url", timeout=120)
    add("photon", "Photon – crawler OSINT", "Crawl và trích URL, email, tham số, file.",
        lambda u: f"photon -u {shlex.quote(u)} -l 2 -t 20", param="url", timeout=180)
    # --- URL lịch sử ---
    add("gau", "gau – URL lịch sử", "Lấy URL đã biết từ nguồn mở.",
        lambda h: f"gau {shlex.quote(h)}", timeout=120)
    add("waybackurls", "waybackurls – URL Wayback", "Lấy URL lịch sử từ Wayback Machine.",
        lambda h: f"waybackurls {shlex.quote(h)}", timeout=120)
    # --- tham số / JS ---
    add("paramspider", "ParamSpider – dò tham số", "Tìm tham số URL có thể kiểm thử.",
        lambda h: f"paramspider -d {shlex.quote(h)}", timeout=120)
    add("arjun", "Arjun – dò tham số ẩn", "Phát hiện tham số HTTP ẩn của endpoint.",
        lambda u: f"arjun -u {shlex.quote(u)}", param="url", timeout=180)
    add("linkfinder", "LinkFinder – trích endpoint trong JS",
        "Tìm endpoint/đường dẫn ẩn trong file JavaScript.",
        lambda u: f"linkfinder -i {shlex.quote(u)} -o cli", param="url", timeout=120)
    add("getjs", "getJS – liệt kê file JS", "Thu thập toàn bộ file JavaScript của trang.",
        lambda u: f"getJS --url {shlex.quote(u)}", param="url", timeout=120)
