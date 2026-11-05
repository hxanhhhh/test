import shlex

from analyzer.kali.base import make_adder

WL = "/usr/share/wordlists/dirb/common.txt"
SUBWL = "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt"


def register(reg, client):
    add = make_adder(reg, client, "dns_web_discovery")
    # --- dò thư mục / đường dẫn ---
    add("ffuf", "ffuf – fuzz đường dẫn", "Fuzz thư mục/tham số bằng wordlist.",
        lambda u: f"ffuf -u {shlex.quote(u.rstrip('/'))}/FUZZ -w {WL} -mc 200,204,301,302,307,401,403 -s",
        param="url", timeout=240)
    add("feroxbuster", "feroxbuster – dò thư mục", "Dò thư mục/đường dẫn (Rust, nhanh).",
        lambda u: f"feroxbuster -u {shlex.quote(u)} -w {WL} -q --no-recursion -k",
        param="url", timeout=240)
    add("dirsearch", "dirsearch – dò đường dẫn", "Brute-force đường dẫn web.",
        lambda u: f"dirsearch -u {shlex.quote(u)} -q --format=plain",
        param="url", timeout=240)
    add("dirb", "dirb – dò thư mục cổ điển", "Quét thư mục/đường dẫn web bằng wordlist.",
        lambda u: f"dirb {shlex.quote(u)} {WL} -S", param="url", timeout=240)
    # --- thăm dò HTTP / WAF ---
    add("httpx", "httpx – thăm dò HTTP", "Lấy status/title/tech của endpoint.",
        lambda u: f"httpx -u {shlex.quote(u)} -silent -title -status-code -tech-detect",
        param="url", timeout=60)
    add("wafw00f", "wafw00f – phát hiện WAF", "Nhận diện tường lửa ứng dụng web.",
        lambda u: f"wafw00f {shlex.quote(u)}", param="url", timeout=60)
    # --- liệt kê DNS / subdomain ---
    add("dnsrecon", "dnsrecon – liệt kê DNS", "Liệt kê bản ghi/subdomain DNS.",
        lambda h: f"dnsrecon -d {shlex.quote(h)}", timeout=120)
    add("dnsenum", "dnsenum – liệt kê DNS", "Liệt kê bản ghi, NS, MX và subdomain.",
        lambda h: f"dnsenum --noreverse {shlex.quote(h)}", timeout=180)
    add("fierce", "fierce – quét subdomain", "Dò subdomain qua brute-force DNS.",
        lambda h: f"fierce --domain {shlex.quote(h)}", timeout=180)
    add("subfinder", "subfinder – tìm subdomain", "Thu thập subdomain thụ động (ProjectDiscovery).",
        lambda h: f"subfinder -d {shlex.quote(h)} -silent", timeout=120)
    add("amass", "amass – liệt kê subdomain", "Liệt kê subdomain thụ động (OWASP Amass).",
        lambda h: f"amass enum -passive -d {shlex.quote(h)}", timeout=300)
    add("assetfinder", "assetfinder – tìm tên miền liên quan",
        "Tìm subdomain/domain liên quan.",
        lambda h: f"assetfinder --subs-only {shlex.quote(h)}", timeout=120)
