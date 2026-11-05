import shlex

from analyzer.kali.base import make_adder


def register(reg, client):
    add = make_adder(reg, client, "recon_osint")
    # --- quét cổng ---
    add("masscan", "masscan – quét cổng siêu nhanh", "Quét cổng tốc độ cao (cần quyền root).",
        lambda h: f"masscan {shlex.quote(h)} -p1-1000 --rate 1000", timeout=180)
    add("naabu", "naabu – quét cổng", "Quét cổng nhanh (ProjectDiscovery).",
        lambda h: f"naabu -host {shlex.quote(h)} -silent", timeout=120)
    add("rustscan", "RustScan – quét cổng (Rust)", "Quét cổng cực nhanh rồi bàn giao nmap.",
        lambda h: f"rustscan -a {shlex.quote(h)} --ulimit 5000 -- -sV", timeout=180)
    add("fping", "fping – kiểm tra host sống", "Ping nhanh xác định host còn hoạt động.",
        lambda h: f"fping -c1 -t500 {shlex.quote(h)}", timeout=30)
    # --- DNS / whois ---
    add("whois", "whois – thông tin đăng ký", "Tra cứu whois của mục tiêu.",
        lambda h: f"whois {shlex.quote(h)}", timeout=30)
    add("dig", "dig – truy vấn DNS", "Truy vấn bản ghi DNS.",
        lambda h: f"dig {shlex.quote(h)} ANY +noall +answer", timeout=30)
    add("nslookup", "nslookup – phân giải DNS", "Phân giải tên miền.",
        lambda h: f"nslookup {shlex.quote(h)}", timeout=30)
    add("host", "host – phân giải DNS", "Phân giải tên miền (host).",
        lambda h: f"host {shlex.quote(h)}", timeout=30)
    add("traceroute", "traceroute – lần vết đường đi", "Lần vết các router tới đích.",
        lambda h: f"traceroute -m 10 {shlex.quote(h)}", timeout=60)
    # --- OSINT / liệt kê dịch vụ ---
    add("dmitry", "DMitry – thu thập thông tin", "Thu thập whois/subdomain/cổng cơ bản.",
        lambda h: f"dmitry -winse {shlex.quote(h)}", timeout=120)
    add("enum4linux", "enum4linux – liệt kê SMB", "Liệt kê thông tin SMB/NetBIOS (Windows/Samba).",
        lambda h: f"enum4linux -a {shlex.quote(h)}", timeout=180)
    add("smbmap", "smbmap – liệt kê share SMB", "Liệt kê thư mục chia sẻ SMB và quyền.",
        lambda h: f"smbmap -H {shlex.quote(h)}", timeout=120)
    add("theharvester", "theHarvester – OSINT email/subdomain",
        "Thu thập email, subdomain, host từ nguồn mở.",
        lambda h: f"theHarvester -d {shlex.quote(h)} -b bing,duckduckgo -l 100", timeout=180)
    add("snmpwalk", "snmp-check – liệt kê SNMP", "Dò thông tin thiết bị qua SNMP (community public).",
        lambda h: f"snmp-check {shlex.quote(h)}", timeout=90)
