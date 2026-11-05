import shlex

from analyzer.kali.base import make_adder


def register(reg, client):
    add = make_adder(reg, client, "vuln_scanners")
    add("wapiti", "Wapiti – quét lỗ hổng web", "Quét SQLi/XSS/các lỗ hổng web phổ biến.",
        lambda u: f"wapiti -u {shlex.quote(u)} --flush-session -m sql,xss,exec -f txt",
        param="url", timeout=360, severity="Medium")
    add("nikto_ssl", "Nikto (SSL) – quét HTTPS", "Quét web server qua HTTPS.",
        lambda u: f"nikto -host {shlex.quote(u)} -ssl -maxtime 120 -ask no -nointeractive",
        param="url", timeout=200, severity="Medium")
    add("dalfox", "Dalfox – quét XSS", "Quét lỗ hổng XSS tự động (tham số URL).",
        lambda u: f"dalfox url {shlex.quote(u)} --silence --no-color",
        param="url", timeout=240, severity="Medium")
    add("wpscan", "WPScan – quét WordPress", "Dò lỗ hổng, plugin, theme của WordPress.",
        lambda u: f"wpscan --url {shlex.quote(u)} --no-banner --random-user-agent",
        param="url", timeout=360, severity="Medium")
    add("skipfish", "Skipfish – quét web tự động", "Quét bảo mật web tốc độ cao của Google.",
        lambda u: f"skipfish -o /tmp/skipfish_out -k 00:05:00 {shlex.quote(u)}",
        param="url", timeout=360, severity="Medium")
    add("nmap_vuln", "Nmap NSE – kịch bản vuln", "Chạy nhóm script 'vuln' của Nmap lên mục tiêu.",
        lambda h: f"nmap -sV --script vuln {shlex.quote(h)}", timeout=360, severity="Medium")
    add("joomscan", "JoomScan – quét Joomla", "Dò lỗ hổng và thành phần của Joomla.",
        lambda u: f"joomscan --url {shlex.quote(u)}", param="url", timeout=300, severity="Medium")
