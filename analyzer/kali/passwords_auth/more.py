import shlex

from analyzer.kali.base import (guard, blocked, run_tool, raw_parse, target_host,
                                make_adder)

WL = "/usr/share/wordlists/rockyou.txt"


def register(reg, client):
    @reg.tool(name="hydra", title="Hydra – brute-force đăng nhập", category="passwords_auth",
              description="Brute-force dịch vụ. service ví dụ 'ssh' hoặc 'http-get /'. Chỉ lab được phép.",
              params=["target", "service", "username", "wordlist"])
    def hydra(target, service="ssh", username="admin", wordlist=WL):
        if not guard(target):
            return blocked("hydra", target)
        host = target_host(target)
        # service giữ nguyên để đúng cú pháp hydra (module + đường dẫn).
        cmd = (f"hydra -l {shlex.quote(username)} -P {shlex.quote(wordlist)} "
               f"{shlex.quote(host)} {service}")
        return run_tool(client, "hydra", cmd, 300, raw_parse("hydra", "Medium"))

    @reg.tool(name="medusa", title="Medusa – brute-force song song", category="passwords_auth",
              description="Brute-force đăng nhập song song. module ví dụ 'ssh', 'http'. Chỉ lab được phép.",
              params=["target", "module", "username", "wordlist"])
    def medusa(target, module="ssh", username="admin", wordlist=WL):
        if not guard(target):
            return blocked("medusa", target)
        host = target_host(target)
        cmd = (f"medusa -h {shlex.quote(host)} -u {shlex.quote(username)} "
               f"-P {shlex.quote(wordlist)} -M {shlex.quote(module)}")
        return run_tool(client, "medusa", cmd, 300, raw_parse("medusa", "Medium"))

    @reg.tool(name="ncrack", title="Ncrack – brute-force dịch vụ mạng", category="passwords_auth",
              description="Brute-force đăng nhập dịch vụ mạng. service ví dụ 'ssh', 'rdp'. Chỉ lab được phép.",
              params=["target", "service", "username", "wordlist"])
    def ncrack(target, service="ssh", username="admin", wordlist=WL):
        if not guard(target):
            return blocked("ncrack", target)
        host = target_host(target)
        cmd = (f"ncrack -u {shlex.quote(username)} -P {shlex.quote(wordlist)} "
               f"{service}://{shlex.quote(host)}")
        return run_tool(client, "ncrack", cmd, 300, raw_parse("ncrack", "Medium"))

    @reg.tool(name="patator", title="Patator – brute-force đa năng", category="passwords_auth",
              description="Brute-force đăng nhập SSH đa năng. Chỉ lab được phép.",
              params=["target", "username", "wordlist"])
    def patator(target, username="admin", wordlist=WL):
        if not guard(target):
            return blocked("patator", target)
        host = target_host(target)
        cmd = (f"patator ssh_login host={shlex.quote(host)} user={shlex.quote(username)} "
               f"password=FILE0 0={shlex.quote(wordlist)} -x ignore:fgrep='failed'")
        return run_tool(client, "patator", cmd, 300, raw_parse("patator", "Medium"))

    @reg.tool(name="crackmapexec", title="CrackMapExec – kiểm thử SMB/WinRM",
              category="passwords_auth",
              description="Kiểm tra đăng nhập SMB với cặp user/pass. Chỉ lab được phép.",
              params=["target", "username", "password"])
    def crackmapexec(target, username="admin", password="admin"):
        if not guard(target):
            return blocked("crackmapexec", target)
        host = target_host(target)
        cmd = (f"crackmapexec smb {shlex.quote(host)} -u {shlex.quote(username)} "
               f"-p {shlex.quote(password)}")
        return run_tool(client, "crackmapexec", cmd, 180, raw_parse("crackmapexec", "Medium"))

    # --- sinh wordlist / bẻ hash offline (không nhắm host) ---
    add = make_adder(reg, client, "passwords_auth")
    add("cewl", "CeWL – sinh wordlist từ website", "Thu thập từ khóa trên trang để tạo wordlist.",
        lambda u: f"cewl -d 2 -m 5 {shlex.quote(u)}", param="url", timeout=180)
    add("john", "John the Ripper – bẻ hash (offline)",
        "Bẻ file hash bằng John (đường dẫn file hash, không nhắm host).",
        lambda f: f"john --wordlist={WL} {shlex.quote(f)}",
        param="hashfile", timeout=300, do_guard=False)
