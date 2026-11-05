"""Ncrack – brute-force đăng nhập dịch vụ mạng. Chỉ chạy trên host lab."""
import shlex

from analyzer.kali.base import guard, blocked, run_tool, raw_parse, target_host

NAME = "ncrack"
TITLE = "Ncrack – brute-force dịch vụ mạng"
DESCRIPTION = ("Brute-force đăng nhập dịch vụ mạng. service ví dụ 'ssh', 'rdp'. "
               "Chỉ lab được phép.")
CATEGORY = "passwords_auth"
WORDLIST = "/usr/share/wordlists/rockyou.txt"


def build_command(host, service, username, wordlist):
    return (f"ncrack -u {shlex.quote(username)} -P {shlex.quote(wordlist)} "
            f"{service}://{shlex.quote(host)}")


def register(reg, client):
    @reg.tool(name=NAME, title=TITLE, category=CATEGORY, description=DESCRIPTION,
              params=["target", "service", "username", "wordlist"])
    def _run(target, service="ssh", username="admin", wordlist=WORDLIST):
        if not guard(target):
            return blocked(NAME, target)
        cmd = build_command(target_host(target), service, username, wordlist)
        return run_tool(client, NAME, cmd, 300, raw_parse(NAME, "Medium"))
    return _run
