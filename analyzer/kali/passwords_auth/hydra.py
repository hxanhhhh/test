"""Hydra – brute-force đăng nhập dịch vụ. Chỉ chạy trên host lab."""
import shlex

from analyzer.kali.base import guard, blocked, run_tool, raw_parse, target_host

NAME = "hydra"
TITLE = "Hydra – brute-force đăng nhập"
DESCRIPTION = ("Brute-force dịch vụ. service ví dụ 'ssh' hoặc 'http-get /'. "
               "Chỉ lab được phép.")
CATEGORY = "passwords_auth"
WORDLIST = "/usr/share/wordlists/rockyou.txt"


def build_command(host, service, username, wordlist):
    # service giữ nguyên để đúng cú pháp hydra (module + đường dẫn).
    return (f"hydra -l {shlex.quote(username)} -P {shlex.quote(wordlist)} "
            f"{shlex.quote(host)} {service}")


def register(reg, client):
    @reg.tool(name=NAME, title=TITLE, category=CATEGORY, description=DESCRIPTION,
              params=["target", "service", "username", "wordlist"])
    def _run(target, service="ssh", username="admin", wordlist=WORDLIST):
        if not guard(target):
            return blocked(NAME, target)
        cmd = build_command(target_host(target), service, username, wordlist)
        return run_tool(client, NAME, cmd, 300, raw_parse(NAME, "Medium"))
    return _run
