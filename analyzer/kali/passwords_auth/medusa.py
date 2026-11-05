"""Medusa – brute-force đăng nhập song song. Chỉ chạy trên host lab."""
import shlex

from analyzer.kali.base import guard, blocked, run_tool, raw_parse, target_host

NAME = "medusa"
TITLE = "Medusa – brute-force song song"
DESCRIPTION = ("Brute-force đăng nhập song song. module ví dụ 'ssh', 'http'. "
               "Chỉ lab được phép.")
CATEGORY = "passwords_auth"
WORDLIST = "/usr/share/wordlists/rockyou.txt"


def build_command(host, module, username, wordlist):
    return (f"medusa -h {shlex.quote(host)} -u {shlex.quote(username)} "
            f"-P {shlex.quote(wordlist)} -M {shlex.quote(module)}")


def register(reg, client):
    @reg.tool(name=NAME, title=TITLE, category=CATEGORY, description=DESCRIPTION,
              params=["target", "module", "username", "wordlist"])
    def _run(target, module="ssh", username="admin", wordlist=WORDLIST):
        if not guard(target):
            return blocked(NAME, target)
        cmd = build_command(target_host(target), module, username, wordlist)
        return run_tool(client, NAME, cmd, 300, raw_parse(NAME, "Medium"))
    return _run
