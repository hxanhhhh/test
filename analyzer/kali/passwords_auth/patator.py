"""Patator – brute-force đăng nhập SSH đa năng. Chỉ chạy trên host lab."""
import shlex

from analyzer.kali.base import guard, blocked, run_tool, raw_parse, target_host

NAME = "patator"
TITLE = "Patator – brute-force đa năng"
DESCRIPTION = "Brute-force đăng nhập SSH đa năng. Chỉ lab được phép."
CATEGORY = "passwords_auth"
WORDLIST = "/usr/share/wordlists/rockyou.txt"


def build_command(host, username, wordlist):
    return (f"patator ssh_login host={shlex.quote(host)} user={shlex.quote(username)} "
            f"password=FILE0 0={shlex.quote(wordlist)} -x ignore:fgrep='failed'")


def register(reg, client):
    @reg.tool(name=NAME, title=TITLE, category=CATEGORY, description=DESCRIPTION,
              params=["target", "username", "wordlist"])
    def _run(target, username="admin", wordlist=WORDLIST):
        if not guard(target):
            return blocked(NAME, target)
        cmd = build_command(target_host(target), username, wordlist)
        return run_tool(client, NAME, cmd, 300, raw_parse(NAME, "Medium"))
    return _run
