"""CrackMapExec – kiểm thử đăng nhập SMB/WinRM. Chỉ chạy trên host lab."""
import shlex

from analyzer.kali.base import guard, blocked, run_tool, raw_parse, target_host

NAME = "crackmapexec"
TITLE = "CrackMapExec – kiểm thử SMB/WinRM"
DESCRIPTION = "Kiểm tra đăng nhập SMB với cặp user/pass. Chỉ lab được phép."
CATEGORY = "passwords_auth"


def build_command(host, username, password):
    return (f"crackmapexec smb {shlex.quote(host)} -u {shlex.quote(username)} "
            f"-p {shlex.quote(password)}")


def register(reg, client):
    @reg.tool(name=NAME, title=TITLE, category=CATEGORY, description=DESCRIPTION,
              params=["target", "username", "password"])
    def _run(target, username="admin", password="admin"):
        if not guard(target):
            return blocked(NAME, target)
        cmd = build_command(target_host(target), username, password)
        return run_tool(client, NAME, cmd, 180, raw_parse(NAME, "Medium"))
    return _run
