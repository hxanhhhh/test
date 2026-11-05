"""Gói công cụ bảo mật Kali, tổ chức theo NHÓM giống Kali_MCP nhưng chạy trong
web_sec_test. Mỗi nhóm có register(reg, client); build_registry() gom tất cả.

Dùng:
    from analyzer.kali import build_registry
    reg = build_registry()                 # KALI_URL từ môi trường
    reg.list()                             # liệt kê tool
    reg.call("sqlmap", url="...", cookie="...")
"""
from analyzer.kali.registry import ToolRegistry
from analyzer.kali.recon_osint import register as register_recon_osint
from analyzer.kali.dns_web_discovery import register as register_dns_web_discovery
from analyzer.kali.web_crawling_content import register as register_web_crawling_content
from analyzer.kali.vuln_scanners import register as register_vuln_scanners
from analyzer.kali.exploitation_frameworks import register as register_exploitation_frameworks
from analyzer.kali.passwords_auth import register as register_passwords_auth
from analyzer.kali.ssl_tls import register as register_ssl_tls


def build_registry(client=None):
    from analyzer.kali.client import KaliClient
    reg = ToolRegistry(client or KaliClient())
    register_recon_osint(reg, reg.client)
    register_dns_web_discovery(reg, reg.client)
    register_web_crawling_content(reg, reg.client)
    register_vuln_scanners(reg, reg.client)
    register_exploitation_frameworks(reg, reg.client)
    register_passwords_auth(reg, reg.client)
    register_ssl_tls(reg, reg.client)
    return reg
