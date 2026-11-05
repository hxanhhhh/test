"""Nhóm SSL/TLS – mỗi tool một file .py riêng (dễ debug)."""
from . import sslscan, testssl, sslyze, nmap_ssl, tlssled

MODULES = [sslscan, testssl, sslyze, nmap_ssl, tlssled]


def register(reg, client):
    for m in MODULES:
        m.register(reg, client)
