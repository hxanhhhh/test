"""Nhóm Vulnerability scanners – mỗi tool một file .py riêng (dễ debug)."""
from . import (nuclei, wapiti, nikto_ssl, dalfox, wpscan, skipfish, nmap_vuln,
               joomscan)

MODULES = [nuclei, wapiti, nikto_ssl, dalfox, wpscan, skipfish, nmap_vuln,
           joomscan]


def register(reg, client):
    for m in MODULES:
        m.register(reg, client)
