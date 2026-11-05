"""Nhóm Recon & OSINT – mỗi tool một file .py riêng (dễ debug)."""
from . import (nmap, masscan, naabu, rustscan, fping, whois, dig, nslookup,
               host, traceroute, dmitry, enum4linux, smbmap, theharvester,
               snmpwalk)

MODULES = [nmap, masscan, naabu, rustscan, fping, whois, dig, nslookup,
           host, traceroute, dmitry, enum4linux, smbmap, theharvester, snmpwalk]


def register(reg, client):
    for m in MODULES:
        m.register(reg, client)
