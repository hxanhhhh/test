"""Nhóm DNS & Web discovery – mỗi tool một file .py riêng (dễ debug)."""
from . import (nikto, whatweb, gobuster, ffuf, feroxbuster, dirsearch, dirb,
               httpx, wafw00f, dnsrecon, dnsenum, fierce, subfinder, amass,
               assetfinder)

MODULES = [nikto, whatweb, gobuster, ffuf, feroxbuster, dirsearch, dirb,
           httpx, wafw00f, dnsrecon, dnsenum, fierce, subfinder, amass,
           assetfinder]


def register(reg, client):
    for m in MODULES:
        m.register(reg, client)
