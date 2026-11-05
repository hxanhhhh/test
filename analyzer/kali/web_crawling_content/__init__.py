"""Nhóm Web crawling & content – mỗi tool một file .py riêng (dễ debug)."""
from . import (katana, hakrawler, photon, gau, waybackurls, paramspider,
               arjun, linkfinder, getjs)

MODULES = [katana, hakrawler, photon, gau, waybackurls, paramspider,
           arjun, linkfinder, getjs]


def register(reg, client):
    for m in MODULES:
        m.register(reg, client)
