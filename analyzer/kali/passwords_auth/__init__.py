"""Nhóm Passwords & auth – mỗi tool một file .py riêng (dễ debug)."""
from . import hydra, medusa, ncrack, patator, crackmapexec, cewl, john

MODULES = [hydra, medusa, ncrack, patator, crackmapexec, cewl, john]


def register(reg, client):
    for m in MODULES:
        m.register(reg, client)
