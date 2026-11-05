"""Kiểm tra Django có 'thông' với máy Kali không.

Dùng:
    python manage.py kali_health
    python manage.py kali_health --target 127.0.0.1   # thử chạy nmap thật qua Kali
"""
from django.core.management.base import BaseCommand

from analyzer.kali.client import KaliClient
from analyzer.kali import build_registry


class Command(BaseCommand):
    help = "Kiểm tra kết nối tới máy Kali (kali_server) và thử chạy một tool."

    def add_arguments(self, parser):
        parser.add_argument("--target", default=None,
                            help="Host lab để thử nmap (vd 127.0.0.1). Bỏ qua nếu chỉ test /health.")

    def handle(self, *args, **opts):
        client = KaliClient()
        self.stdout.write(f"KALI_URL = {client.base_url}")

        health = client.health()
        if isinstance(health, dict) and "error" not in health:
            self.stdout.write(self.style.SUCCESS(f"[OK] /health: {health}"))
        else:
            self.stdout.write(self.style.ERROR(f"[LỖI] /health: {health}"))
            self.stdout.write("→ Kiểm tra: kali_server đang chạy? bind 0.0.0.0? IP/cổng đúng? firewall?")
            return

        target = opts.get("target")
        if not target:
            self.stdout.write("Mẹo: thêm --target 127.0.0.1 để thử chạy nmap thật qua Kali.")
            return

        self.stdout.write(f"Chạy thử nmap qua Kali lên {target} ...")
        res = build_registry(client).call("nmap", target=target)
        if res.get("ok"):
            n = len(res.get("services", []))
            self.stdout.write(self.style.SUCCESS(f"[OK] nmap chạy được, {n} dịch vụ phát hiện."))
        else:
            self.stdout.write(self.style.WARNING(f"[?] nmap trả về: {res.get('findings') or res.get('raw','')[:200]}"))
