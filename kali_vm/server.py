#!/usr/bin/env python3
"""Server tối giản chạy TRÊN máy Kali để web_sec_test gọi tool thật.

Chỉ cần Python3 + Flask (không cần toàn bộ MCP-Kali-Server). Phơi đúng 2
endpoint mà analyzer/kali/client.py (KaliClient) mong đợi:

    GET  /health
    POST /api/command   body: {"command": "...", "timeout": 300}
    -> {"stdout","stderr","return_code","success","timed_out","command"}

Chạy trên VM Kali:
    pip install flask          # hoặc: sudo apt install python3-flask
    python3 server.py --ip 0.0.0.0 --port 5000

CẢNH BÁO: /api/command chạy lệnh shell tùy ý. CHỈ chạy trên VM lab của bạn,
trong mạng nội bộ. Giới hạn mục tiêu (chỉ host lab) nằm ở phía Django (guard()).
"""
import argparse
import os
import shutil
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)
DEFAULT_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", "300"))


@app.get("/health")
def health():
    """Báo server sống + tool nào đã cài trên Kali."""
    tools = ["nmap", "nikto", "sqlmap", "nuclei", "gobuster", "ffuf",
             "whatweb", "sslscan", "hydra", "wpscan", "dalfox"]
    return jsonify({
        "status": "ok",
        "tools": {t: bool(shutil.which(t)) for t in tools},
    })


@app.post("/api/command")
def run_command():
    """Chạy một lệnh shell trên Kali, trả về stdout/stderr/return_code."""
    data = request.get_json(silent=True) or {}
    command = (data.get("command") or "").strip()
    if not command:
        return jsonify({"error": "Command parameter is required"}), 400

    timeout = int(data.get("timeout") or DEFAULT_TIMEOUT)
    try:
        proc = subprocess.run(command, shell=True, capture_output=True,
                              text=True, timeout=timeout)
        return jsonify({
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "return_code": proc.returncode,
            "success": proc.returncode == 0,
            "timed_out": False,
            "command": command,
        })
    except subprocess.TimeoutExpired as exc:
        return jsonify({
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "return_code": -1,
            "success": False,
            "timed_out": True,
            "command": command,
        })
    except Exception as exc:  # noqa: BLE001
        return jsonify({
            "stdout": "", "stderr": str(exc), "return_code": -1,
            "success": False, "timed_out": False, "command": command,
        }), 500


def parse_args():
    ap = argparse.ArgumentParser(description="Server tool Kali tối giản cho web_sec_test")
    ap.add_argument("--ip", default="127.0.0.1",
                    help="IP bind. Dùng 0.0.0.0 để máy khác gọi được (mặc định 127.0.0.1).")
    ap.add_argument("--port", type=int, default=5000, help="Cổng (mặc định 5000).")
    return ap.parse_args()


if __name__ == "__main__":
    args = parse_args()
    print(f"[kali_vm] Server chạy tại {args.ip}:{args.port}  (Ctrl+C để dừng)")
    app.run(host=args.ip, port=args.port)
