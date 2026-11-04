#!/usr/bin/env bash
# Khởi động toàn bộ hệ thống để test.
# Cách dùng (từ gốc repo):   bash scripts/run_all.sh
# Đổi model LLM:             OLLAMA_MODEL=qwen2.5:7b-instruct bash scripts/run_all.sh
set -e
cd "$(dirname "$0")/.."

MODEL="${OLLAMA_MODEL:-qwen2.5-coder:3b}"
export OLLAMA_MODEL="$MODEL"

echo "==> 1/5 Môi trường Python + phụ thuộc"
if [ ! -d .venv ]; then python3 -m venv .venv; fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r requirements.txt

echo "==> 2/5 Ollama (model: $MODEL)"
if ! curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
  echo "    Khởi động ollama serve (log: /tmp/ollama.log)"
  nohup ollama serve >/tmp/ollama.log 2>&1 &
  for i in $(seq 1 15); do
    curl -sf http://localhost:11434/api/tags >/dev/null 2>&1 && break
    sleep 1
  done
fi
if ! ollama list 2>/dev/null | grep -q "${MODEL%%:*}"; then
  echo "    Tải model $MODEL (lần đầu có thể lâu)..."
  ollama pull "$MODEL"
fi

echo "==> 3/5 Lab DVWA / Juice Shop"
if command -v docker >/dev/null 2>&1; then
  docker compose -f docker-compose.lab.yml up -d || echo "    (bỏ qua lab nếu docker lỗi)"
  echo "    DVWA: http://127.0.0.1:4280/  ·  Juice Shop: http://127.0.0.1:3000/"
  echo "    Lần đầu DVWA: mở /setup.php -> Create/Reset Database, đăng nhập admin/password"
else
  echo "    Không thấy docker — bỏ qua lab (phần Agent/bảo mật vẫn test được với site khác)."
fi

echo "==> 4/5 Cơ sở dữ liệu"
python manage.py migrate

echo "==> 5/5 Web server"
echo "    Mở http://127.0.0.1:8000/   (Ctrl+C để dừng)"
echo "    Gợi ý: nạp CVE thật trước nếu cần:  python -m analyzer.fetch_nvd_cve && python -m analyzer.rebuild_rag"
python manage.py runserver
