#!/usr/bin/env bash
# Token Security 一键启动（Linux/macOS）
set -e
cd "$(dirname "$0")"

command -v uv >/dev/null 2>&1 || python3 -m pip install -q uv
uv sync --quiet 2>/dev/null || python3 -m pip install -q -r requirements.txt

[ -f config/credentials.env ] || echo "[TIP] config/credentials.env not found - copy credentials.env.example and fill your API key for full LLM features."

echo "[START] Token Security -> http://127.0.0.1:5000/web"
(cd src && nohup python3 main.py -m http -p 5000 > ../server.log 2>&1 &)
sleep 10
open http://127.0.0.1:5000/web 2>/dev/null || xdg-open http://127.0.0.1:5000/web 2>/dev/null || echo "Open in browser: http://127.0.0.1:5000/web"
echo "Server running in background. Log: server.log. Stop: pkill -f 'main.py -m http'"
