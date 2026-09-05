#!/usr/bin/env bash
set -euo pipefail

mkdir -p staging-logs state
touch staging-logs/auth.log

echo "BastionFW grafik arayüzü başlatılıyor."
echo "Tarayıcıda aç: http://127.0.0.1:8080"
echo "Durdurmak için Ctrl+C tuşlarına bas."

exec python3 -m ed_bt_ade.dashboard --config config.staging.json --host 0.0.0.0 --port 8080