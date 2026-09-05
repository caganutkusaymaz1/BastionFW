#!/usr/bin/env bash
set -euo pipefail

mkdir -p staging-logs state
touch staging-logs/auth.log

echo "BastionFW staging/dry-run başlatılıyor."
echo "Durdurmak için Ctrl+C tuşlarına bas."
echo "Health:  http://127.0.0.1:19109/healthz"
echo "Metrics: http://127.0.0.1:19109/metrics"

exec python3 -m ed_bt_ade.sentinel --config config.staging.json