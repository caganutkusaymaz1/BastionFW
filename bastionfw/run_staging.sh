#!/usr/bin/env bash
set -euo pipefail

mkdir -p staging-logs state
touch staging-logs/auth.log

echo "Starting BastionFW in staging/dry-run mode."
echo "Press Ctrl+C to stop."
echo "Health:  http://127.0.0.1:19109/healthz"
echo "Metrics: http://127.0.0.1:19109/metrics"

exec python3 -m ed_bt_ade.sentinel --config config.staging.json