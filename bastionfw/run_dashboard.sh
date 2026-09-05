#!/usr/bin/env bash
set -euo pipefail

mkdir -p staging-logs state
touch staging-logs/auth.log

echo "Starting the BastionFW dashboard."
echo "Open in a browser: http://127.0.0.1:8080"
echo "Press Ctrl+C to stop."

exec python3 -m ed_bt_ade.dashboard --config config.staging.json --host 0.0.0.0 --port 8080