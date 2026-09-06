#!/usr/bin/env bash
set -euo pipefail

mkdir -p staging-logs
touch staging-logs/auth.log

echo "Writing demo SSH events..."
for n in 1 2 3; do
  echo "Failed password for root from 203.0.113.10" >> staging-logs/auth.log
  sleep 0.2
done

echo "Demo events complete."
echo "View metrics with: curl http://127.0.0.1:19109/metrics"