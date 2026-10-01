#!/bin/sh
# BastionFW Coraza/Caddy WAF entrypoint.
#
# The upstream `corazawaf/coraza-caddy:v2` image bakes a static example
# Caddyfile and exposes no UPSTREAM_URL / WAF_MODE handling at all (see
# docs/OPERATIONS.md, "WAF image verification"). This entrypoint restores the
# contract the BastionFW engine and docker-compose.yml expect:
#
#   UPSTREAM_URL  application to reverse-proxy (default http://app:3000)
#   WAF_MODE      "detect" (DetectionOnly, default) or "block" (SecRuleEngine On)
#
# The mode is translated into the Caddyfile `{$WAF_ENGINE}` placeholder so the
# generated ruleset can never silently fall back to enforcement: an unknown
# WAF_MODE aborts startup instead of guessing.
set -eu

MODE="${WAF_MODE:-detect}"
case "$MODE" in
    detect) ENGINE="DetectionOnly" ;;
    block)  ENGINE="On" ;;
    *)
        echo "fatal: WAF_MODE must be 'detect' or 'block' (got '$MODE')" >&2
        exit 1
        ;;
esac

UPSTREAM="${UPSTREAM_URL:-http://app:3000}"
export WAF_MODE WAF_ENGINE="$ENGINE" UPSTREAM_URL="$UPSTREAM"

# Caddy needs writable data/config dirs; the container root filesystem is
# mounted read-only, so keep them on the tmpfs the engine Compose file ships.
export XDG_DATA_HOME="${XDG_DATA_HOME:-/tmp/caddy/data}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-/tmp/caddy/config}"
mkdir -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" 2>/dev/null || true

# Shared audit volume (read-only in the engine container). Best effort so a
# pre-created volume with the right owner does not need root here.
mkdir -p /var/log/waf 2>/dev/null || true

echo "bastionfw-waf: mode=$MODE engine=$ENGINE upstream=$UPSTREAM"

exec caddy run --config /etc/caddy/Caddyfile.bastionfw --adapter caddyfile
