#!/bin/sh
# BastionFW WAF entrypoint.
#
# Seeds the shared volume so Caddy can parse the Caddyfile even when the
# BastionFW engine has not started yet:
#   - engine-mode.conf   <- SecRuleEngine On | DetectionOnly, from $WAF_MODE
#   - deny.caddy         <- empty dynamic deny include (filled by BastionFW)
set -eu

shared="/var/lib/bastionfw/waf"
mkdir -p "${shared}"

mode="${WAF_MODE:-detect}"
case "${mode}" in
  detect) engine="SecRuleEngine DetectionOnly" ;;
  block)  engine="SecRuleEngine On" ;;
  *)
    echo "invalid WAF_MODE '${mode}': expected detect or block" >&2
    exit 1
    ;;
esac

printf '%s\n' "${engine}" > "${shared}/engine-mode.conf"
if [ ! -f "${shared}/deny.caddy" ]; then
  : > "${shared}/deny.caddy"
fi
chmod 0644 "${shared}/engine-mode.conf" "${shared}/deny.caddy"

exec /usr/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
