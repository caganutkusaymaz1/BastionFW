# syntax=docker/dockerfile:1
#
# BastionFW Coraza/Caddy WAF layer.
#
# FINDING (2026-10-01): the image the repository previously referenced,
# `corazawaf/coraza-caddy:v2`, does NOT exist on Docker Hub
# (https://hub.docker.com/v2/repositories/corazawaf/coraza-caddy -> "object not
# found"), so the old `image:`-based WAF service could never start. The Coraza
# Caddy module is distributed as a Go plugin (github.com/corazawaf/coraza-caddy
# /v2); there is no official prebuilt image. We therefore build Caddy with the
# plugin from source using Caddy's official builder image, which embeds the
# OWASP CRS that `load_owasp_crs` resolves. See docs/OPERATIONS.md
# "WAF image verification".
#
# Pin the builder/runtime tags (or digests) and bump both together.
FROM caddy:2.11.4-builder AS builder
RUN xcaddy build v2.11.4 \
    --with github.com/corazawaf/coraza-caddy/v2

FROM caddy:2.11.4

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# Writable audit location for the shared `waf-audit` volume (read-only in the
# engine container). 0777 keeps it usable regardless of the runtime uid.
RUN mkdir -p /var/log/waf \
    && chmod 0777 /var/log/waf

COPY Caddyfile /etc/caddy/Caddyfile.bastionfw
COPY entrypoint.sh /usr/local/bin/bastionfw-waf-entrypoint.sh
RUN chmod 0755 /usr/local/bin/bastionfw-waf-entrypoint.sh

# Run as a dedicated non-root user. The base caddy image ships no `caddy`
# account (only `nobody`), so create one here. entrypoint.sh only needs to
# read /etc/caddy/Caddyfile.bastionfw and write to the tmpfs-backed XDG
# dirs (/tmp/caddy/...) plus the shared audit dir; docker-compose.yml mounts
# the root filesystem read-only and /tmp as rw,noexec,nosuid tmpfs, so those
# paths are the only writable ones needed at runtime.
RUN addgroup -S waf \
    && adduser -S -D -H -h /nonexistent -s /sbin/nologin -G waf -u 10001 waf \
    && mkdir -p /tmp/caddy/data /tmp/caddy/config \
    && chown -R waf:waf /tmp/caddy /var/log/waf \
    && chmod 0755 /etc/caddy/Caddyfile.bastionfw

USER waf

ENTRYPOINT ["/usr/local/bin/bastionfw-waf-entrypoint.sh"]
