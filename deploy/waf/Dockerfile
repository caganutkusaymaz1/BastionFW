# BastionFW hybrid WAF: Caddy + OWASP Coraza + embedded OWASP CRS.
#
# No official "corazawaf/coraza-caddy" image is published to Docker Hub, so the
# compose stack builds Caddy from source with the coraza-caddy module. The CRS
# ruleset is compiled into the binary (load_owasp_crs + @owasp_crs includes),
# so no rule files need to be mounted.
#
# Pinned to coraza-caddy v2.6.0 (Caddy v2.11.4, Coraza v3.7.0, CRS v4.25.0).

FROM golang:1.25-alpine AS builder

ARG CORAZA_CADDY_VERSION=v2.6.0

RUN apk add --no-cache git ca-certificates \
    && go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

WORKDIR /build
RUN git clone --depth 1 --branch "${CORAZA_CADDY_VERSION}" \
        https://github.com/corazawaf/coraza-caddy.git
WORKDIR /build/coraza-caddy
# Build from the checked-out module so xcaddy resolves Caddy from go.mod.
RUN xcaddy build --with github.com/corazawaf/coraza-caddy/v2=. \
        --output /usr/bin/caddy

FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 caddy \
    && adduser -S -D -H -u 10001 -G caddy caddy

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
COPY entrypoint.sh /usr/local/bin/waf-entrypoint

# Shared-volume roots: deny-list includes, engine-mode file, audit logs.
RUN mkdir -p /var/lib/bastionfw/waf /var/log/waf \
    && chown -R caddy:caddy /var/lib/bastionfw/waf /var/log/waf \
    && chmod +x /usr/local/bin/waf-entrypoint

USER caddy
EXPOSE 8080 2019

ENTRYPOINT ["/usr/local/bin/waf-entrypoint"]
