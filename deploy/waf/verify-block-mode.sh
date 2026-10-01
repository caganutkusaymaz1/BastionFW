#!/bin/sh
# BastionFW Coraza WAF block-mode verification (end-to-end, real containers).
#
# Builds the deploy/waf image, deploys it behind a throwaway upstream, and
# asserts:
#   WAF_MODE=block  -> a SQLi probe returns 403 (Coraza denies)
#   WAF_MODE=detect -> the same probe reaches the upstream and returns 200
# It tears every container/network it created down on exit.
#
# Run from the repository root (Docker + network access required):
#   sh ./deploy/waf/verify-block-mode.sh
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

IMAGE="bastionfw-waf:local"
NET="bastionfw-waf-verify-net"
UPSTREAM="bastionfw-waf-verify-upstream"
BLOCK="bastionfw-waf-verify-block"
DETECT="bastionfw-waf-verify-detect"
BLOCK_PORT="${WAF_BLOCK_PORT:-18081}"
DETECT_PORT="${WAF_DETECT_PORT:-18082}"
# URL-encoded SQL injection probe: /?id=1' OR '1'='1
SQLI_PATH='/?id=1%27%20OR%20%271%27%3D%271'
FAILED=0

cleanup() {
    docker rm -f "$BLOCK" "$DETECT" "$UPSTREAM" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

wait_ready() {
    port="$1"
    i=0
    while [ "$i" -lt 30 ]; do
        if curl -s -o /dev/null "http://127.0.0.1:${port}/" 2>/dev/null; then
            return 0
        fi
        i=$((i + 1))
        sleep 1
    done
    return 1
}

code() { # $1=port
    curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1/" 2>/dev/null || echo "000"
}

echo "[waf-verify] building $IMAGE"
docker build -t "$IMAGE" "$REPO_ROOT/deploy/waf"

cleanup
echo "[waf-verify] starting network + upstream"
docker network create "$NET" >/dev/null
docker run -d --name "$UPSTREAM" --network "$NET" nginx:alpine >/dev/null

echo "[waf-verify] deploying WAF in block mode on :$BLOCK_PORT"
docker run -d --name "$BLOCK" --network "$NET" \
    -e WAF_MODE=block -e UPSTREAM_URL="http://${UPSTREAM}:80" \
    -p "${BLOCK_PORT}:8080" "$IMAGE" >/dev/null
wait_ready "$BLOCK_PORT" || { echo "[waf-verify] block WAF did not become ready" >&2; docker logs "$BLOCK" >&2; exit 1; }

BLOCK_SQLI="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${BLOCK_PORT}${SQLI_PATH}")"
BLOCK_BENIGN="$(code "$BLOCK_PORT")"
echo "[waf-verify] block  benign=$BLOCK_BENIGN  sqli=$BLOCK_SQLI"
[ "$BLOCK_BENIGN" = "200" ] || { echo "[waf-verify] FAIL: benign request not 200 in block mode" >&2; FAILED=1; }
[ "$BLOCK_SQLI" = "403" ] || { echo "[waf-verify] FAIL: SQLi not blocked (got $BLOCK_SQLI)" >&2; FAILED=1; }

echo "[waf-verify] deploying WAF in detect mode on :$DETECT_PORT"
docker run -d --name "$DETECT" --network "$NET" \
    -e WAF_MODE=detect -e UPSTREAM_URL="http://${UPSTREAM}:80" \
    -p "${DETECT_PORT}:8080" "$IMAGE" >/dev/null
wait_ready "$DETECT_PORT" || { echo "[waf-verify] detect WAF did not become ready" >&2; docker logs "$DETECT" >&2; exit 1; }

DETECT_SQLI="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${DETECT_PORT}${SQLI_PATH}")"
echo "[waf-verify] detect sqli=$DETECT_SQLI (expected upstream 200)"
[ "$DETECT_SQLI" = "200" ] || { echo "[waf-verify] FAIL: detect mode should not block" >&2; FAILED=1; }

[ "$FAILED" -eq 0 ] && echo "[waf-verify] PASS: block=403, detect=200"
exit "$FAILED"
