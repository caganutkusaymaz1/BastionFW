#!/bin/sh
# BastionFW nftables provisioning (idempotent).
#
# Creates the exact table/set/chain/rule that the engine's nftables driver
# writes into, so an operator never has to hand-craft them:
#
#   ed_bt_ade.firewall.NftablesDriver  ->  nft add element inet ed_bt_ade blacklist { <ip> }
#                                          nft delete element inet ed_bt_ade blacklist { <ip> }
#
# Run this once on the host (outside Docker) before setting
# firewall.enabled=true with firewall.backend=nftables. Re-running is safe:
# existing objects are detected with `nft list` and never re-created, and the
# input drop rule is only added when it is missing.
#
# Requires root (nft needs CAP_NET_ADMIN). No shell interpolation of user
# data happens here; the script only manages the fixed BastionFW objects.
set -eu

if ! command -v nft >/dev/null 2>&1; then
    echo "provision-nftables: 'nft' not found; install the nftables package first" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "provision-nftables: must run as root (nft requires CAP_NET_ADMIN)" >&2
    exit 1
fi

TABLE="inet ed_bt_ade"

# Table.
if ! nft list table $TABLE >/dev/null 2>&1; then
    nft add table $TABLE
fi

# IPv4 ban set (matches NftablesDriver's "add element ... blacklist" target).
if ! nft list set $TABLE blacklist >/dev/null 2>&1; then
    nft add set $TABLE blacklist '{ type ipv4_addr; flags interval; }'
fi

# Input chain.
if ! nft list chain $TABLE input >/dev/null 2>&1; then
    nft add chain $TABLE input '{ type filter hook input priority 0; }'
fi

# Drop rule for set members, added only when absent.
if ! nft list chain $TABLE input 2>/dev/null | grep -q 'ip saddr @blacklist drop'; then
    nft add rule $TABLE input ip saddr @blacklist drop
fi

echo "provision-nftables: inet ed_bt_ade table/set/chain/rule ready"
nft list table $TABLE
