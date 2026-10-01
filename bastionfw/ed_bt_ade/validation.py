"""Strict validation primitives for network and firewall configuration."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


class ValidationError(ValueError):
    """Raised when an externally supplied network value is invalid."""


@dataclass(frozen=True, slots=True)
class NetworkRule:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    protocol: str
    port: int | None = None


def parse_ip(value: str, *, version: int | None = None,
             ipv6_enabled: bool = True) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse and canonicalize an IP address.

    ``ipv6_enabled=False`` refuses IPv6 outright, so callers that can only
    enforce IPv4 (the firewall orchestrator) reject an IPv6 ban up front with
    a clear error instead of sending it to a driver without an IPv6 set.
    Generic parsers keep accepting IPv6 by default.
    """
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValidationError("IP address must be a non-empty canonical string")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError("invalid IP address") from exc
    if version is not None and address.version != version:
        raise ValidationError(f"IPv{version} address required")
    if address.version == 6 and not ipv6_enabled:
        raise ValidationError("IPv6 is disabled; an IPv4 address is required")
    return address


def parse_network(value: str, *, version: int | None = None,
                  ipv6_enabled: bool = True) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse a canonical network. ``ipv6_enabled=False`` refuses IPv6."""
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValidationError("network must be a non-empty canonical string")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValidationError("network must use canonical address/prefix notation") from exc
    if version is not None and network.version != version:
        raise ValidationError(f"IPv{version} network required")
    if network.version == 6 and not ipv6_enabled:
        raise ValidationError("IPv6 is disabled; an IPv4 network is required")
    return network


def parse_port(value: int | str) -> int:
    if isinstance(value, bool):
        raise ValidationError("port must be an integer")
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.isdecimal():
        port = int(value)
    else:
        raise ValidationError("port must be an integer")
    if not 1 <= port <= 65535:
        raise ValidationError("port must be between 1 and 65535")
    return port


def parse_protocol(value: str) -> str:
    protocol = value.strip().lower() if isinstance(value, str) else ""
    allowed = {"tcp", "udp", "icmp", "icmpv6"}
    if protocol not in allowed:
        raise ValidationError("protocol must be tcp, udp, icmp, or icmpv6")
    return protocol


def is_global_address(value: str) -> bool:
    address = parse_ip(value)
    return address.is_global


def peer_matches_network(peer: str, network: str) -> bool:
    try:
        return parse_ip(peer) in parse_network(network)
    except ValidationError:
        return False
