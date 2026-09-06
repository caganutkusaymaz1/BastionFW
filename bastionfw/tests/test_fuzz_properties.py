"""Property-based (fuzz) tests for the input-facing validation and parsing.

These tests assert invariants rather than examples: the parsers must never
crash on arbitrary input (they either return a valid value or a defined
None/ValidationError outcome) and every accepted value must be canonical.
Run as part of the normal pytest pipeline; example counts are bounded to
keep CI time reasonable.

Edge-case exploration evidence (manual adversarial probes run alongside the
hypothesis campaigns):
- ``010.1.1.1`` / ``01.2.3.4`` / ``1.2.3.04`` -> ValidationError (leading-zero
  octets rejected; no octal-decimal ambiguity).
- ``1.2.3.4 `` / `` 1.2.3.4`` / ``1.2.3.4\n`` / NUL-prefixed/suffixed forms ->
  ValidationError (no whitespace or NUL tricks).
- ``0x7f.0.0.1`` / ``2130706433`` -> ValidationError (hex/integer forms
  rejected).
- ``FE80::1`` -> ``fe80::1`` (case-insensitive, canonical lowercase).
- ``::ffff:8.8.8.8`` -> ``::ffff:808:808`` (IPv4-mapped accepted as IPv6 and
  canonicalized; the firewall policy only bans IPv4 so mapped forms cannot
  smuggle an IPv4 ban past policy).
- Coraza parser: hostile IPs (``8.8.8.8; rm -rf /``, ``999.999.999.999``),
  broken JSON, oversized payloads, and depth-beyond-limit documents all yield
  ``None`` without raising.
"""

import json

from hypothesis import HealthCheck, given, settings, strategies as st

from ed_bt_ade.parsing import MAX_CORAZA_JSON_DEPTH, parse_coraza_audit_line
from ed_bt_ade.validation import ValidationError, parse_ip, parse_network


# --- Strategies -------------------------------------------------------------

text_strategy = st.text(
    alphabet=st.characters(min_codepoint=0, max_codepoint=0x10FFFF),
    max_size=256,
)

# IPv4-ish strings: octets, leading zeros, out-of-range values, junk.
ipv4_like = st.builds(
    lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
    st.integers(min_value=0, max_value=300),
    st.integers(min_value=-5, max_value=300),
    st.integers(min_value=0, max_value=300),
    st.integers(min_value=0, max_value=300),
).filter(lambda s: True)

# Real IPv4 addresses, including edge values.
real_ipv4 = st.builds(
    lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
)

# IPv6 forms including edge cases and mixed case.
real_ipv6 = st.sampled_from([
    "::", "::1", "2001:db8::1", "FE80::1", "fe80:0:0:0:0:0:0:1",
    "::ffff:192.168.1.1", "2001:DB8:ABCD:0012:0000:0000:0000:0001",
    "64:ff9b::1.2.3.4", "fc00::7", "ff02::1", "100::1",
])

# Simple Coraza-audit-like JSON documents (possibly broken).
coraza_jsonish = st.one_of(
    st.builds(lambda ip: json.dumps({"transaction": {"client_ip": ip}}), text_strategy),
    st.builds(
        lambda ip, score: json.dumps(
            {"transaction": {"client_ip": ip}, "anomaly_score": score}),
        text_strategy, st.integers(min_value=-1000, max_value=1000),
    ),
    st.builds(
        lambda ip, rules: json.dumps(
            {"client_ip": ip, "rule_ids": rules}),
        text_strategy,
        st.lists(st.one_of(st.integers(), text_strategy), max_size=40),
    ),
    text_strategy,  # arbitrary garbage that may or may not parse
)


# --- parse_ip / parse_network properties ------------------------------------

class TestParseIpProperties:
    @settings(max_examples=200, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    @given(text_strategy)
    def test_parse_ip_never_crashes(self, value: str) -> None:
        """parse_ip either returns a canonical address or raises ValidationError."""
        try:
            network = parse_ip(value)
        except ValidationError:
            return
        # Accepted values must be canonical (str() round-trips exactly) and
        # the original input must not contain whitespace tricks.
        assert str(network) == str(parse_ip(str(network)))
        assert value.strip() == value
        assert "\x00" not in value

    @settings(max_examples=200, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    @given(real_ipv4)
    def test_valid_ipv4_accepted_canonically(self, value: str) -> None:
        network = parse_ip(value)
        assert network.version == 4
        assert str(network) == str(__import__("ipaddress").ip_address(value))

    @settings(max_examples=100, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    @given(real_ipv6)
    def test_ipv6_edge_cases_never_crash(self, value: str) -> None:
        try:
            parse_ip(value)
        except ValidationError:
            pass  # versions may restrict to IPv4; defined outcome either way

    @settings(max_examples=200, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    @given(ipv4_like)
    def test_noncanonical_octets_rejected(self, value: str) -> None:
        """Out-of-range octets must never be accepted."""
        octets = value.split(".")
        try:
            numbers = [int(o) for o in octets]
        except ValueError:
            return
        if any(n < 0 or n > 255 for n in numbers):
            try:
                parse_ip(value)
            except ValidationError:
                return
            raise AssertionError(f"parse_ip accepted out-of-range octets: {value}")

    @settings(max_examples=100, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    @given(text_strategy)
    def test_parse_network_never_crashes(self, value: str) -> None:
        try:
            parse_network(value)
        except ValidationError:
            return


# --- parse_coraza_audit_line fuzz --------------------------------------------

class TestCorazaParserProperties:
    @settings(max_examples=200, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    @given(coraza_jsonish)
    def test_coraza_parser_never_crashes(self, line: str) -> None:
        """The audit parser returns Detection or None — never raises."""
        result = parse_coraza_audit_line(line)
        if result is not None:
            assert result.ip is not None
            assert result.source == "coraza_audit"
            assert result.score >= 1

    @settings(max_examples=100, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    @given(st.lists(st.text(max_size=64), max_size=64))
    def test_deep_nesting_is_bounded(self, items) -> None:
        """Deeply nested documents are rejected, not crashed on."""
        document: dict = {"client_ip": "8.8.8.8"}
        for _ in range(MAX_CORAZA_JSON_DEPTH + 8):
            document = {"child": document}
        assert parse_coraza_audit_line(json.dumps(document)) is None
