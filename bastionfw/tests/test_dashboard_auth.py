import unittest

from ed_bt_ade.dashboard import (
    LOOPBACK_HOST,
    is_authorized,
    resolve_bind_host,
    resolve_dashboard_token,
)


class DashboardAuthTests(unittest.TestCase):
    def test_token_resolution_trims_and_bounds(self) -> None:
        self.assertIsNone(resolve_dashboard_token({}))
        self.assertIsNone(resolve_dashboard_token({"ED_BT_ADE_DASHBOARD_TOKEN": "   "}))
        self.assertIsNone(resolve_dashboard_token(
            {"ED_BT_ADE_DASHBOARD_TOKEN": "x" * 513}))
        self.assertEqual(resolve_dashboard_token(
            {"ED_BT_ADE_DASHBOARD_TOKEN": "  secret  "}), "secret")

    def test_missing_token_authorizes_only_in_fail_safe_mode(self) -> None:
        # token=None means auth is disabled; binding logic must compensate.
        self.assertTrue(is_authorized(None, None))
        self.assertFalse(is_authorized(None, "secret"))
        self.assertFalse(is_authorized("Bearer wrong", "secret"))
        self.assertFalse(is_authorized("Basic c2VjcmV0", "secret"))
        self.assertFalse(is_authorized("Bearer", "secret"))
        self.assertTrue(is_authorized("Bearer secret", "secret"))

    def test_bearer_comparison_is_exact_and_constant_time(self) -> None:
        self.assertTrue(is_authorized("Bearer token-123", "token-123"))
        self.assertFalse(is_authorized("Bearer token-124", "token-123"))
        self.assertFalse(is_authorized("Bearer token-123 ", "token-123"))
        # Scheme match is case-insensitive per RFC 7235; the token is not.
        self.assertTrue(is_authorized("bearer token-123", "token-123"))
        self.assertFalse(is_authorized("Bearer TOKEN-123", "token-123"))
        # Oversized payloads are rejected before comparison.
        self.assertFalse(is_authorized("Bearer " + "a" * 600, "a" * 512))

    def test_fail_safe_bind_without_token(self) -> None:
        self.assertEqual(resolve_bind_host("0.0.0.0", None), LOOPBACK_HOST)
        self.assertEqual(resolve_bind_host("::", None), LOOPBACK_HOST)
        self.assertEqual(resolve_bind_host("192.0.2.7", None), LOOPBACK_HOST)
        # Loopback requests stay loopback.
        self.assertEqual(resolve_bind_host("127.0.0.1", None), LOOPBACK_HOST)
        self.assertEqual(resolve_bind_host("localhost", None), "localhost")

    def test_token_allows_requested_bind_host(self) -> None:
        self.assertEqual(resolve_bind_host("0.0.0.0", "secret"), "0.0.0.0")
        self.assertEqual(resolve_bind_host("127.0.0.1", "secret"), "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
