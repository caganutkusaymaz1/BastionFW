"""Static checks for the deploy/waf Coraza WAF layer.

The stock ``corazawaf/coraza-caddy:v2`` image bakes a static example
Caddyfile and has no ``UPSTREAM_URL`` / ``WAF_MODE`` handling, so BastionFW
ships its own ``deploy/waf`` build (Caddyfile + entrypoint + Dockerfile).
These tests verify that contract without requiring Docker or the network.
"""

import unittest
from pathlib import Path

_WAF_DIR = Path(__file__).resolve().parents[2] / "deploy" / "waf"
CADDYFILE = _WAF_DIR / "Caddyfile"
ENTRYPOINT = _WAF_DIR / "entrypoint.sh"
DOCKERFILE = _WAF_DIR / "Dockerfile"
COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"


@unittest.skipUnless(_WAF_DIR.is_dir(), "deploy/waf not present in this checkout")
class WafDeployConfigTests(unittest.TestCase):
    def test_caddyfile_uses_env_upstream_and_engine_placeholders(self) -> None:
        document = CADDYFILE.read_text(encoding="utf-8")
        self.assertIn("{$UPSTREAM_URL}", document)
        self.assertIn("{$WAF_ENGINE}", document)
        # Default must fail safe: no hardcoded enforcement.
        self.assertNotIn("SecRuleEngine On", document)

    def test_caddyfile_loads_owasp_crs_and_writes_json_audit(self) -> None:
        document = CADDYFILE.read_text(encoding="utf-8")
        self.assertIn("load_owasp_crs", document)
        self.assertIn("SecAuditLog /var/log/waf/audit.json", document)
        self.assertIn("SecAuditLogFormat json", document)
        self.assertIn("Include @owasp_crs/*.conf", document)

    def test_entrypoint_maps_detect_and_block_modes(self) -> None:
        document = ENTRYPOINT.read_text(encoding="utf-8")
        self.assertIn('ENGINE="DetectionOnly"', document)
        self.assertIn('ENGINE="On"', document)
        self.assertIn('WAF_MODE must be', document)

    def test_dockerfile_builds_caddy_with_coraza_from_official_builder(self) -> None:
        document = DOCKERFILE.read_text(encoding="utf-8")
        # The Coraza module ships as a Go plugin; build it from Caddy's
        # official builder image rather than a non-existent stock image.
        self.assertIn("FROM caddy:2.11.4-builder AS builder", document)
        self.assertIn("--with github.com/corazawaf/coraza-caddy/v2", document)
        # The old, non-existent base image must not be used as a FROM.
        self.assertNotIn("FROM corazawaf/coraza-caddy", document)
        self.assertIn("Caddyfile.bastionfw", document)
        self.assertIn("bastionfw-waf-entrypoint.sh", document)

    def test_compose_waf_service_builds_from_deploy_waf(self) -> None:
        document = COMPOSE.read_text(encoding="utf-8")
        self.assertIn("context: ./deploy/waf", document)
        # The stock image line must be gone: it cannot honor our env contract.
        self.assertNotIn("image: corazawaf/coraza-caddy:v2", document)


if __name__ == "__main__":
    unittest.main()
