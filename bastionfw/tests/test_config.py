import json
import tempfile
import unittest
from pathlib import Path

from ed_bt_ade.config import ConfigError, load_config


class ConfigTests(unittest.TestCase):
    def _write(self, directory: str, document: dict[str, object]) -> Path:
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(document))
        return path

    def test_loads_json_and_environment_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, {
                "log_sources": [{"name": "test", "path": "/tmp/test.log"}],
                "firewall": {"enabled": True, "backend": "dry-run"}
            })
            config = load_config(path, {"ED_BT_ADE_DRY_RUN": "true"})
            self.assertFalse(config.firewall.enabled)
            self.assertEqual(config.log_sources[0].name, "test")

    def test_rejects_empty_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, {"log_sources": []})
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_coraza_audit_source_type_is_validated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, {
                "log_sources": [
                    {"name": "plain", "path": "/tmp/a.log"},
                    {"name": "coraza_waf", "path": "/tmp/audit.json",
                     "source_type": "coraza_audit"},
                ],
            })
            config = load_config(path)
            plain, coraza = config.log_sources
            self.assertFalse(plain.is_coraza_audit)
            self.assertTrue(coraza.is_coraza_audit)
            with tempfile.TemporaryDirectory() as other:
                invalid = self._write(other, {
                    "log_sources": [{"name": "x", "path": "/tmp/a.log",
                                      "source_type": "kafka"}],
                })
                with self.assertRaises(ConfigError):
                    load_config(invalid)

    def test_waf_section_and_environment_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, {
                "log_sources": [{"name": "test", "path": "/tmp/test.log"}],
                "waf": {"mode": "detect", "data_dir": "./state/waf"},
            })
            config = load_config(path)
            self.assertFalse(config.waf.enabled)
            self.assertEqual(config.waf.mode, "detect")
            config = load_config(path, {
                "ED_BT_ADE_WAF_ENABLED": "true",
                "ED_BT_ADE_WAF_MODE": "block",
            })
            self.assertTrue(config.waf.enabled)
            self.assertEqual(config.waf.mode, "block")
            self.assertEqual(config.waf.data_dir, Path("./state/waf"))
            with self.assertRaises(ConfigError):
                load_config(path, {"ED_BT_ADE_WAF_MODE": "ban"})


if __name__ == "__main__":
    unittest.main()
