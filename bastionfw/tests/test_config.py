import json
import tempfile
import unittest
from pathlib import Path

from ed_bt_ade.config import ConfigError, load_config


class ConfigTests(unittest.TestCase):
    def test_loads_json_and_environment_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({
                "log_sources": [{"name": "test", "path": "/tmp/test.log"}],
                "firewall": {"enabled": True, "backend": "dry-run"}
            }))
            config = load_config(path, {"ED_BT_ADE_DRY_RUN": "true"})
            self.assertFalse(config.firewall.enabled)
            self.assertEqual(config.log_sources[0].name, "test")

    def test_rejects_empty_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"log_sources": []}')
            with self.assertRaises(ConfigError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
