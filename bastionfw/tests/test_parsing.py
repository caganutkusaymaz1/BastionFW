import unittest

from ed_bt_ade.parsing import extract_remote_ip, normalize_for_detection


class ParsingTests(unittest.TestCase):
    def test_json_and_journal_ip_extraction(self) -> None:
        self.assertEqual(extract_remote_ip('{"remote_addr":"198.51.100.7"}'),
                         "198.51.100.7")
        self.assertEqual(extract_remote_ip('{"MESSAGE":"failed from 198.51.100.8"}'),
                         "198.51.100.8")

    def test_double_encoded_payload_is_normalized(self) -> None:
        self.assertIn("union select", normalize_for_detection("union%2520select"))


if __name__ == "__main__":
    unittest.main()