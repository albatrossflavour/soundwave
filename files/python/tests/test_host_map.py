"""Run from files/python with: python3 -m pytest tests -q"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lib.host_map import apply_host_map, load_host_map  # noqa: E402


def _hosts():
    return [
        {"hostname": "puppet.example.com", "ipaddress": "192.0.2.10", "vulnerabilities": []},
        {"hostname": "192.0.2.1", "ipaddress": "192.0.2.1", "vulnerabilities": []},
        {"hostname": "old-dns-name.example.com", "ipaddress": "192.0.2.13", "vulnerabilities": []},
    ]


def _file(content):
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    with handle:
        handle.write(content)
    return handle.name


class LoadHostMapTest(unittest.TestCase):
    def test_no_path_means_no_map(self):
        self.assertIsNone(load_host_map(""))

    def test_reads_an_object(self):
        path = _file(json.dumps({"192.0.2.13": "dashboard.example.com"}))
        self.addCleanup(os.remove, path)
        self.assertEqual(load_host_map(path), {"192.0.2.13": "dashboard.example.com"})

    def test_missing_or_broken_file_falls_back(self):
        path = _file("{not json")
        self.addCleanup(os.remove, path)
        with self.assertLogs("transformer", "ERROR"):
            self.assertIsNone(load_host_map(path))
        with self.assertLogs("transformer", "ERROR"):
            self.assertIsNone(load_host_map("/nonexistent/scan-hosts.json"))

    def test_not_an_object(self):
        path = _file('["192.0.2.13"]')
        self.addCleanup(os.remove, path)
        with self.assertLogs("transformer", "ERROR"):
            self.assertIsNone(load_host_map(path))


class ApplyHostMapTest(unittest.TestCase):
    def test_no_map_changes_nothing(self):
        self.assertEqual(apply_host_map(_hosts(), None), _hosts())

    def test_known_addresses_take_the_certname(self):
        mapping = {"192.0.2.10": "puppet.example.com", "192.0.2.13": "dashboard.example.com"}
        with self.assertLogs("transformer", "INFO") as logs:
            hosts = apply_host_map(_hosts(), mapping)
        self.assertEqual(
            [h["hostname"] for h in hosts],
            ["puppet.example.com", "192.0.2.1", "dashboard.example.com"],
        )
        self.assertIn("Named 2 of 3 host(s) by certname", "\n".join(logs.output))

    def test_unknown_address_is_logged(self):
        with self.assertLogs("transformer", "WARNING") as logs:
            apply_host_map(_hosts(), {"192.0.2.10": "puppet.example.com"})
        warnings = [line for line in logs.output if line.startswith("WARNING")]
        self.assertEqual(len(warnings), 2)
        self.assertIn("192.0.2.1", warnings[0])


if __name__ == "__main__":
    unittest.main()
