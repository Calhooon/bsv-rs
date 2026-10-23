"""Regression witnesses for skipped pins and a silently unused Cargo patch."""

from pathlib import Path
import unittest

from dependents import admits, verify_resolution


class Requirements(unittest.TestCase):
    def test_exact_cli_pin_does_not_admit_the_patch_release(self):
        self.assertFalse(admits("=0.8.1", "0.8.2"))

    def test_caret_pins_admit_only_their_compatible_line(self):
        for requirement in ("0.8", "0.8.0", "^0.8.1"):
            self.assertTrue(admits(requirement, "0.8.2"))
            self.assertFalse(admits(requirement, "0.9.0"))
            self.assertFalse(admits(requirement, "0.8.2-beta.1"))

    def test_older_consumers_wait_for_their_captains(self):
        for requirement in ("=0.4.5", "0.5.0", "0.6.0", "0.7", "=0.7.2"):
            self.assertFalse(admits(requirement, "0.8.2"))

    def test_partial_and_zero_caret_bounds(self):
        self.assertTrue(admits("1", "1.9.3"))
        self.assertFalse(admits("1", "2.0.0"))
        self.assertTrue(admits("0.0", "0.0.9"))
        self.assertFalse(admits("0.0.1", "0.0.2"))
        self.assertTrue(admits("=0.8", "0.8.9"))

    def test_beta_requires_an_explicit_exact_pin(self):
        self.assertTrue(admits("=0.9.0-beta.2", "0.9.0-beta.2"))
        self.assertFalse(admits("=0.9.0-beta.1", "0.9.0-beta.2"))

    def test_unrecognized_requirement_fails_closed(self):
        with self.assertRaises(ValueError):
            admits(">=0.8, <0.9", "0.8.2")
        with self.assertRaises(ValueError):
            admits("^0.9.0-beta.1", "0.9.0-beta.2")


class Resolution(unittest.TestCase):
    def graph(self, sdk_manifest, source):
        return {
            "packages": [
                {"id": "consumer", "name": "consumer", "manifest_path": "/consumer/Cargo.toml"},
                {"id": "sdk", "name": "bsv-rs", "version": "0.8.2", "manifest_path": sdk_manifest, "source": source},
            ],
            "resolve": {"nodes": [{"id": "consumer", "deps": [{"name": "bsv_sdk", "pkg": "sdk"}]}]},
        }

    def test_alias_resolves_to_the_pr_tree(self):
        verify_resolution(self.graph("/sdk/Cargo.toml", None), Path("/consumer/Cargo.toml"), "bsv-sdk", Path("/sdk"))

    def test_unused_patch_cannot_report_success(self):
        with self.assertRaisesRegex(ValueError, "path override was not selected"):
            verify_resolution(self.graph("/registry/Cargo.toml", "registry"), Path("/consumer/Cargo.toml"), "bsv-sdk", Path("/sdk"))


if __name__ == "__main__":
    unittest.main()
