"""The adapter that WS1 patch 0001 calls from Runtime.scan — tested directly, so the
policy is proven even before WS1 merges the patch. SYNTHETIC TEST FIXTUREs only."""
from __future__ import annotations

import unittest

from backend.tests.ws2 import helpers
from backend.app.core import scorer as ws1_scorer


def ws1_scan(kind: str, value: str) -> dict:
    return ws1_scorer.score_request(kind, value, "en", **helpers.catalog().scoring_kwargs())


class TestApplyToScanResult(unittest.TestCase):
    def setUp(self):
        self.shield = helpers.scorer()

    def apply(self, kind, value):
        base = ws1_scan(kind, value)
        out = self.shield.apply_to_scan_result(dict(base), kind=kind, input_value=value)
        for key in base:  # WS1 fields are never modified
            self.assertEqual(out[key], base[key], key)
        return out

    def test_unknown_url_becomes_warning(self):
        out = self.apply("url", "https://plain-unknown-site.example/")
        self.assertEqual((out["verdict"], out["tag"]), ("UNKNOWN", "WARNING"))

    def test_authenticated_url_can_be_safe(self):
        self.assertEqual(self.apply("url", "https://police.gov.example/")["tag"], "SAFE")

    def test_ws1_brand_allowlisted_bank_is_not_safe_without_registry(self):
        out = self.apply("url", "https://adcb.ae/login")
        self.assertEqual(out["verdict"], "UNKNOWN")  # WS1 allowlist: no impersonation signals
        self.assertEqual(out["tag"], "WARNING")      # …but not an authenticated official source

    def test_malicious_url_is_fake(self):
        self.assertEqual(self.apply("url", "https://adcb-secure-login.xyz/login")["tag"], "FAKE")

    def test_text_with_contradicted_claim(self):
        out = self.apply("text", "Synthetic Police: your bank account is frozen due to unpaid traffic fines. Pay at https://pay-now.example")
        self.assertEqual(out["gov_verification"]["status"], "CONTRADICTED")
        self.assertEqual(out["tag"], "MISLEADING")

    def test_numbers_never_safe(self):
        self.assertEqual(self.apply("number", "+971 4 123 4567")["tag"], "WARNING")
        self.assertEqual(self.apply("number", "+971900000042")["tag"], "FAKE")

    def test_text_without_link(self):
        out = self.apply("text", "hello, see you tomorrow")
        self.assertEqual(out["domain_auth"]["status"], "NOT_CHECKABLE")
        self.assertEqual(out["tag"], "WARNING")


if __name__ == "__main__":
    unittest.main()
