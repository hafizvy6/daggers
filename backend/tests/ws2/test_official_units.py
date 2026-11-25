"""Unit tests: normalization, registry, extraction, CLI. SYNTHETIC TEST FIXTUREs only."""
from __future__ import annotations

import copy
import io
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import timedelta
from pathlib import Path

import yaml

from backend.tests.ws2 import helpers
from backend.app.channels.official import normalize
from backend.app.channels.official.cli import main as cli_main
from backend.app.channels.official.extract import extract_claim
from backend.app.channels.official.registry import (
    DEFAULT_REGISTRY_PATH,
    Registry,
    RegistryError,
    parse_target,
    validate_entries,
)


class TestNormalize(unittest.TestCase):
    def test_arabic_diacritics_tatweel_alef_ya_digits(self):
        self.assertEqual(normalize.normalize_arabic("مُـــحَمَّد"), "محمد")
        self.assertEqual(normalize.normalize_arabic("أإآٱ"), "اااا")
        self.assertEqual(normalize.normalize_arabic("على"), "علي")
        self.assertEqual(normalize.normalize_digits("٠١٢٣٤٥٦٧٨٩ ۱۲"), "0123456789 12")
        self.assertEqual(normalize.match_key("الإقامة"), normalize.match_key("الاقامه"))

    def test_amounts_to_aed(self):
        amounts = {a.aed for a in normalize.extract_amounts("Pay AED 1,150 or ١٥٠ درهم, prize 1 million dirhams")}
        self.assertEqual(amounts, {1150.0, 150.0, 1_000_000.0})
        usd = normalize.extract_amounts("fee of USD 100")[0]
        self.assertTrue(usd.converted)
        self.assertAlmostEqual(usd.aed, 367.25)
        self.assertEqual({a.aed for a in normalize.extract_amounts("جائزة مليون درهم")}, {1_000_000.0})
        self.assertEqual(normalize.extract_amounts("Dhs5k cashback")[0].aed, 5000.0)

    def test_bilingual_dates(self):
        self.assertEqual(normalize.extract_dates("until 31 December 2026"), ["2026-12-31"])
        self.assertEqual(normalize.extract_dates("December 2, 2026"), ["2026-12-02"])
        self.assertEqual(normalize.extract_dates("حتى ٣١ ديسمبر ٢٠٢٦"), ["2026-12-31"])
        self.assertEqual(normalize.extract_dates("deadline 05/01/2027"), ["2027-01-05"])  # day-first
        self.assertEqual(normalize.extract_dates("bad 31/02/2026"), [])

    def test_proclitic_tolerant_phrase_match(self):
        key = normalize.match_key("وبالإقامة الذهبية")
        self.assertTrue(normalize.contains_phrase(normalize.match_key("والإقامة"), "اقامة"))
        self.assertFalse(normalize.contains_phrase(key, "visa"))


class TestRegistry(unittest.TestCase):
    def setUp(self):
        self.reg = helpers.synthetic_registry()

    def test_production_registry_validates_and_is_all_pending(self):
        reg = Registry.load()
        self.assertTrue(reg.entries)
        self.assertTrue(all(e.status == "pending" for e in reg.entries))
        self.assertTrue(all(e.reviewer is None and e.verified_at is None for e in reg.entries))
        self.assertEqual(reg.trusted(helpers.NOW), [])
        domains = {d for e in reg.entries for d in e.domains}
        self.assertTrue({"u.ae", "uaepass.ae", "mediaoffice.abudhabi"} <= domains)

    def test_production_registry_never_authenticates_while_pending(self):
        reg = Registry.load()
        for url in ("https://u.ae/en", "https://www.adpolice.gov.ae/", "https://mediaoffice.abudhabi/"):
            self.assertEqual(reg.authenticate(url, helpers.NOW).status, "PENDING")
        self.assertEqual(reg.authenticate("https://random.gov.ae/", helpers.NOW).status, "UNLISTED")

    def test_gov_ae_suffix_alone_is_never_trusted(self):
        bad = copy.deepcopy(self.reg.raw["entries"][0])
        bad.update({"id": "bad-suffix", "domains": ["gov.ae"], "synthetic": False, "jurisdiction": "federal"})
        report = validate_entries([bad])
        self.assertFalse(report.ok)
        self.assertTrue(any("public suffix" in e for e in report.errors))

    def test_validation_rejects_malformed_entries(self):
        base = copy.deepcopy(self.reg.raw["entries"][0])
        cases = {
            "duplicate domain": [base, {**copy.deepcopy(base), "id": "other"}],
            "bad class": [{**copy.deepcopy(base), "source_class": "Z"}],
            "http source": [{**copy.deepcopy(base), "source_urls": ["http://police.gov.example/"]}],
            "off-domain source": [{**copy.deepcopy(base), "source_urls": ["https://elsewhere.example/"]}],
            "wildcard": [{**copy.deepcopy(base), "domains": ["*.police.gov.example"]}],
            "uppercase": [{**copy.deepcopy(base), "domains": ["Police.gov.example"]}],
            "class C scope": [{**copy.deepcopy(base), "source_class": "C"}],
            "synthetic in prod": [base],
        }
        for name, entries in cases.items():
            with self.subTest(name):
                report = validate_entries(entries, allow_synthetic=(name != "synthetic in prod"))
                self.assertFalse(report.ok, name)

    def test_homograph_and_tricky_hosts_are_not_authenticated(self):
        auth = self.reg.authenticate
        self.assertEqual(auth("https://pоlice.gov.example/", helpers.NOW).status, "UNLISTED")  # Cyrillic о
        self.assertEqual(auth("https://police.gov.example.evil.example/", helpers.NOW).status, "UNLISTED")
        self.assertEqual(auth("https://police.gov.example@evil.example/", helpers.NOW).status, "NOT_CHECKABLE")
        self.assertEqual(auth("http://police.gov.example/", helpers.NOW).status, "NOT_CHECKABLE")
        self.assertEqual(auth("https://police.gov.example:8443/", helpers.NOW).status, "NOT_CHECKABLE")
        self.assertEqual(auth("https://10.0.0.1/", helpers.NOW).status, "NOT_CHECKABLE")
        self.assertEqual(auth("javascript:alert(1)", helpers.NOW).status, "NOT_CHECKABLE")
        self.assertEqual(auth("https://POLICE.gov.example./", helpers.NOW).status, "AUTHENTICATED")
        self.assertEqual(parse_target("")[1], "empty URL")

    def test_approval_freshness_window(self):
        entry = self.reg.by_id["syn-police"]
        self.assertTrue(entry.is_trusted(helpers.NOW))
        self.assertFalse(entry.is_trusted(helpers.NOW + timedelta(days=200)))

    def test_entity_resolution_en_ar(self):
        ids = [e.id for e in self.reg.resolve_entities("بيان من هيئة الإقامة التجريبية")]
        self.assertEqual(ids, ["syn-residency"])
        ids = [e.id for e in self.reg.resolve_entities("SIRA statement")]
        self.assertEqual(ids, ["syn-residency"])

    def test_class_c_mention_is_not_the_claimed_entity(self):
        claim = extract_claim("Synthetic Daily reports Synthetic Police warns of fines", self.reg, helpers.lexicon())
        self.assertEqual(claim.entity_ids, ("syn-police",))

    def test_approve_without_a_name_and_refuses_synthetic(self):
        with self.assertRaises(RegistryError):
            self.reg.approved_mapping("syn-pending", None, helpers.NOW)
        prod = Registry.load()
        data = prod.approved_mapping("wam", None, helpers.NOW)          # no name: only "approved" + date
        entry = next(e for e in data["entries"] if e["id"] == "wam")
        assert entry["status"] == "approved" and entry["reviewer"] is None and entry["verified_at"]
        approved = Registry.from_mapping(data)
        assert approved.authenticate("https://www.wam.ae/en", helpers.NOW).status == "AUTHENTICATED"


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.path = self.tmp / "registry.yaml"
        shutil.copy(DEFAULT_REGISTRY_PATH, self.path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, *args) -> tuple[int, str]:
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli_main(["--registry", str(self.path), *args])
        return code, out.getvalue()

    def test_validate_list_approve_revoke_cycle(self):
        self.assertEqual(self.run_cli("validate")[0], 0)
        code, out = self.run_cli("list", "--status", "pending")
        self.assertEqual(code, 0)
        self.assertIn("wam", out)
        code, _ = self.run_cli("approve", "wam", "--reviewer", "Test Reviewer", "--yes")
        self.assertEqual(code, 0)
        reg = Registry.load(self.path)
        self.assertEqual(reg.by_id["wam"].status, "approved")
        self.assertEqual(reg.by_id["wam"].reviewer, "Test Reviewer")
        self.assertIsNotNone(reg.by_id["wam"].verified_at)
        now = helpers.models_now()
        self.assertEqual(reg.authenticate("https://www.wam.ae/en", now).status, "AUTHENTICATED")
        self.assertEqual(self.run_cli("revoke", "wam", "--reviewer", "Test Reviewer", "--reason", "test")[0], 0)
        reg = Registry.load(self.path)
        self.assertEqual(reg.authenticate("https://www.wam.ae/en", now).status, "REVOKED")
        # Only wam changed.
        others = [e for e in reg.entries if e.id != "wam"]
        self.assertTrue(all(e.status == "pending" for e in others))

    def test_approve_without_confirmation_aborts(self):
        import builtins
        original = builtins.input
        builtins.input = lambda *_: "no"
        try:
            code, out = self.run_cli("approve", "wam", "--reviewer", "Test Reviewer")
        finally:
            builtins.input = original
        self.assertEqual(code, 1)
        self.assertEqual(Registry.load(self.path).by_id["wam"].status, "pending")

    def test_invalid_registry_is_never_written(self):
        data = yaml.safe_load(self.path.read_text(encoding="utf-8"))
        data["entries"][0]["domains"] = ["gov.ae"]
        self.path.write_text(yaml.safe_dump(data), encoding="utf-8")
        self.assertEqual(self.run_cli("validate")[0], 1)
        before = self.path.read_text(encoding="utf-8")
        self.assertEqual(self.run_cli("approve", "wam", "--reviewer", "R1", "--yes")[0], 1)
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)

    def test_authenticate_command(self):
        code, out = self.run_cli("authenticate", "https://example.com")
        self.assertEqual(code, 0)
        self.assertIn("UNLISTED", out)


if __name__ == "__main__":
    unittest.main()
