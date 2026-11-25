"""The 14 required scenarios. SYNTHETIC TEST FIXTUREs on .example domains only.

Every test asserts four separate layers:
  1. domain authentication   2. claim verification
  3. maliciousness evidence   4. final tag
"""
from __future__ import annotations

import unittest

from backend.tests.ws2 import helpers


class Scenario(unittest.TestCase):
    def assess(self, url: str, text: str | None = None, records=None, context=None) -> dict:
        return helpers.scorer(records).assess_url(url, text=text, context=context)

    def layers(self, result: dict, *, auth: str, claim: str | None, ws1: str, tag: str) -> None:
        self.assertEqual(result["domain_auth"]["status"], auth, result["trust_reasons"])
        gov = result["gov_verification"]
        self.assertEqual(gov["status"] if gov else None, claim, gov and gov["notes"])
        self.assertEqual(result["verdict"], ws1, result["reasons"])
        self.assertEqual(result["tag"], tag, result["trust_reasons"])


class TestFourteenScenarios(Scenario):
    def test_01_claim_matches_current_approved_class_a_source(self):
        r = self.assess(
            "https://www.sira.gov.example/fees",
            "Synthetic Residency Authority announces the golden visa renewal fee of AED 1,150.",
        )
        self.layers(r, auth="AUTHENTICATED", claim="VERIFIED", ws1="MISLEADING", tag="SAFE")
        decisive = [e for e in r["gov_verification"]["evidence"] if e["role"] == "decisive"]
        self.assertEqual(decisive[0]["source_class"], "A")
        self.assertTrue(r["gov_verification"]["evidence_id"].startswith("gv_"))

    def test_02_fake_government_giveaway_contradicted(self):
        r = self.assess(
            "https://moss-national-day-gift.example/claim",
            "Synthetic Ministry of Social Support is giving away AED 10,000 to every family for National Day. "
            "Claim your prize now.",
        )
        self.layers(r, auth="UNLISTED", claim="CONTRADICTED", ws1="MISLEADING", tag="MISLEADING")
        self.assertFalse(r["blockable"])

    def test_03_fake_police_warning(self):
        r = self.assess(
            "https://police-fines-pay.example/unblock",
            "Synthetic Police: your bank account is frozen due to unpaid traffic fines. Pay AED 500 now.",
        )
        self.layers(r, auth="UNLISTED", claim="CONTRADICTED", ws1="MISLEADING", tag="MISLEADING")
        self.assertIn("contradicted", " ".join(r["trust_reasons"]))

    def test_04_false_immigration_announcement(self):
        r = self.assess(
            "https://visa-amnesty-register.example/",
            "SIRA announces visa amnesty for overstayers until 31 December 2026. Register today.",
        )
        self.layers(r, auth="UNLISTED", claim="CONTRADICTED", ws1="UNKNOWN", tag="MISLEADING")

    def test_05_false_financial_aid_announcement(self):
        r = self.assess(
            "https://moss-support-apply.example/",
            "Synthetic Ministry of Social Support announces an unemployment grant of AED 5,000 for all residents.",
        )
        self.layers(r, auth="UNLISTED", claim="CONTRADICTED", ws1="MISLEADING", tag="MISLEADING")
        details = " ".join(e["detail"] for e in r["gov_verification"]["evidence"])
        self.assertIn("amount differs", details)

    def test_06_fee_contradicted_by_official_fee_schedule(self):
        r = self.assess(
            "https://cheap-visa-renewal.example/pay",
            "Synthetic Residency Authority: golden visa renewal fee is now only AED 99.",
        )
        self.layers(r, auth="UNLISTED", claim="CONTRADICTED", ws1="MISLEADING", tag="MISLEADING")

    def test_07_legitimate_private_business_not_in_registry(self):
        r = self.assess("https://sunrise-bakery.example/", "Fresh bread daily. Open from 7am.")
        self.layers(r, auth="UNLISTED", claim=None, ws1="UNKNOWN", tag="WARNING")
        self.assertNotEqual(r["tag"], "FAKE")
        self.assertFalse(r["blockable"])

    def test_08_official_government_media_announcement(self):
        r = self.assess(
            "https://news.gov.example/national-day",
            "Synthetic News Agency: the Synthetic Government announces National Day fireworks on 2 December 2026.",
        )
        # The typo heuristic flags 'news' ~ 'dewa' (distance 2): a domain-NAME signal only.
        # Registry authentication of this exact domain supersedes name heuristics.
        self.layers(r, auth="AUTHENTICATED", claim="VERIFIED", ws1="SUSPICIOUS", tag="SAFE")
        self.assertEqual(r["domain_auth"]["source_class"], "B")

    def test_08b_media_alone_cannot_validate_regulated_claim_when_authority_available(self):
        r = self.assess(
            "https://fines-discount-blog.example/",
            "Synthetic Transport Authority announces a 50% discount on traffic fines.",
        )
        self.layers(r, auth="UNLISTED", claim="NOT_VERIFIABLE", ws1="UNKNOWN", tag="MISLEADING")
        self.assertEqual(r["gov_verification"]["coverage"], "checked")

    def test_09_old_announcement_superseded_by_newer_source(self):
        r = self.assess(
            "https://old-fee-blog.example/",
            "Synthetic Residency Authority: the golden visa renewal fee is AED 1,000.",
        )
        self.layers(r, auth="UNLISTED", claim="CONTRADICTED", ws1="MISLEADING", tag="MISLEADING")
        roles = {e["role"] for e in r["gov_verification"]["evidence"]}
        self.assertIn("superseded", roles)

    def test_10_unavailable_official_source(self):
        records = helpers.synthetic_records(exclude=("r-parking-fee",))
        failed = helpers.OfficialRecord(
            "r-sta-down", "syn-transport", "https://sta.gov.example/news", "", "2026-11-24T11:00:00Z",
            fetch_status="error", fetch_error="timeout", synthetic=True,
        )
        r = self.assess(
            "https://parking-pay.example/",
            "Synthetic Transport Authority announces a parking fee of AED 4 per hour.",
            records=records + [failed],
        )
        self.layers(r, auth="UNLISTED", claim="SOURCE_UNAVAILABLE", ws1="UNKNOWN", tag="WARNING")
        self.assertTrue(r["manual_review"])
        self.assertIn("syn-transport", r["gov_verification"]["unchecked_sources"])
        self.assertTrue(any("not checked" in n for n in r["gov_verification"]["notes"]))

    def test_11_arabic_claim_matches_english_source(self):
        r = self.assess(
            "https://sira.gov.example/ar",
            "أعلنت هيئة الإقامة التجريبية أن رسوم تجديد الإقامة الذهبية ١١٥٠ درهم",
        )
        self.layers(r, auth="AUTHENTICATED", claim="VERIFIED", ws1="MISLEADING", tag="SAFE")
        self.assertEqual(r["gov_verification"]["claim"]["language"], "ar")
        self.assertEqual(r["gov_verification"]["claim"]["amounts_aed"], [1150.0])

    def test_12_conflicting_approved_sources(self):
        r = self.assess(
            "https://housing-grant-info.example/",
            "Synthetic Ministry of Social Support announces a housing grant of AED 50,000.",
        )
        self.layers(r, auth="UNLISTED", claim="CONFLICTING_SOURCES", ws1="MISLEADING", tag="MISLEADING")
        self.assertTrue(r["manual_review"])

    def test_13_cloned_government_media_page(self):
        # Cloned page impersonating a catalogued government brand, with clone evidence.
        r = self.assess(
            "https://dubaipolice-media.example/news",
            "Synthetic News Agency: the Synthetic Government announces National Day fireworks on 2 December 2026.",
            context={"clone_score": 96, "gallery_match": "news page"},
        )
        self.layers(r, auth="UNLISTED", claim="VERIFIED", ws1="MALICIOUS", tag="FAKE")
        self.assertTrue(r["blockable"])

    def test_13b_clone_without_malicious_evidence_is_not_auto_fake(self):
        r = self.assess(
            "https://synthetic-agency-mirror.example/story",
            "Synthetic News Agency: the Synthetic Government announces National Day fireworks on 2 December 2026.",
        )
        self.layers(r, auth="UNLISTED", claim="VERIFIED", ws1="UNKNOWN", tag="WARNING")

    def test_14_fraudulent_ugc_on_authenticated_official_domain(self):
        r = self.assess(
            "https://forum.portal.gov.example/thread/991",
            "Synthetic Ministry of Social Support is giving away AED 10,000 to every family. Claim your prize.",
        )
        # The scorer does not treat forum.portal.gov.example as a brand domain, so its claim rule fires.
        self.layers(r, auth="AUTHENTICATED", claim="CONTRADICTED", ws1="MISLEADING", tag="WARNING")
        self.assertTrue(r["manual_review"])
        self.assertFalse(r["blockable"])
        self.assertNotEqual(r["tag"], "FAKE")


class TestPolicyInvariants(Scenario):
    def test_unknown_domain_never_safe(self):
        self.assertEqual(self.assess("https://totally-unknown-site.example/")["tag"], "WARNING")

    def test_pending_domain_never_safe(self):
        r = self.assess("https://pending.gov.example/")
        self.assertEqual(r["domain_auth"]["status"], "PENDING")
        self.assertEqual(r["tag"], "WARNING")

    def test_revoked_domain_never_safe(self):
        r = self.assess("https://revoked.gov.example/")
        self.assertEqual(r["domain_auth"]["status"], "REVOKED")
        self.assertEqual(r["tag"], "WARNING")

    def test_expired_approval_never_safe(self):
        r = self.assess("https://expired.gov.example/")
        self.assertEqual(r["domain_auth"]["status"], "EXPIRED")
        self.assertEqual(r["tag"], "WARNING")

    def test_official_domain_without_suspicious_content_can_be_safe(self):
        r = self.assess("https://police.gov.example/")
        self.assertEqual(r["tag"], "SAFE")
        r = self.assess("https://www.police.gov.example/about", "Opening hours of our service centres.")
        self.assertEqual(r["tag"], "SAFE")

    def test_unlisted_subdomain_of_official_domain_not_authenticated(self):
        r = self.assess("https://evil.police.gov.example/")
        self.assertEqual(r["domain_auth"]["status"], "UNLISTED")
        self.assertNotEqual(r["tag"], "SAFE")

    def test_official_domain_with_suspicious_ugc_is_still_examined(self):
        r = self.assess(
            "https://forum.portal.gov.example/t/1",
            "Abu Dhabi bank is giving away 1 million dirhams, claim your prize",
        )
        self.assertEqual(r["domain_auth"]["status"], "AUTHENTICATED")
        self.assertEqual(r["tag"], "WARNING")
        self.assertTrue(r["manual_review"])

    def test_retrieval_failure_never_verified(self):
        failed = [
            helpers.OfficialRecord("x1", "syn-residency", "https://sira.gov.example/news", "",
                                   "2026-11-24T11:00:00Z", fetch_status="error", fetch_error="http_503")
        ]
        r = self.assess(
            "https://sira.gov.example/",
            "Synthetic Residency Authority announces the golden visa renewal fee of AED 1,150.",
            records=failed,
        )
        self.assertNotEqual(r["gov_verification"]["status"], "VERIFIED")
        self.assertEqual(r["gov_verification"]["status"], "SOURCE_UNAVAILABLE")
        self.assertNotEqual(r["tag"], "SAFE")

    def test_class_c_cannot_authenticate_or_verify(self):
        r = self.assess("https://syntheticdaily.example/story")
        self.assertEqual(r["domain_auth"]["status"], "INDEPENDENT_MEDIA")
        self.assertFalse(r["domain_auth"]["authenticated"])
        self.assertEqual(r["tag"], "WARNING")
        r = self.assess(
            "https://parking-news.example/",
            "Synthetic Transport Authority announces free parking on National Day.",
        )
        gov = r["gov_verification"]
        self.assertNotEqual(gov["status"], "VERIFIED")
        self.assertTrue(all(e["role"] == "supporting_context" for e in gov["evidence"] if e["source_class"] == "C"))

    def test_stale_evidence_gives_source_expired(self):
        stale = [
            helpers.OfficialRecord("s1", "syn-transport", "https://sta.gov.example/news/s1",
                                   "SYNTHETIC TEST FIXTURE. parking fee AED 4 per hour.",
                                   "2026-08-01T00:00:00Z", synthetic=True)
        ]
        r = self.assess("https://parking.example/", "Synthetic Transport Authority announces a parking fee of AED 4 per hour.",
                        records=stale)
        self.assertEqual(r["gov_verification"]["status"], "SOURCE_EXPIRED")
        self.assertEqual(r["tag"], "WARNING")

    def test_record_from_outside_entry_domains_is_ignored(self):
        spoofed = [
            helpers.OfficialRecord("sp", "syn-residency", "https://sira-gov.example/news",
                                   "SYNTHETIC TEST FIXTURE. golden visa renewal fee is AED 99.",
                                   "2026-11-20T00:00:00Z", synthetic=True)
        ]
        r = self.assess("https://x.example/", "Synthetic Residency Authority: golden visa renewal fee AED 99", records=spoofed)
        self.assertNotEqual(r["gov_verification"]["status"], "VERIFIED")
        self.assertTrue(any("outside" in n for n in r["gov_verification"]["notes"]))

    def test_evidence_id_is_deterministic_and_versioned(self):
        a = self.assess("https://a.example/", "Synthetic Residency Authority announces the golden visa renewal fee of AED 1,150.")
        b = self.assess("https://b.example/", "Synthetic Residency Authority announces the golden visa renewal fee of AED 1,150.")
        self.assertEqual(a["gov_verification"]["evidence_id"], b["gov_verification"]["evidence_id"])
        self.assertTrue(a["gov_verification"]["registry_version"].startswith("reg_"))
        self.assertEqual(a["gov_verification"]["policy_version"], a["policy_version"])

    def test_no_relevant_approved_source_is_reported_honestly(self):
        real = helpers.Registry.load()  # production registry: every curated entry is still pending
        r = helpers.scorer(records=[], registry=real).assess_url(
            "https://x.example/", text="Abu Dhabi Police warns that traffic fines are doubled"
        )
        gov = r["gov_verification"]
        self.assertEqual(gov["status"], "NOT_VERIFIABLE")
        self.assertEqual(gov["checked_sources"], [])
        self.assertEqual(gov["coverage"], "no_relevant_source")
        self.assertNotIn("not found on official channels", " ".join(gov["notes"]))
        self.assertTrue(any("pending" in n for n in gov["notes"]))
        self.assertEqual(r["tag"], "WARNING")  # no coverage → manual review, not MISLEADING


if __name__ == "__main__":
    unittest.main()
