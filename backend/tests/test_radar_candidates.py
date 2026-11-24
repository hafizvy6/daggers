from __future__ import annotations

from backend.app.radar.candidates import admit_candidate
from backend.app.radar.gate import actionable_from_context


TERMS = [
    "adcb",
    "bankfab",
    "fabbank",
    "firstabudhabi",
    "emiratesnbd",
    "dewa",
    "rtarefund",
]
OFFICIALS = ["adcb.ae", "bankfab.com", "emiratesnbd.com", "dewa.gov.ae"]


def test_ct_noise_is_rejected():
    for domain in ("fabbri.local", "fab7.com", "fab-store.com", "fab-defense.com", "fabcorp.com"):
        assert admit_candidate(domain, TERMS, OFFICIALS)["admitted"] is False, domain


def test_high_signal_brand_candidates_are_admitted():
    for domain in (
        "adcb-secure-login.xyz",
        "adcblogin.com",
        "bankfab-login.com",
        "bankfab-secure.com",
        "fabbank.mobi",
        "firstabudhabi-secure.com",
        "dewa-payment.xyz",
        "rtarefund.ae",
    ):
        assert admit_candidate(domain, TERMS, OFFICIALS)["admitted"] is True, domain


def test_official_domains_and_subdomains_are_rejected():
    for domain in ("adcb.ae", "www.adcb.ae", "bankfab.com", "emiratesnbd.com"):
        assert admit_candidate(domain, TERMS, OFFICIALS)["admitted"] is False, domain


def test_punycode_is_checked_after_decode():
    # Cyrillic а and с fold onto Latin a and c.
    assert admit_candidate("xn--dblogin-1fg8m.xyz", TERMS, OFFICIALS)["admitted"] is True


def test_suppressed_unknown_candidates_require_corroboration():
    assert actionable_from_context(score=0.0, verdict="UNKNOWN", context={}, min_score=0.35) is False
    assert actionable_from_context(
        score=0.0,
        verdict="UNKNOWN",
        context={"payment_harvest_fields": True},
        min_score=0.35,
    ) is True
    assert actionable_from_context(
        score=0.35,
        verdict="UNKNOWN",
        context={},
        min_score=0.35,
    ) is True
    assert actionable_from_context(
        score=0.55,
        verdict="SUSPICIOUS",
        context={},
        min_score=0.35,
    ) is True
