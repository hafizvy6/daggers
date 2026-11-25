from __future__ import annotations

from backend.app.core import claims


def evaluate(text, catalog, host="example.info"):
    return claims.evaluate_claims(text, host, list(catalog.brands), catalog.official_domains)


def test_english_giveaway_with_amount_and_entity(catalog):
    signal = evaluate("Abu Dhabi bank is giving away 1 million dirhams", catalog)
    assert signal is not None
    assert signal.weight == 0.50
    assert signal.forced_min == "MISLEADING"
    assert "unverifiable claim — not confirmed by an authenticated official source" in signal.reason
    assert "amount" in signal.matched_patterns


def test_arabic_giveaway_claim(catalog):
    signal = evaluate("شرطة أبوظبي توزع مليون درهم", catalog)
    assert signal is not None
    assert "arabic_offer" in signal.matched_patterns
    assert "arabic_entity" in signal.matched_patterns


def test_arabizi_giveaway_claim(catalog):
    signal = evaluate("rab7 mablagh bank", catalog)
    assert signal is not None
    assert signal.scam_type == "unverifiable-giveaway-claim"


def test_brand_alias_is_an_entity_claim(catalog):
    signal = evaluate("بنك أبوظبي التجاري يوزع هدية مليون درهم", catalog, "odd-example.info")
    assert signal is not None
    assert "brand_claim" in signal.matched_patterns


def test_official_domain_suppresses_unverifiable_claim(catalog):
    signal = evaluate("bank giveaway 1 million dirhams", catalog, "https://adcb.ae/news")
    assert signal is None


def test_offer_without_entity_is_not_a_claim(catalog):
    signal = evaluate("a free gift is available today", catalog)
    assert signal is None


def test_entity_without_offer_is_not_a_claim(catalog):
    signal = evaluate("please verify your account with the bank", catalog)
    assert signal is None
