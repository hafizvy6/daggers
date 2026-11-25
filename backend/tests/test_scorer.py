from __future__ import annotations

import pytest

from backend.app.core import numbers, scorer


def score(url, scoring_kwargs, **context):
    return scorer.score_url(url, **scoring_kwargs, context=context)


def test_official_bank_domain_is_clean(scoring_kwargs):
    result = score("https://adcb.ae/login", scoring_kwargs)
    assert result.verdict == "UNKNOWN"
    assert result.score == 0.0
    assert result.brand_hit is False


def test_official_subdomain_is_clean(scoring_kwargs):
    result = score("https://www.emiratesnbd.com/login", scoring_kwargs)
    assert result.verdict == "UNKNOWN"
    assert result.score == 0.0


def test_brand_login_clone_is_malicious(scoring_kwargs):
    result = score("https://adcb-secure-login.xyz", scoring_kwargs)
    assert result.verdict == "MALICIOUS"
    assert result.score >= 0.90
    assert result.brand_hit is True
    assert any("brand typo/name 'adcb'" in reason for reason in result.reasons)
    assert result.l1_detail["identity.brand_typo_d1"] == 0.55


def test_cyrillic_confusable_domain_scores_both_punycode_and_homograph(scoring_kwargs):
    result = score("аmazon.ae", scoring_kwargs)
    assert result.verdict == "MALICIOUS"
    assert result.homograph["mixed_script"] is True
    assert result.homograph["spoof"] is True
    assert result.homograph["spoofed_domain"] == "amazon.ae"
    assert result.l1_detail["homograph.mixed_or_spoof"] == 0.45
    assert result.l1_detail["lexical.punycode_xn"] == 0.35


def test_punycode_wire_form_decodes_to_confusable_spoof(scoring_kwargs):
    result = score("https://xn--mazon-3ve.ae/", scoring_kwargs)
    assert result.verdict == "MALICIOUS"
    assert result.normalized["unicode_host"] == "аmazon.ae"
    assert result.homograph["spoofed_domain"] == "amazon.ae"


def test_fully_non_latin_domain_is_not_flagged_without_spoof(scoring_kwargs):
    result = score("https://موقع.ae/", scoring_kwargs)
    assert result.verdict == "UNKNOWN"
    assert result.score == 0.0
    assert result.homograph["mixed_script"] is False
    assert result.homograph["spoof"] is False
    assert "lexical.punycode_xn" not in result.l1_detail


def test_ip_literal_host_is_suspicious(scoring_kwargs):
    result = score("http://192.168.1.1/", scoring_kwargs)
    assert result.verdict == "SUSPICIOUS"
    assert result.l1_detail["lexical.ip_host"] == 0.40


def test_user_at_host_trick_is_malicious(scoring_kwargs):
    result = score("https://adcb.ae@evil.xyz/login", scoring_kwargs)
    assert result.verdict == "MALICIOUS"
    assert result.l1_detail["lexical.at_in_authority"] == 0.30
    assert result.l1_detail["lexical.risky_tld"] == 0.15


def test_lure_keyword_pushes_risky_tld_to_suspicious(scoring_kwargs):
    result = score("https://odd.xyz/login", scoring_kwargs)
    assert result.verdict == "SUSPICIOUS"
    assert result.score >= 0.35
    assert "lexical.lure_keyword" in result.l1_detail


def test_path_depth_and_gibberish_are_recorded(scoring_kwargs):
    deep = score("https://odd.xyz/a/b/c/d/e", scoring_kwargs)
    gibberish = score("https://abcdef1234567890.xyz/a", scoring_kwargs)
    assert deep.l1_detail["lexical.path_depth"] == 0.10
    assert gibberish.l1_detail["lexical.gibberish_run"] == 0.15
    assert gibberish.verdict == "UNKNOWN"


SCAN_RESULT_KEYS = {
    "kind", "input", "verdict", "score", "reasons", "evidence_url", "scam_type", "offline_capable",
    # full engine output for the Checker: annotated signals + what was analysed
    "signals", "analyzed_url", "normalized", "homograph", "urls",
}


def test_english_claim_without_url_floors_at_misleading(scoring_kwargs):
    result = scorer.score_request(
        "text",
        "Abu Dhabi government is giving away 1 million dirhams",
        "en",
        **scoring_kwargs,
    )
    assert set(result) == SCAN_RESULT_KEYS
    assert result["verdict"] == "MISLEADING"
    assert result["offline_capable"] is True
    assert any("unverifiable claim" in reason for reason in result["reasons"])


def test_arabic_claim_is_detected(scoring_kwargs):
    result = scorer.score_request(
        "text",
        "شرطة أبوظبي توزع مليون درهم",
        "ar",
        **scoring_kwargs,
    )
    assert result["verdict"] == "MISLEADING"
    assert result["scam_type"] == "unverifiable-giveaway-claim"


def test_arabizi_claim_is_detected(scoring_kwargs):
    result = scorer.score_request("text", "rab7 mablagh bank", "en", **scoring_kwargs)
    assert result["verdict"] == "MISLEADING"


def test_official_host_suppresses_claim_signal(scoring_kwargs):
    result = score(
        "https://adcb.ae/news",
        scoring_kwargs,
    )
    assert result.verdict == "UNKNOWN"
    assert result.claim_hit is False
    claim_with_text = scorer.score_url(
        "https://adcb.ae/news",
        **scoring_kwargs,
        text="bank giveaway 1 million dirhams",
    )
    assert claim_with_text.claim_hit is False


def test_confirmed_feed_label_is_strong_evidence(scoring_kwargs):
    result = score("https://odd-example.com/", scoring_kwargs, phishtank_confirmed=True)
    assert result.verdict == "MALICIOUS"
    assert result.l1_detail["feeds.phishtank_confirmed"] == 0.70


def test_visual_clone_and_content_signals(scoring_kwargs):
    result = score(
        "https://adcb-secure-login.xyz/",
        scoring_kwargs,
        clone_score=97,
        gallery_match="adcb.ae/login",
        form_action_mismatch=True,
        payment_harvest_fields=True,
    )
    assert result.verdict == "MALICIOUS"
    assert result.l1_detail["vision.clone_ge_90"] == 0.60
    assert result.l1_detail["content.form_action_mismatch"] == 0.30
    assert result.l1_detail["content.payment_harvest_fields"] == 0.25
    assert result.scam_type == "fake-banking-login"


def test_fresh_certificate_signal(scoring_kwargs):
    result = score("https://adcb-secure-login.xyz/", scoring_kwargs, cert_age_hours=0.7)
    assert result.verdict == "MALICIOUS"
    assert result.l1_detail["infra.cert_age_lt_24h"] == 0.25


def test_scan_result_never_contains_internal_fields(scoring_kwargs):
    result = scorer.score_request("url", "https://adcb-secure-login.xyz/", "en", **scoring_kwargs)
    assert set(result) == SCAN_RESULT_KEYS
    assert result["kind"] == "url"
    assert result["input"] == "https://adcb-secure-login.xyz/"


@pytest.mark.parametrize(
    "name,kind,value,lang,context,expected",
    [
        ("official adcb", "url", "https://adcb.ae/login", "en", {}, "UNKNOWN"),
        ("official subdomain", "url", "https://www.emiratesnbd.com/login", "en", {}, "UNKNOWN"),
        ("official amazon", "url", "https://amazon.ae/", "en", {}, "UNKNOWN"),
        ("brand clone", "url", "https://adcb-secure-login.xyz", "en", {}, "MALICIOUS"),
        ("brand d1 typo", "url", "https://adcb1.xyz", "en", {}, "MALICIOUS"),
        ("brand d2 typo", "url", "https://adcb12.xyz", "en", {}, "SUSPICIOUS"),
        ("unicode homograph", "url", "аmazon.ae", "en", {}, "MALICIOUS"),
        ("punycode homograph", "url", "https://xn--mazon-3ve.ae/", "en", {}, "MALICIOUS"),
        ("pure arabic", "url", "https://موقع.ae/", "ar", {}, "UNKNOWN"),
        ("ip host", "url", "http://192.168.1.1/", "en", {}, "SUSPICIOUS"),
        ("at trick", "url", "https://adcb.ae@evil.xyz/login", "en", {}, "MALICIOUS"),
        ("risky plus lure", "url", "https://odd.xyz/login", "en", {}, "SUSPICIOUS"),
        ("deep path", "url", "https://odd.example.com/a/b/c/d/e", "en", {}, "UNKNOWN"),
        ("hex gibberish", "url", "https://abcdef1234567890.xyz/a", "en", {}, "UNKNOWN"),
        ("claim only url", "url", "https://uae-lucky-day.info/?message=bank+giveaway+1+million+dirhams", "en", {}, "MISLEADING"),
        ("claim plus feed proof", "url", "https://uae-lucky-day.info/?message=bank+giveaway+1+million+dirhams", "en", {"phishtank_confirmed": True}, "MALICIOUS"),
        ("feed proof", "url", "https://odd-example.com/", "en", {"phishtank_confirmed": True}, "MALICIOUS"),
        ("clone proof", "url", "https://adcb-secure-login.xyz/", "en", {"clone_score": 97, "gallery_match": "adcb.ae/login"}, "MALICIOUS"),
        ("form and payment proof", "url", "https://adcb-secure-login.xyz/", "en", {"form_action_mismatch": True, "payment_harvest_fields": True}, "MALICIOUS"),
        ("fresh cert", "url", "https://adcb-secure-login.xyz/", "en", {"cert_age_hours": 0.7}, "MALICIOUS"),
        ("claim only text", "text", "Abu Dhabi bank is giving away 1 million dirhams", "en", {}, "MISLEADING"),
        ("arabic claim", "text", "شرطة أبوظبي توزع مليون درهم", "ar", {}, "MISLEADING"),
        ("clean number", "number", "+971 4 123 4567", "en", {}, "UNKNOWN"),
        ("reported number", "number", "+971900000042", "en", {}, "MALICIOUS"),
    ],
)
def test_golden_accuracy_matrix(name, kind, value, lang, context, expected, scoring_kwargs):
    if kind == "number":
        verdict = numbers.check_number(value).verdict
    elif kind == "text":
        verdict = scorer.score_request(kind, value, lang, **scoring_kwargs)["verdict"]
    else:
        verdict = score(value, scoring_kwargs, **context).verdict
    assert verdict == expected, name


def test_claim_only_high_score_is_capped_at_misleading(scoring_kwargs):
    result = score(
        "https://uae-lucky-day.info/?message=bank+giveaway+1+million+dirhams",
        scoring_kwargs,
    )
    assert result.score >= 0.65
    assert result.claim_hit is True
    assert result.verdict == "MISLEADING"
    assert result.scam_type == "unverifiable-giveaway-claim"


def test_claim_with_feed_proof_can_be_malicious(scoring_kwargs):
    result = score(
        "https://uae-lucky-day.info/?message=bank+giveaway+1+million+dirhams",
        scoring_kwargs,
        phishtank_confirmed=True,
    )
    assert result.verdict == "MALICIOUS"
    assert result.scam_type == "known-phishing-url"
