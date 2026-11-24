from __future__ import annotations

from backend.app.core import numbers, scorer


def test_pattern_catalog_has_200_deterministic_signatures():
    assert numbers.pattern_catalog_size() == 200


def test_reported_premium_number_is_malicious():
    result = numbers.check_number("+971 9000 00042")
    assert result.verdict == "MALICIOUS"
    assert result.score >= 0.85
    assert any("deterministic reported-number pattern" in reason for reason in result.reasons)
    assert result.offline_capable is True


def test_premium_prefix_without_report_is_suspicious():
    result = numbers.check_number("+9001234567")
    assert result.verdict == "SUSPICIOUS"
    assert any("premium-rate" in reason for reason in result.reasons)


def test_north_american_caribbean_premium_forms_are_suspicious():
    for value in ("+1 809 555 0123", "+1 829 555 0123", "+1 849 555 0123", "001-809-555-0123"):
        result = numbers.check_number(value)
        assert result.verdict == "SUSPICIOUS", value
        assert any("Caribbean" in reason for reason in result.reasons), value


def test_voip_callback_pattern_is_suspicious():
    result = numbers.check_number("+445612345678")
    assert result.verdict == "SUSPICIOUS"
    assert result.scam_type == "callback-voip-pattern"


def test_same_digit_repeat_is_suspicious():
    result = numbers.check_number("1111111111")
    assert result.verdict == "SUSPICIOUS"
    assert any("same-digit repeat" in reason for reason in result.reasons)


def test_clean_uae_landline_has_no_signs():
    result = numbers.check_number("+971 4 123 4567")
    assert result.verdict == "UNKNOWN"
    assert result.score == 0.0
    assert result.reasons == ["no signs found in the deterministic number patterns"]


def test_arabic_indic_digits_normalize_to_pattern_catalog():
    assert numbers.normalize_number("+٩٧١٩٠٠٠٠٠٠٤٢") == "971900000042"
    result = numbers.check_number("+٩٧١٩٠٠٠٠٠٠٤٢")
    assert result.verdict == "MALICIOUS"


def test_scan_request_number_shape(scoring_kwargs):
    result = scorer.score_request("number", "+971900000042", "en", **scoring_kwargs)
    assert set(result) == {
        "kind", "input", "verdict", "score", "reasons",
        "evidence_url", "scam_type", "offline_capable",
    }
    assert result["kind"] == "number"
    assert result["verdict"] == "MALICIOUS"
    assert result["evidence_url"] is None
    assert result["offline_capable"] is True
