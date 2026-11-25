from __future__ import annotations

from backend.app.core import homograph


def test_confusable_fold_maps_cyrillic_and_greek_lookalikes():
    assert homograph.confusable_fold("аmazon.ae") == "amazon.ae"
    assert homograph.confusable_fold("аеорсух.com") == "aeopcyx.com"
    assert homograph.confusable_fold("οrange.example") == "orange.example"


def test_mixed_script_label_reports_both_scripts():
    mixed, scripts = homograph.has_mixed_script("аmazon")
    assert mixed is True
    assert "CYRILLIC" in scripts
    assert "LATIN" in scripts


def test_fully_non_latin_label_is_not_mixed_script():
    mixed, scripts = homograph.has_mixed_script("موقع")
    assert mixed is False
    assert "ARABIC" in scripts


def test_host_forms_keep_unicode_and_punycode_together():
    forms = homograph.host_forms("аmazon.ae")
    assert forms["unicode_host"] == "аmazon.ae"
    assert forms["punycode_host"] == "xn--mazon-3ve.ae"
    decoded = homograph.host_forms("xn--mazon-3ve.ae")
    assert decoded["unicode_host"] == "аmazon.ae"


def test_confusable_spoof_matches_official_brand(catalog):
    audit = homograph.audit("аmazon.ae", catalog.official_domains, "аmazon.ae")
    assert audit.mixed_script is True
    assert audit.spoof is True
    assert audit.spoofed_domain == "amazon.ae"


def test_confusable_spoof_matches_bank_label(catalog):
    spoof = "а" + "dcb.ae"
    audit = homograph.audit(spoof, catalog.official_domains, spoof)
    assert audit.spoof is True
    assert audit.spoofed_domain == "adcb.ae"


def test_official_subdomain_is_not_spoof(catalog):
    audit = homograph.audit("www.adcb.ae", catalog.official_domains, "adcb.ae")
    assert audit.spoof is False
    assert audit.mixed_script is False


def test_pure_arabic_domain_has_no_homograph_signal(catalog):
    audit = homograph.audit("موقع.ae", catalog.official_domains, "موقع.ae")
    assert audit.signal is False
    assert audit.spoof is False
