"""Government authentication → central verdict → database → Checker / Police Portal.

Uses the REAL shipped registry (backend/app/channels/official/registry.yaml), copied to a
temporary directory. Approvals in these tests are applied to that COPY only, through the
same Registry.approved_mapping() the human approval CLI uses, with reviewer "Test Reviewer".
The shipped registry itself is never modified by tests (every entry ships `pending`).
"""
from __future__ import annotations

import itertools
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.channels.official import POLICY_VERSION
from backend.app.channels.official.registry import DEFAULT_REGISTRY_PATH, Registry, write_registry_atomic
from backend.app.config import Settings
from backend.app.main import create_app
from backend.tests.conftest import login_as

VERIFIED = ("uae-gov-portal uae-pass abu-dhabi-police dubai-police icp mohre rta dewa tamm wam "
            "abu-dhabi-media-office dubai-media-office khaleej-times gulf-news emirates-nbd").split()
_ids = itertools.count(1)

# Real UAE government hosts (each verified against the sources in its registry provenance).
GOVERNMENT_SAFE = [
    "https://u.ae/en", "https://ask.u.ae/", "https://uaepass.ae/", "https://id.uaepass.ae/",
    "https://www.adpolice.gov.ae/en", "https://adpolice.gov.ae/", "https://es.adpolice.gov.ae/",
    "https://www.dubaipolice.gov.ae/", "https://icp.gov.ae/en/", "https://www.icp.gov.ae/",
    "https://smartservices.icp.gov.ae/", "https://www.mohre.gov.ae/", "https://ibtikar.mohre.gov.ae/",
    "https://www.rta.ae/", "https://www.dewa.gov.ae/en", "https://www.tamm.abudhabi/",
    "https://www.wam.ae/en", "https://www.mediaoffice.abudhabi/en/", "https://www.mediaoffice.ae/en",
]
NEWS_SAFE = ["https://www.khaleejtimes.com/", "https://gulfnews.com/"]
COMMERCIAL_SAFE = ["https://www.emiratesnbd.com/en", "https://online.emiratesnbd.com/"]


def rid() -> str:
    return f"gov-test-{next(_ids):06d}"


def approve(path: Path, ids, *, when: datetime | None = None) -> Registry:
    reg = Registry.load(path)
    for entry_id in ids:
        reg = write_registry_atomic(path, reg.approved_mapping(entry_id, "Test Reviewer", when or datetime.now(timezone.utc)))
    return reg


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "template")
    reg_path = tmp_path / "registry.yaml"
    shutil.copy(DEFAULT_REGISTRY_PATH, reg_path)
    settings = Settings(
        db_path=tmp_path / "d.db", evidence_dir=tmp_path / "e", gallery_dir=tmp_path / "g",
        web_dir=Path(__file__).resolve().parents[2] / "web", cors_origins=[], heartbeat_interval_s=1,
        crt_poll_interval_s=20, feed_poll_interval_s=20, pipeline_poll_interval_s=1, ai_state="template",
        official_snapshot_dir=tmp_path / "snap", scan_rate_per_min=1000,
    )
    app = create_app(settings)
    with TestClient(app) as client:
        rt = app.state.runtime
        rt.trust_policy.registry = Registry.load(reg_path)
        rt.maybe_reload_registry()          # start watching the temporary copy
        yield client, app, reg_path


def reload_now(app):
    rt = app.state.runtime
    rt._registry_checked_at = 0.0          # skip the 2-second throttle
    return rt.maybe_reload_registry()


def check(client, value):
    r = client.post("/api/check", json={"input": value, "lang": "en", "request_id": rid()})
    assert r.status_code in (200, 201), r.text
    return r.json()


# ------------------------------------------------------------------ shipped state

def test_shipped_registry_is_all_pending_with_verified_evidence():
    reg = Registry.load()
    assert {e.status for e in reg.entries} == {"pending"}
    for entry_id in VERIFIED:
        assert reg.by_id[entry_id].provenance.startswith("verified 2026-11-24"), entry_id
    assert reg.by_id["the-national"].provenance.startswith("partially checked")
    assert reg.by_id["emirates-nbd"].source_class == "P"
    assert reg.by_id["uae-gov-portal"].allowed_subdomains == ("ask", "assets")   # no www: u.ae doesn't use it


def test_pending_government_domains_are_warning_never_safe(env):
    client, _, _ = env
    for url in ("https://www.adpolice.gov.ae/en", "https://u.ae/en", "https://www.emiratesnbd.com/en"):
        f = check(client, url)
        assert f["tag"] == "WARNING" and f["domain_auth"]["status"] == "PENDING", url


# ------------------------------------------------------------------ the two SAFE paths

def test_approved_real_government_domains_are_safe(env):
    client, app, reg_path = env
    approve(reg_path, VERIFIED)
    reload_now(app)
    for url in GOVERNMENT_SAFE:
        f = check(client, url)
        assert f["tag"] == "SAFE", (url, f["trust_reasons"])
        a = f["domain_auth"]
        assert a["status"] == "AUTHENTICATED" and a["authenticated"] is True and a["legitimate_site"] is False
        assert a["reviewer"] == "Test Reviewer" and a["verified_at"] and a["expires_at"]
        assert a["source_class"] in ("A", "B")


def test_news_and_verified_commercial_sites_are_safe_but_never_government(env):
    client, app, reg_path = env
    approve(reg_path, VERIFIED)
    reload_now(app)
    for url in NEWS_SAFE + COMMERCIAL_SAFE:
        f = check(client, url)
        assert f["tag"] == "SAFE", (url, f["trust_reasons"])
        a = f["domain_auth"]
        assert a["authenticated"] is False and a["legitimate_site"] is True
        assert a["status"] in ("INDEPENDENT_MEDIA", "VERIFIED_ORGANIZATION")
        assert any("not" in r and "government" in r for r in f["trust_reasons"])
        assert "stay_alert_site" in f["precautions"]
    # a class P company mentioned in a message never becomes a "government claim"
    f = check(client, "Emirates NBD announces a new savings account. Details at https://www.emiratesnbd.com/en")
    assert f["tag"] == "SAFE" and f["gov_verification"] is None


def test_unverified_commercial_and_pending_news_stay_warning(env):
    client, app, reg_path = env
    approve(reg_path, VERIFIED)
    reload_now(app)
    assert check(client, "https://www.noon.com/")["tag"] == "WARNING"                  # not in registry
    national = check(client, "https://www.thenationalnews.com/")
    assert national["tag"] == "WARNING" and national["domain_auth"]["status"] == "PENDING"


# ------------------------------------------------------------------ failures of authentication

def test_expired_and_revoked_entries_are_not_safe(env):
    client, app, reg_path = env
    approve(reg_path, ["abu-dhabi-police"], when=datetime.now(timezone.utc) - timedelta(days=200))
    reload_now(app)
    f = check(client, "https://www.adpolice.gov.ae/en")
    assert f["tag"] == "WARNING" and f["domain_auth"]["status"] == "EXPIRED"
    reg = approve(reg_path, ["abu-dhabi-police"])
    write_registry_atomic(reg_path, reg.revoked_mapping("abu-dhabi-police", "Test Reviewer", "test", datetime.now(timezone.utc)))
    reload_now(app)
    f = check(client, "https://adpolice.gov.ae/")
    assert f["tag"] == "WARNING" and f["domain_auth"]["status"] == "REVOKED"


@pytest.mark.parametrize("url", [
    "https://evil.adpolice.gov.ae/",          # subdomain not explicitly permitted
    "https://www.u.ae/",                      # u.ae is served on the bare domain only
    "https://evil.emiratesnbd.com/",
    "https://www.adpolice.gov.ae:8443/",      # non-default port: not checkable
])
def test_unauthorised_hosts_are_never_safe(env, url):
    client, app, reg_path = env
    approve(reg_path, VERIFIED)
    reload_now(app)
    f = check(client, url)
    assert f["tag"] == "WARNING" and not f["domain_auth"]["authenticated"], f["domain_auth"]


@pytest.mark.parametrize("url", [
    "https://www.adpolice.gov.ae@evil.top/login",     # user-info trick: real host is evil.top
    "https://adpolice.gov.ae.evil.top/",              # official name as a prefix of another domain
    "https://аdpolice.gov.ae/",                       # Cyrillic 'а' homograph
    "https://adpolice-gov.ae/",                       # government look-alike
    "https://abudhabi-police-fines.top/pay",
    "https://dubaipolice-fines.com/pay",
    "https://emiratesnbd-rewards.com/",
    "https://adcb-secure-login.xyz/login",            # confirmed phishing pattern (bank)
])
def test_impersonation_and_spoofing_are_fake(env, url):
    client, app, reg_path = env
    approve(reg_path, VERIFIED)
    reload_now(app)
    f = check(client, url)
    assert f["tag"] == "FAKE", (url, f["domain_auth"], [s["name"] for s in f["signals"]])
    assert not f["domain_auth"]["authenticated"]


def test_url_normalisation_keeps_genuine_hosts_safe(env):
    client, app, reg_path = env
    approve(reg_path, VERIFIED)
    reload_now(app)
    for url in ("HTTPS://WWW.ADPOLICE.GOV.AE/EN", "https://www.adpolice.gov.ae./", "www.adpolice.gov.ae/en?utm_source=x",
                "adpolice.gov.ae", "https://www.adpolice.gov.ae/en/login"):
        f = check(client, url)
        assert f["tag"] == "SAFE", (url, f["domain_auth"])


# ------------------------------------------------------------------ authentication never overrides malice

def test_suspicious_message_linking_to_genuine_government_site_is_not_safe(env):
    client, app, reg_path = env
    approve(reg_path, VERIFIED)
    reload_now(app)
    f = check(client, "Abu Dhabi Police: your fine is unpaid. Send us the OTP you received to clear it: "
                      "https://www.adpolice.gov.ae")
    assert f["domain_auth"]["authenticated"] is True
    assert f["tag"] in ("WARNING", "FAKE") and f["manual_review"] is True
    assert "message.credential_request" in {s["name"] for s in f["signals"]}


def test_giveaway_content_on_genuine_government_page_is_flagged(env):
    client, app, reg_path = env
    approve(reg_path, VERIFIED)
    reload_now(app)
    login_as(client, app, "investigator")
    r = client.post("/api/investigations", json={
        "url": "https://www.icp.gov.ae/en/", "page_text": "Congratulations! You won a prize of AED 50,000. Claim your reward now."})
    f = r.json()
    assert r.status_code == 201 and f["domain_auth"]["authenticated"] is True
    assert f["tag"] == "WARNING" and f["manual_review"] is True


def test_confirmed_malicious_evidence_on_authenticated_domain_is_fake_not_blocked(env):
    _, app, reg_path = env
    approve(reg_path, VERIFIED)
    reload_now(app)
    scorer = app.state.runtime.trust_policy
    out = scorer.assess_url("https://www.mohre.gov.ae/login", context={"phishtank_confirmed": True,
                                                                         "form_action_mismatch": True})
    assert out["domain_auth"]["authenticated"] is True
    assert out["tag"] == "FAKE" and out["manual_review"] is True
    assert out["blockable"] is False      # Guard never auto-blocks a registry domain
    assert any("registry approval does not override" in r for r in out["trust_reasons"])


# ------------------------------------------------------------------ database, cache, Checker = Portal

def test_stored_findings_are_reconciled_when_the_registry_changes(env):
    client, app, reg_path = env
    before = check(client, "https://www.adpolice.gov.ae/en")
    assert before["tag"] == "WARNING" and before["domain_auth"]["status"] == "PENDING"
    login_as(client, app, "viewer")
    # approval takes effect WITHOUT a restart (hot reload) and the stored record is corrected
    approve(reg_path, VERIFIED)
    assert reload_now(app) is True
    after = client.get(f"/api/finding/{before['id']}").json()
    assert after["tag"] == "SAFE" and after["domain_auth"]["status"] == "AUTHENTICATED"
    assert after["policy_version"] == POLICY_VERSION
    assert after["verdict_history"][-1]["tag"] == "WARNING"
    stored = app.state.runtime.repo.get_finding(before["id"])           # persisted, not just computed
    assert stored["tag"] == "SAFE"
    listed = client.get("/api/portal/findings", params={"q": "adpolice"}).json()["findings"]
    assert [x["tag"] for x in listed if x["id"] == before["id"]] == ["SAFE"]
    # the Checker never reads the Portal: its stored result was made under the old registry, so it is
    # NOT reused — the input is analysed again (SAFE) and the new result is sent to the Portal
    again = client.post("/api/check", json={"input": "https://www.adpolice.gov.ae/en", "request_id": rid()}).json()
    assert again["tag"] == "SAFE" and again["duplicate"] is False and again["id"] != before["id"]
    # revocation flows the other way
    reg = Registry.load(reg_path)
    write_registry_atomic(reg_path, reg.revoked_mapping("abu-dhabi-police", "Test Reviewer", "test", datetime.now(timezone.utc)))
    reload_now(app)
    revoked = client.get(f"/api/finding/{before['id']}").json()
    assert revoked["tag"] == "WARNING" and revoked["domain_auth"]["status"] == "REVOKED"
    assert [h["tag"] for h in revoked["verdict_history"]][-2:] == ["WARNING", "SAFE"]


def test_bulk_reconciliation_updates_every_stale_record(env):
    client, app, reg_path = env
    ids = [check(client, u)["id"] for u in ("https://www.wam.ae/en", "https://www.rta.ae/", "https://gulfnews.com/")]
    approve(reg_path, VERIFIED)
    app.state.runtime.trust_policy.registry = Registry.load(reg_path)
    assert app.state.runtime.reconcile_findings() == 3
    repo = app.state.runtime.repo
    assert [repo.get_finding(i)["tag"] for i in ids] == ["SAFE", "SAFE", "SAFE"]
    assert app.state.runtime.reconcile_findings() == 0          # nothing stale left


def test_invalid_registry_fails_closed(env):
    client, app, reg_path = env
    approve(reg_path, VERIFIED)
    reload_now(app)
    assert check(client, "https://u.ae/en")["tag"] == "SAFE"
    reg_path.write_text("entries: [ {id: broken", encoding="utf-8")     # corrupt file
    reload_now(app)
    f = check(client, "https://u.ae/fr")
    assert f["tag"] == "WARNING"                                         # nothing authenticates
    assert app.state.runtime.registry_error


def test_guard_never_blocks_registry_domains_even_if_flagged(env):
    client, app, reg_path = env
    approve(reg_path, VERIFIED)
    reload_now(app)
    app.state.runtime.repo.insert_finding(domain="www.dubaipolice.gov.ae", score=0.95, verdict="MALICIOUS",
                                          reasons=["test feed listing"], source="feeds", first_seen="2026-11-24T08:00:00Z")
    assert "dubaipolice.gov.ae" not in client.get("/api/guard/blocklist.txt").text


def test_42_abu_dhabi_is_a_pending_verified_organisation_until_approved(env):
    client, app, reg_path = env
    entry = Registry.load().by_id["42-abu-dhabi"]
    assert entry.status == "pending" and entry.source_class == "P"
    assert entry.provenance.startswith("verified 2026-11-25")
    assert check(client, "https://42abudhabi.ae/")["tag"] == "WARNING"            # pending: not SAFE yet
    approve(reg_path, ["42-abu-dhabi"])
    reload_now(app)
    for url in ("https://42abudhabi.ae/apply", "https://www.42abudhabi.ae/"):
        f = check(client, url)
        assert f["tag"] == "SAFE", (url, f["trust_reasons"])
        assert f["domain_auth"]["status"] == "VERIFIED_ORGANIZATION" and f["domain_auth"]["authenticated"] is False
    fake = check(client, "https://42abudhabi-scholarship.com/apply")
    assert fake["tag"] != "SAFE" and "identity.registry_name_reuse" in {s["name"] for s in fake["signals"]}
    assert check(client, "https://intra.42abudhabi.ae/")["tag"] == "WARNING"        # sub-domain not listed


def test_approve_verified_is_derived_from_registry_evidence_not_a_code_list(tmp_path):
    import subprocess, sys
    copy = tmp_path / "registry.yaml"
    shutil.copy(DEFAULT_REGISTRY_PATH, copy)
    out = subprocess.run([sys.executable, "-m", "backend.app.channels.official.cli", "--registry", str(copy),
                          "approve-verified", "--reviewer", "Test Reviewer", "--yes"],
                         capture_output=True, text=True, check=True).stdout
    reg = Registry.load(copy)
    approved = {e.id for e in reg.entries if e.status == "approved"}
    expected = {e.id for e in Registry.load().entries if e.provenance.lower().startswith("verified ")}
    assert approved == expected and "the-national" not in approved and "42-abu-dhabi" in approved
    assert all(e.reviewer == "Test Reviewer" for e in reg.entries if e.status == "approved")
    assert f"approved {len(expected)} entries" in out


def test_etisalat_eand_link_is_safe_once_approved(env):
    client, app, reg_path = env
    url = "https://www.eand.ae/en/c/mobile/add-ons/unlimited-ksa-roaming.html"
    before = check(client, url)
    assert before["tag"] == "WARNING" and before["domain_auth"]["status"] == "PENDING"
    assert "lexical.lure_keyword" not in {s["name"] for s in before["signals"]}      # 'unlimited' ≠ 'limited'
    approve(reg_path, ["etisalat-uae"])
    reload_now(app)
    for u in (url, "https://www.etisalat.ae/", "https://eand.com/"):
        f = check(client, u)
        assert f["tag"] == "SAFE" and f["domain_auth"]["status"] == "VERIFIED_ORGANIZATION", (u, f["trust_reasons"])


def test_real_bank_domain_is_never_fake_and_safe_once_approved(env):
    client, app, reg_path = env
    for url in ("https://www.adcb.com/", "https://www.adcb.com/en/personal"):
        f = check(client, url)
        assert f["tag"] == "WARNING", (url, f["signals"])           # pending: not SAFE yet, never FAKE
        assert not [s for s in f["signals"] if s["name"].startswith(("identity.", "homograph."))]
    approve(reg_path, ["adcb"])
    reload_now(app)
    f = check(client, "https://www.adcb.com/en/personal-banking")
    assert f["tag"] == "SAFE" and f["domain_auth"]["status"] == "VERIFIED_ORGANIZATION"
    assert check(client, "https://adcb-secure-login.xyz/")["tag"] == "FAKE"          # impersonation still FAKE


def test_every_catalogue_brand_domain_is_not_flagged_as_impersonating_itself(scoring_kwargs_catalog=None):
    from backend.app.catalog import load_catalogs
    from backend.app.core import scorer
    kwargs = load_catalogs().scoring_kwargs()
    for brand in kwargs["brands"]:
        r = scorer.score_url(f"https://www.{brand['official_domain']}/", **kwargs)
        assert r.verdict == "UNKNOWN", (brand["official_domain"], r.l1_detail)
