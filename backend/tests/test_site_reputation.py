"""Independent reputation SAFE path (widely used, legitimate, NON-government sites).

The ranking file below is TEST DATA written to a temporary directory (ranks are illustrative,
not the real Tranco list). The real list is downloaded at run time by `make reputation-update`
or automatically by the server; none ships in the code. The Public Suffix List used to exclude
shared platforms is the real one bundled in backend/app/channels/reputation_data/.
"""
from __future__ import annotations

import io
import itertools
import json
import shutil
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.channels import reputation as rep_mod
from backend.app.channels.official.registry import DEFAULT_REGISTRY_PATH, Registry
from backend.app.channels.reputation import Reputation
from backend.app.config import Settings
from backend.app.main import create_app
from backend.tests.conftest import login_as

_ids = itertools.count(1)
RANKS = {  # TEST DATA
    "google.com": 1, "youtube.com": 2, "facebook.com": 3, "microsoft.com": 4, "whatsapp.com": 20,
    "github.com": 30, "github.io": 50, "blogspot.com": 60, "web.app": 70, "bit.ly": 80,
    "wikipedia.org": 90, "u.ae": 900, "adpolice.gov.ae": 950, "moi.gov.ae": 980,
    "emiratesnbd.com": 1500, "noon.com": 2000, "deep-ranked.com": 20000,
}


def write_list(path: Path, ranks=RANKS, *, age_days: float = 1, list_id: str = "TEST1") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(ranks.items(), key=lambda kv: kv[1])
    path.write_text("".join(f"{r},{d}\n" for d, r in rows), encoding="utf-8")
    retrieved = (datetime.now(timezone.utc) - timedelta(days=age_days)).replace(microsecond=0).isoformat()
    path.with_suffix(".json").write_text(json.dumps({"list_id": list_id, "retrieved_at": retrieved}), encoding="utf-8")


def rid() -> str:
    return f"rep-test-{next(_ids):06d}"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "template")
    reg_path = tmp_path / "registry.yaml"
    shutil.copy(DEFAULT_REGISTRY_PATH, reg_path)          # real registry, every entry pending
    list_path = tmp_path / "reputation" / "top-sites.csv"
    write_list(list_path)
    settings = Settings(
        db_path=tmp_path / "d.db", evidence_dir=tmp_path / "e", gallery_dir=tmp_path / "g",
        web_dir=Path(__file__).resolve().parents[2] / "web", cors_origins=[], heartbeat_interval_s=1,
        crt_poll_interval_s=20, feed_poll_interval_s=20, pipeline_poll_interval_s=1, ai_state="template",
        official_snapshot_dir=tmp_path / "snap", scan_rate_per_min=1000,
        reputation_list_path=list_path, reputation_top_n=10_000, reputation_max_age_days=45,
    )
    app = create_app(settings)
    with TestClient(app) as client:
        rt = app.state.runtime
        rt.trust_policy.registry = Registry.load(reg_path)
        rt.maybe_reload_registry()
        yield client, app, list_path


def reload_now(app):
    rt = app.state.runtime
    rt._registry_checked_at = 0.0
    return rt.maybe_reload_registry()


def check(client, value):
    r = client.post("/api/check", json={"input": value, "lang": "en", "request_id": rid()})
    assert r.status_code in (200, 201), r.text
    return r.json()


# ------------------------------------------------------------------ SAFE for widely used sites

@pytest.mark.parametrize("url", [
    "https://www.youtube.com/", "https://youtube.com/watch?v=abc", "https://m.youtube.com/",
    "https://web.whatsapp.com/", "https://www.whatsapp.com/", "https://www.google.com/",
    "https://github.com/", "https://en.wikipedia.org/wiki/Abu_Dhabi", "HTTPS://WWW.YOUTUBE.COM./",
])
def test_widely_used_sites_are_safe_but_not_government(env, url):
    client, _, _ = env
    f = check(client, url)
    assert f["tag"] == "SAFE", (url, f["trust_reasons"])
    a = f["domain_auth"]
    assert a["status"] == "REPUTABLE_SITE" and a["authenticated"] is False and a["legitimate_site"] is True
    assert a["reputation"]["trusted"] is True and a["reputation"]["rank"] and a["reputation"]["list_id"] == "TEST1"
    assert any("not a government source" in r for r in f["trust_reasons"])
    assert "stay_alert_popular" in f["precautions"]


def test_pending_company_entry_does_not_block_the_popularity_path(env):
    client, _, _ = env
    f = check(client, "https://www.emiratesnbd.com/en")          # class P entry pending + ranked
    assert f["tag"] == "SAFE" and f["domain_auth"]["status"] == "REPUTABLE_SITE"
    assert "pending review" in f["domain_auth"]["reason"]


# ------------------------------------------------------------------ never SAFE by popularity

@pytest.mark.parametrize("url,why", [
    ("https://evil-shop.github.io/login", "SHARED_HOST"),          # PSL private: user sub-domain
    ("https://promo.blogspot.com/", "SHARED_HOST"),
    ("https://claim-prize.web.app/", "SHARED_HOST"),
    ("https://docs.google.com/forms/d/e/abc/viewform", "SHARED_HOST"),
    ("https://sites.google.com/view/abc", "SHARED_HOST"),
    ("https://bit.ly/3abc", "SHARED_HOST"),
    ("https://deep-ranked.com/", "NOT_RANKED"),                      # rank beyond top N
    ("https://unknown-small-shop.example/", "NOT_RANKED"),
])
def test_shared_platforms_and_unranked_sites_are_not_safe(env, url, why):
    client, _, _ = env
    f = check(client, url)
    assert f["tag"] != "SAFE", (url, f["trust_reasons"])
    assert f["domain_auth"]["status"] == "UNLISTED"
    assert f["domain_auth"]["reputation"]["status"] == why
    assert any(r.startswith("reputation check:") for r in f["trust_reasons"])


@pytest.mark.parametrize("url", [
    "https://www.u.ae/",                 # u.ae is a registry organisation: only listed sub-domains count
    "https://evil.adpolice.gov.ae/",     # government zone + registry organisation
    "https://moi.gov.ae/",               # government zone, not in the registry: registry only
    "https://www.adpolice.gov.ae/en",    # GOVERNMENT registry entry pending → stays PENDING
])
def test_government_and_registry_hosts_are_decided_by_the_registry_only(env, url):
    client, _, _ = env
    f = check(client, url)
    assert f["tag"] == "WARNING", (url, f["trust_reasons"])
    assert f["domain_auth"]["status"] in ("UNLISTED", "PENDING")


@pytest.mark.parametrize("url", [
    "https://youtube-login-verify.com/",          # look-alike, not ranked
    "https://www.youtube.com@evil.top/login",     # user-info trick: real host is evil.top
    "https://youtube.com.evil.top/",              # popular name as a prefix of another domain
    "https://yоutube.com/",                       # Cyrillic о homograph
])
def test_impersonation_of_popular_sites_is_never_safe(env, url):
    client, _, _ = env
    f = check(client, url)
    assert f["tag"] != "SAFE", (url, f["trust_reasons"])
    assert f["domain_auth"]["status"] != "REPUTABLE_SITE"


def test_scam_message_linking_to_popular_site_is_not_safe(env):
    client, _, _ = env
    f = check(client, "Your WhatsApp account will be closed today. Send us the 6-digit OTP code you "
                      "received to keep it: https://web.whatsapp.com/")
    assert f["tag"] != "SAFE" and f["manual_review"] is True


def test_any_engine_signal_removes_reputation_safe(env):
    _, app, _ = env
    out = app.state.runtime.trust_policy.assess_url("https://www.youtube.com/watch?v=1",
                                                    context={"phishtank_confirmed": True})
    assert out["domain_auth"]["status"] == "REPUTABLE_SITE"
    assert out["tag"] == "FAKE" and out["manual_review"] is True
    assert out["blockable"] is False          # Guard never blocks a whole popular domain for one URL


# ------------------------------------------------------------------ list freshness / failures

def test_missing_stale_or_corrupt_list_fails_closed(env):
    client, app, list_path = env
    assert check(client, "https://www.youtube.com/a")["tag"] == "SAFE"
    write_list(list_path, age_days=100, list_id="OLD1")                 # stale
    reload_now(app)
    f = check(client, "https://www.youtube.com/b")
    assert f["tag"] == "WARNING" and f["domain_auth"]["reputation"]["status"] == "LIST_STALE"
    list_path.write_text("garbage\n", encoding="utf-8")                  # corrupt
    reload_now(app)
    f = check(client, "https://www.youtube.com/c")
    assert f["tag"] == "WARNING" and f["domain_auth"]["reputation"]["status"] == "LIST_INVALID"
    list_path.unlink()                                                   # missing
    reload_now(app)
    f = check(client, "https://www.youtube.com/d")
    assert f["tag"] == "WARNING" and f["domain_auth"]["reputation"]["status"] == "LIST_MISSING"
    ready = app.state.runtime.readiness()["reputation"]
    assert ready["loaded"] is False


# ------------------------------------------------------------------ DB / Checker / Portal consistency

def test_stored_finding_is_corrected_when_a_list_is_installed(env):
    client, app, list_path = env
    list_path.unlink()
    list_path.with_suffix(".json").unlink()
    reload_now(app)
    before = check(client, "https://web.whatsapp.com/")
    assert before["tag"] == "WARNING"
    write_list(list_path, list_id="NEW1")
    assert reload_now(app) is True or app.state.runtime.trust_policy.reputation_version.startswith("tranco-NEW1")
    login_as(client, app, "viewer")
    after = client.get(f"/api/finding/{before['id']}").json()
    assert after["tag"] == "SAFE" and after["domain_auth"]["status"] == "REPUTABLE_SITE"
    assert after["verdict_history"][-1]["tag"] == "WARNING"
    assert app.state.runtime.repo.get_finding(before["id"])["tag"] == "SAFE"          # persisted
    listed = client.get("/api/portal/findings", params={"q": "whatsapp"}).json()["findings"]
    assert [x["tag"] for x in listed if x["id"] == before["id"]] == ["SAFE"]
    again = client.post("/api/check", json={"input": "https://web.whatsapp.com/", "request_id": rid()}).json()
    assert again["tag"] == "SAFE" and again["id"] != before["id"]       # new list → fresh analysis, not reused


def test_scan_endpoint_used_by_extension_agrees(env):
    client, _, _ = env
    body = client.post("/api/scan", json={"kind": "url", "input": "https://www.youtube.com/"}).json()
    assert body["tag"] == "SAFE" and body["domain_auth"]["legitimate_site"] is True


# ------------------------------------------------------------------ downloader (no network: fake fetch)

def _fake_fetch(rows: int, list_id: str = "ABC12", psl: bytes | None = None):
    csv = "".join(f"{i},site{i}.com\n" for i in range(1, rows + 1))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("top-1m.csv", csv)
    psl = psl if psl is not None else rep_mod.BUNDLED_PSL.read_bytes()

    def fetch(url, timeout):
        return {rep_mod.TRANCO_ID_URL: list_id.encode(), rep_mod.TRANCO_LIST_URL: buf.getvalue(),
                rep_mod.PSL_URL: psl}[url]
    return fetch


def test_update_installs_validated_list(tmp_path):
    path = tmp_path / "rep" / "top-sites.csv"
    meta = rep_mod.update(path, top_n=5000, fetch=_fake_fetch(8000))
    assert meta["rows"] == 5000 and meta["list_id"] == "ABC12"
    rep = Reputation.load(path, top_n=5000)
    assert rep.lookup("www.site42.com").trusted and not rep.lookup("site6000.com").trusted
    assert (path.parent / "public_suffix_list.dat").exists()


def test_update_rejects_bad_downloads_and_keeps_current_list(tmp_path):
    path = tmp_path / "rep" / "top-sites.csv"
    rep_mod.update(path, top_n=5000, fetch=_fake_fetch(8000))
    before = path.read_bytes()
    with pytest.raises(ValueError):
        rep_mod.update(path, top_n=5000, fetch=_fake_fetch(10))                       # too short
    with pytest.raises(ValueError):
        rep_mod.update(path, top_n=5000, fetch=_fake_fetch(8000, list_id="<html>"))   # bad id
    with pytest.raises(ValueError):
        rep_mod.update(path, top_n=5000, fetch=_fake_fetch(8000, psl=b"not a psl"))   # bad PSL
    assert path.read_bytes() == before


def test_no_list_ships_with_the_code():
    root = Path(__file__).resolve().parents[2]
    assert not (root / "backend" / "data" / "reputation" / "top-sites.csv").exists()
