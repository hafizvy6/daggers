"""Live Checker: the 18 required scenarios, end to end through HTTP.

Checker → POST /api/check → engine → trust policy → evidence → SQLite → findings API →
Police Portal. Official-source cases use SYNTHETIC registry entries and records on
.example domains (backend/tests/ws2/data) — never real government evidence.
"""
from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.config import Settings
from backend.app.main import create_app
from backend.tests.conftest import login_as
from backend.tests.ws2 import helpers

_ids = itertools.count(1)


def rid() -> str:
    return f"test-req-{next(_ids):06d}"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "template")
    settings = Settings(
        db_path=tmp_path / "d.db", evidence_dir=tmp_path / "e", gallery_dir=tmp_path / "g",
        web_dir=Path(__file__).resolve().parents[2] / "web", cors_origins=[], heartbeat_interval_s=1,
        crt_poll_interval_s=20, feed_poll_interval_s=20, pipeline_poll_interval_s=1, ai_state="template",
        official_snapshot_dir=tmp_path / "snap", scan_rate_per_min=500,
    )
    app = create_app(settings)
    app.state.runtime.trust_policy = helpers.scorer()   # synthetic registry + records
    with TestClient(app) as client:
        yield client, app


def check(client, text, *, request_id=None, lang="en", status=(200, 201)):
    response = client.post("/api/check", json={"input": text, "lang": lang, "request_id": request_id or rid()})
    assert response.status_code in (status if isinstance(status, tuple) else (status,)), response.text
    return response.json()


def names(finding):
    return {s["name"] for s in finding["signals"]}


# ------------------------------------------------------------------ 1–5: URLs

def test_01_legitimate_approved_government_url_is_safe(env):
    client, _ = env
    f = check(client, "https://police.gov.example/")
    assert f["tag"] == "SAFE" and f["domain_auth"]["status"] == "AUTHENTICATED"
    assert f["input_type"] == "url" and f["scan_status"] == "completed"
    assert "stay_alert" in f["precautions"]


def test_02_unknown_website_is_never_safe(env):
    client, _ = env
    f = check(client, "unknown-bakery-dubai.example")
    assert f["tag"] == "WARNING"
    assert f["normalized_url"] == "https://unknown-bakery-dubai.example/"
    assert f["domain_auth"]["status"] == "UNLISTED"
    assert "unverified_not_safe" in f["precautions"]


def test_03_suspicious_bank_login_url_is_fake(env):
    client, _ = env
    f = check(client, "https://adcb-secure-login.xyz/login?utm_source=sms&id=7")
    assert f["tag"] == "FAKE" and f["verdict"] == "MALICIOUS"
    assert f["normalized_url"] == "https://adcb-secure-login.xyz/login?id=7"   # tracking removed
    assert {"identity.brand_typo_d1", "lexical.risky_tld", "lexical.lure_keyword"} <= names(f)
    sig = next(s for s in f["signals"] if s["name"] == "lexical.lure_keyword")
    assert sig["part"] == "path" and sig["excerpt"] == "login" and sig["category"] == "phishing"
    assert {"dont_click", "never_share_codes", "use_official_channel", "report_block"} <= set(f["precautions"])


def test_04_government_impersonation_url_is_fake(env):
    client, _ = env
    f = check(client, "https://abudhabi-police-fines.top/pay")
    assert f["tag"] == "FAKE"
    gov = [s for s in f["signals"] if s["category"] == "government_impersonation"]
    assert gov and gov[0]["name"] == "identity.brand_embedded"


def test_05_homograph_domain_is_fake(env):
    client, _ = env
    f = check(client, "https://аdcb.ae/login")          # Cyrillic 'а'
    assert f["tag"] == "FAKE"
    assert "homograph.mixed_or_spoof" in names(f)
    assert f["homograph"]["spoof"] or f["homograph"]["mixed_script"]


# ------------------------------------------------------------------ 6–9: messages

def test_06_fake_delivery_fee_message(env):
    client, _ = env
    text = ("Emirates Post: your parcel is on hold due to an unpaid customs fee of AED 12.50. "
            "Pay within 24 hours: https://emiratespost-uae.top/pay")
    f = check(client, text)
    assert f["tag"] == "FAKE" and f["input_type"] == "text"
    assert {"message.payment_demand", "message.delivery_lure", "message.urgency_threat",
            "message.impersonation_brand"} <= names(f)
    assert f["scam_type"] == "fake-delivery-fee"
    assert f["analyzed_url"] == "https://emiratespost-uae.top/pay"
    assert "dont_pay" in f["precautions"]


def test_06b_delivery_fee_message_without_link_is_warning_not_fake(env):
    client, _ = env
    f = check(client, "Your parcel delivery failed. Pay the redelivery fee of 5 AED.")
    assert f["tag"] == "WARNING"            # no link / no credential request → never confirmed FAKE
    assert {"message.payment_demand", "message.delivery_lure"} <= names(f)
    assert "claims.unverifiable" not in names(f)   # a fee demand is not reported as a prize claim


def test_07_fake_government_giveaway_message(env):
    client, _ = env
    text = ("Abu Dhabi Police: congratulations! You won AED 50,000 in the national giveaway. "
            "Claim your prize now at http://adpolice-gift.com")
    f = check(client, text)
    assert f["tag"] == "FAKE"
    assert {"claims.unverifiable", "message.impersonation_government", "identity.brand_embedded"} <= names(f)


def test_07b_giveaway_claim_without_link_is_misleading(env):
    client, _ = env
    f = check(client, "Abu Dhabi government is giving away 1 million dirhams to every resident")
    assert f["tag"] == "MISLEADING"


def test_07c_arabic_government_fine_message(env):
    client, _ = env
    text = "شرطة أبوظبي: تم تسجيل مخالفة عليك. ادفع الغرامة 500 درهم خلال 24 ساعة عبر الرابط https://adpolice-pay.top"
    f = check(client, text, lang="ar")
    assert f["tag"] == "FAKE"
    assert {"message.impersonation_government", "message.payment_demand", "message.urgency_threat"} <= names(f)


def test_07d_arabic_prize_and_otp_request(env):
    client, _ = env
    f = check(client, "مبروك! ربحت جائزة 100,000 درهم من شرطة أبوظبي. أرسل رمز التحقق لاستلامها", lang="ar")
    assert f["tag"] == "FAKE"                # asks for an OTP: an action channel without a link
    assert "message.credential_request" in names(f)


def test_08_suspicious_message_containing_url(env):
    client, _ = env
    text = "Your ADCB account will be suspended. Verify now: https://adcb-verify-account.xyz/login"
    f = check(client, text)
    assert f["tag"] == "FAKE"
    assert f["urls"][0]["url"] == "https://adcb-verify-account.xyz/login"
    assert "message.urgency_threat" in names(f) and "identity.brand_typo_d1" in names(f)
    assert f["domain_auth"]["host"] == "adcb-verify-account.xyz"


def test_08b_otp_request_without_link(env):
    client, _ = env
    f = check(client, "Your ADCB account will be suspended. Send us the OTP you received to verify your account.")
    assert f["tag"] == "FAKE"
    assert {"message.credential_request", "message.impersonation_brand"} <= names(f)


def test_09_ordinary_legitimate_message_is_warning_not_safe(env):
    client, _ = env
    f = check(client, "Hi Sara, the meeting is moved to 5pm tomorrow. See you there.")
    assert f["tag"] == "WARNING" and f["signals"] == []
    assert f["domain_auth"]["status"] == "NOT_CHECKABLE"
    assert f["checks"][1] == {"id": "domain_authentication", "status": "not_applicable",
                              "detail": "message contains no link to authenticate"}


def test_09b_arabic_ordinary_message(env):
    client, _ = env
    f = check(client, "مرحبا أحمد، الاجتماع غدًا الساعة الخامسة مساءً.", lang="ar")
    assert f["tag"] == "WARNING" and f["signals"] == []


# ------------------------------------------------------------------ 10–13: failures

@pytest.mark.parametrize("value,code", [
    ("javascript:alert(1)", "unsupported_scheme"),
    ("ftp://files.example.com/x", "unsupported_scheme"),
    ("http://", "invalid_host"),
    ("hi", "too_short"),
    ("x" * 4001, None),
])
def test_10_invalid_input_is_rejected_and_not_stored(env, value, code):
    client, app = env
    r = client.post("/api/check", json={"input": value, "request_id": rid()})
    assert r.status_code == 422
    if code:
        assert r.json()["detail"]["code"] == code
    assert app.state.runtime.repo.counts()["findings"] == 0


@pytest.mark.parametrize("value", ["", "   ", "\n\t"])
def test_11_empty_input_is_rejected(env, value):
    client, app = env
    r = client.post("/api/check", json={"input": value, "request_id": rid()})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "empty"
    assert app.state.runtime.repo.counts()["findings"] == 0


def test_12_official_source_unavailable_is_reported(env):
    client, app = env
    failed = [helpers.OfficialRecord("x", "syn-transport", "https://sta.gov.example/news", "", "2026-11-24T11:00:00Z",
                                     fetch_status="error", fetch_error="timeout")]
    app.state.runtime.trust_policy = helpers.scorer(records=failed)
    f = check(client, "Synthetic Transport Authority announces a parking fee of AED 4 per hour. Details: https://parking-info.example/")
    assert f["gov_verification"]["status"] == "SOURCE_UNAVAILABLE"
    assert f["tag"] != "SAFE" and f["manual_review"] is True
    assert f["scan_status"] == "partial"
    gov_check = next(c for c in f["checks"] if c["id"] == "official_verification")
    assert gov_check["status"] == "incomplete" and "syn-transport" in gov_check["detail"]


def test_12b_trust_policy_unavailable_never_safe(env):
    client, app = env
    app.state.runtime.trust_policy = None
    f = check(client, "https://police.gov.example/")
    assert f["tag"] == "WARNING" and f["scan_status"] == "partial"
    assert {c["id"]: c["status"] for c in f["checks"]}["domain_authentication"] == "unavailable"


def test_13_backend_analysis_failure_is_reported_and_nothing_stored(env, monkeypatch):
    client, app = env

    def broken(*a, **k):
        raise RuntimeError("engine crashed")

    monkeypatch.setattr(app.state.runtime, "scan", broken)
    r = client.post("/api/check", json={"input": "https://adcb-secure-login.xyz/", "request_id": rid()})
    assert r.status_code == 503 and r.json()["detail"]["code"] == "analysis_failed"
    assert r.json()["detail"]["result"] is None
    assert app.state.runtime.repo.counts()["findings"] == 0


def test_13b_persistence_failure_is_reported_honestly(env, monkeypatch):
    client, app = env

    def broken(**kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(app.state.runtime.repo, "insert_check_finding", broken)
    r = client.post("/api/check", json={"input": "https://adcb-secure-login.xyz/", "request_id": rid()})
    body = r.json()["detail"]
    assert r.status_code == 503 and body["code"] == "persist_failed"
    assert body["result"]["id"] is None and body["result"]["tag"] == "FAKE"   # shown, marked not saved


# ------------------------------------------------------------------ 14–18: storage + portal

def test_14_database_persistence_of_every_field(env):
    client, app = env
    text = "Emirates Post: parcel held, pay customs fee AED 9 at https://emiratespost-uae.top/pay. Call 050 123 4567, mail me ali@example.com"
    f = check(client, text)
    stored = app.state.runtime.repo.get_finding(f["id"])
    for key in ("tag", "input_type", "submitted_input", "analyzed_url", "signals", "trust_reasons", "domain_auth",
                "gov_verification", "risk_score", "scanned_at", "scan_status", "checks", "precautions", "policy_version",
                "engine_version"):
        assert stored[key] == f[key], key
    assert stored["source"] == "checker" and stored["domain"] == "emiratespost-uae.top"
    # personal data removed before storage, link kept as evidence
    assert "050 123 4567" not in stored["submitted_input"] and "ali@example.com" not in stored["submitted_input"]
    assert "https://emiratespost-uae.top/pay" in stored["submitted_input"]
    assert stored["redactions"] == {"phone": 1, "email": 1}
    assert all("050 123 4567" not in (s.get("excerpt") or "") for s in stored["signals"])


def test_15_police_portal_retrieval_and_privacy(env):
    client, app = env
    f = check(client, "https://adcb-secure-login.xyz/login")
    anon = TestClient(app)
    assert anon.get(f"/api/finding/{f['id']}").status_code == 401             # portal data
    assert f["id"] not in [x["id"] for x in anon.get("/api/feed?limit=200").json()]
    assert anon.get("/api/portal/findings").status_code == 401
    # the Guard lists only the confirmed-fake DOMAIN (Checker → Guard live loop); the submission itself,
    # the finding and its id stay portal-only
    blocklist = anon.get("/api/guard/blocklist.txt").text
    assert ("adcb-secure-login.xyz" in blocklist) == (f["tag"] == "FAKE")
    assert "adcb-secure-login.xyz/login" not in blocklist
    assert all("id" not in row and "finding_id" not in row for row in
               (json.loads(line) for line in anon.get("/api/guard/feed").text.splitlines() if line))
    assert all(row["finding_id"] is None for row in anon.get("/api/guard/stats").json()["newest_fakes"])
    login_as(client, app, "viewer")
    portal = client.get(f"/api/finding/{f['id']}").json()
    for key in ("tag", "signals", "trust_reasons", "domain_auth", "checks", "precautions", "submitted_input"):
        assert portal[key] == f[key], key
    listed = client.get("/api/portal/findings").json()
    assert [x["id"] for x in listed["findings"]] == [f["id"]] and listed["findings"][0]["tag"] == f["tag"]


def test_16_evidence_is_traceable_to_the_input(env):
    client, _ = env
    f = check(client, "URGENT: your account will be suspended within 24 hours. Send the OTP to keep it: https://wio-secure.top/x")
    for s in f["signals"]:
        assert {"name", "reason", "weight", "category", "part", "excerpt"} <= set(s)
        if s["part"] == "message":
            assert s["excerpt"].strip("…").split()[0] in f["submitted_input"]
    assert f["checks"][0]["id"] == "engine" and f["checks"][0]["status"] == "completed"


def test_17_multiple_findings_search_and_filters(env):
    client, app = env
    a = check(client, "https://adcb-secure-login.xyz/login")
    b = check(client, "Hi Sara, the meeting is moved to 5pm tomorrow.")
    c = check(client, "Abu Dhabi government is giving away 1 million dirhams to every resident")
    d = check(client, "https://police.gov.example/")
    login_as(client, app, "viewer")
    get = lambda **q: client.get("/api/portal/findings", params=q).json()  # noqa: E731
    assert get()["total"] == 4
    assert [x["id"] for x in get()["findings"]] == [d["id"], c["id"], b["id"], a["id"]]   # newest first
    assert [x["id"] for x in get(tag="FAKE")["findings"]] == [a["id"]]
    assert [x["id"] for x in get(tag="MISLEADING")["findings"]] == [c["id"]]
    assert {x["id"] for x in get(input_type="text")["findings"]} == {b["id"], c["id"]}
    assert {x["id"] for x in get(input_type="url")["findings"]} == {a["id"], d["id"]}
    assert [x["id"] for x in get(q="meeting")["findings"]] == [b["id"]]
    assert [x["id"] for x in get(q=f"#{a['id']}")["findings"]] == [a["id"]]
    assert get(source="checker")["total"] == 4 and get(source="investigation")["total"] == 0
    today = a["scanned_at"][:10]
    assert get(date_from=today, date_to=today)["total"] == 4
    assert get(date_from="2001-01-01", date_to="2001-01-02")["total"] == 0
    assert client.get("/api/portal/findings", params={"date_from": "yesterday"}).status_code == 422
    page = get(limit=2, offset=2)
    assert [x["id"] for x in page["findings"]] == [b["id"], a["id"]] and page["total"] == 4
    assert get()["facets"]["tag"] == {"FAKE": 1, "WARNING": 1, "MISLEADING": 1, "SAFE": 1}


def test_18_refresh_and_repeated_requests_do_not_duplicate(env):
    client, app = env
    first = check(client, "https://adcb-secure-login.xyz/login", request_id="same-click-0001")
    assert first["duplicate"] is False
    again = client.post("/api/check", json={"input": "https://adcb-secure-login.xyz/login", "request_id": "same-click-0001"})
    assert again.status_code == 200 and again.json()["id"] == first["id"] and again.json()["duplicate"] is True
    # a new click with identical input from the same client inside the window → same finding
    third = check(client, "  https://adcb-secure-login.xyz/login  ")
    assert third["id"] == first["id"] and third["duplicate"] is True
    # portal reads never create anything
    login_as(client, app, "viewer")
    for _ in range(3):
        assert client.get("/api/portal/findings").json()["total"] == 1
        client.get(f"/api/finding/{first['id']}")
    assert app.state.runtime.repo.counts()["findings"] == 1
    # with result reuse switched off it is a new, separate check
    app.state.runtime.settings.__dict__["check_cache_ttl_s"] = 0
    fourth = check(client, "https://adcb-secure-login.xyz/login")
    assert fourth["id"] != first["id"]


def test_checker_and_scan_agree_on_the_tag(env):
    client, _ = env
    for value in ("https://adcb-secure-login.xyz/login", "https://police.gov.example/", "https://unknown-shop.example/"):
        scanned = client.post("/api/scan", json={"kind": "url", "input": value, "lang": "en"}).json()
        assert check(client, value)["tag"] == scanned["tag"], value


def test_request_id_and_rate_limit(env):
    client, app = env
    bad = client.post("/api/check", json={"input": "https://a.example/", "request_id": "bad id!"})
    assert bad.status_code == 422
    app.state.runtime.scan_limiter = type(app.state.runtime.scan_limiter)(1, 60)
    assert client.post("/api/check", json={"input": "https://a.example/", "request_id": rid()}).status_code in (200, 201)
    limited = client.post("/api/check", json={"input": "https://b.example/", "request_id": rid()})
    assert limited.status_code == 429 and limited.json()["detail"]["code"] == "rate_limited"


# ------------------------------------------------------------------ LOCAL_OPEN_ACCESS (dev convenience)

def test_local_open_access_is_off_by_default_and_forced_off_in_production(env):
    client, app = env
    assert app.state.runtime.settings.local_open_access is False
    assert client.get("/api/portal/findings").status_code == 401
    prod = Settings.from_env({"APP_ENV": "production", "LOCAL_OPEN_ACCESS": "1"})
    assert prod.local_open_access is False
    assert Settings.from_env({"APP_ENV": "dev", "LOCAL_OPEN_ACCESS": "1"}).local_open_access is True


def test_local_open_access_only_for_this_machine_and_keeps_csrf(env, monkeypatch):
    client, app = env
    from backend.app import security

    app.state.runtime.settings.__dict__["local_open_access"] = True
    # TestClient's peer is "testclient" (not loopback) → still no access
    assert client.get("/api/portal/findings").status_code == 401
    monkeypatch.setattr(security, "is_local_request", lambda request: True)
    me = client.get("/api/auth/me").json()
    assert me["user"] == {"username": "local", "role": "admin", "local": True}
    assert client.get("/api/portal/findings").status_code == 200
    # state changes still need the same-origin CSRF token
    assert client.post("/api/investigations", json={"url": "https://adcb-secure-login.xyz/"}).status_code == 403
    ok = client.post("/api/investigations", json={"url": "https://adcb-secure-login.xyz/"},
                     headers={"X-CSRF-Token": me["csrf_token"]})
    assert ok.status_code == 201 and ok.json()["investigator"] == "local"
    monkeypatch.undo()
    # a request relayed by a proxy is never "local"
    app.state.runtime.settings.__dict__["local_open_access"] = True
    proxied = TestClient(app, client=("127.0.0.1", 50000))
    assert proxied.get("/api/portal/findings", headers={"X-Forwarded-For": "203.0.113.9"}).status_code == 401
    assert proxied.get("/api/portal/findings").status_code == 200
