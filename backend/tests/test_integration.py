"""End-to-end integration tests for the merged Daggers application.

These drive the real app (WS1 runtime + WS2 trust policy/channels + WS3 reports/AI)
through HTTP. Official-source cases use the SYNTHETIC registry/records fixtures
(.example domains); no real government evidence is fabricated.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.config import Settings
from backend.app.main import create_app
from backend.tests.conftest import TEST_PASSWORD, login_as
from backend.tests.ws2 import helpers


def make_settings(tmp_path: Path, **overrides) -> Settings:
    base = dict(
        db_path=tmp_path / "daggers.db", evidence_dir=tmp_path / "evidence", gallery_dir=tmp_path / "gallery",
        web_dir=Path(__file__).resolve().parents[2] / "web",
        mode="live", environment="dev", cors_origins=[], heartbeat_interval_s=1,
        crt_poll_interval_s=20, feed_poll_interval_s=20, pipeline_poll_interval_s=1, ai_state="template",
    )
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def live(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "template")
    app = create_app(make_settings(tmp_path))
    # Synthetic official registry + records so authenticated/verified paths are exercised.
    app.state.runtime.trust_policy = helpers.scorer()
    with TestClient(app) as client:
        yield client, app


# ------------------------------------------------------------------ the mandatory flow


def test_portal_flow_url_to_persisted_finding_report_ai_guard(live):
    client, app = live
    login_as(client, app, "investigator")
    # Government claim WITHOUT a money offer (WS1 caps offer-claims at MISLEADING by design).
    page = "SIRA announces visa amnesty for overstayers until 31 December 2026. Register today."
    r = client.post("/api/investigations", json={"url": "https://adcb-secure-login.xyz/login?utm_source=x",
                                                  "page_text": page})
    assert r.status_code == 201, r.text
    finding = r.json()
    fid = finding["id"]
    # scoring + central verdict + separate layers
    assert finding["tag"] == "FAKE"
    assert finding["verdict"] == "MALICIOUS"
    assert finding["domain_auth"]["status"] == "UNLISTED"
    assert finding["gov_verification"]["status"] == "CONTRADICTED"
    assert finding["gov_verification"]["evidence_id"].startswith("gv_")
    assert finding["signals"] and all("reason" in s for s in finding["signals"])
    assert finding["submitted_url"] == "https://adcb-secure-login.xyz/login"  # tracking param stripped
    # persisted in SQLite (not just returned)
    stored = app.state.runtime.repo.get_finding(fid, "live")
    assert stored["tag"] == "FAKE" and stored["gov_verification"]["status"] == "CONTRADICTED"
    # portal can read it back; anonymous users cannot
    assert client.get(f"/api/finding/{fid}").json()["tag"] == "FAKE"
    anon = TestClient(app)
    assert anon.get(f"/api/finding/{fid}").status_code == 401
    assert fid not in [f["id"] for f in anon.get("/api/feed?limit=200").json()]
    assert fid in [f["id"] for f in client.get("/api/investigations").json()["findings"]]
    # report → zero-PII evidence with the same tag
    rep = client.post("/api/reports", json={"finding_id": fid})
    assert rep.status_code == 201, rep.text
    report = rep.json()
    assert report["evidence"]["tag"] == "FAKE"
    assert report["evidence"]["evidence_id"] == finding["gov_verification"]["evidence_id"]
    assert client.post("/api/reports", json={"finding_id": fid}).json()["id"] == report["id"]  # idempotent
    # AI Analyst: grounded template (no provider key), stored on the report
    with client.stream("POST", f"/api/report/{report['id']}/analysis") as stream:
        body = "".join(stream.iter_text())
    final = json.loads(body.split("event: final\ndata: ")[1].split("\n\n")[0])
    assert final["fallback"] is True and "FAKE" in final["summary_en"]
    assert "CONTRADICTED" in final["summary_en"]
    assert "Synthetic Residency Authority" in final["summary_en"]  # cited official source
    assert client.get(f"/api/reports/{report['id']}").json()["ai"]["provider"] == "template"
    # export pack carries the finding and provenance
    pack = client.get(f"/api/reports/{report['id']}/export").json()
    assert pack["finding"]["gov_verification"]["evidence"][0]["source_url"].startswith("https://sira.gov.example")
    assert pack["registry_version"].startswith("reg_")
    # Guard consumes the confirmed FAKE domain
    blocklist = client.get("/api/guard/blocklist.txt").text
    assert "0.0.0.0 adcb-secure-login.xyz" in blocklist
    # audit trail
    actions = {(e["action"], e["outcome"]) for e in app.state.runtime.repo.list_audit()}
    assert {("auth.login", "ok"), ("investigation.create", "ok"), ("report.file", "ok"), ("ai.analysis", "ok")} <= actions


def test_extension_and_api_and_portal_agree_on_the_tag(live):
    client, app = live
    login_as(client, app, "investigator")
    for url, expected in (("https://police.gov.example/", "SAFE"), ("https://totally-unknown.example/", "WARNING"),
                          ("https://pending.gov.example/", "WARNING"), ("https://adcb-secure-login.xyz/", "FAKE")):
        scan = client.post("/api/scan", json={"kind": "url", "input": url, "lang": "en"}).json()  # extension path
        inv = client.post("/api/investigations", json={"url": url}).json()                        # portal path
        assert scan["tag"] == inv["tag"] == expected, (url, scan["tag"], inv["tag"])
        assert client.get(f"/api/finding/{inv['id']}").json()["tag"] == expected
        assert scan["domain_auth"]["authenticated"] is (expected == "SAFE")


# ------------------------------------------------------------------ required scenarios via HTTP


@pytest.mark.parametrize("url,text,tag,claim", [
    ("https://police.gov.example/", None, "SAFE", None),                                  # approved official
    ("https://unknown-shop.example/", "Fresh bread daily.", "WARNING", None),            # unknown / private business
    ("https://pending.gov.example/", None, "WARNING", None),                             # pending
    ("https://revoked.gov.example/", None, "WARNING", None),                             # revoked
    ("https://expired.gov.example/", None, "WARNING", None),                             # expired approval
    ("https://visa-amnesty.example/", "SIRA announces visa amnesty for overstayers until 31 December 2026.",
     "MISLEADING", "CONTRADICTED"),                                                      # false immigration claim
    ("https://moss-aid.example/", "Synthetic Ministry of Social Support announces an unemployment grant of AED 5,000.",
     "MISLEADING", "CONTRADICTED"),                                                      # false financial assistance
    ("https://forum.portal.gov.example/t/1", "Synthetic Ministry of Social Support is giving away AED 10,000. Claim your prize.",
     "WARNING", "CONTRADICTED"),                                                         # fraudulent UGC, official host
    ("https://housing.example/", "Synthetic Ministry of Social Support announces a housing grant of AED 50,000.",
     "WARNING", "CONFLICTING_SOURCES"),                                                  # conflicting sources
    ("https://sira.gov.example/ar", "أعلنت هيئة الإقامة التجريبية أن رسوم تجديد الإقامة الذهبية ١١٥٠ درهم",
     "SAFE", "VERIFIED"),                                                                # Arabic claim, English source
])
def test_scenarios_through_portal_api(live, url, text, tag, claim):
    client, app = live
    login_as(client, app, "investigator")
    out = client.post("/api/investigations", json={"url": url, "page_text": text}).json()
    assert out["tag"] == tag, out.get("trust_reasons")
    assert (out["gov_verification"] or {}).get("status") == claim


def test_source_unavailable_is_reported_not_checked(live):
    client, app = live
    failed = [helpers.OfficialRecord("x", "syn-transport", "https://sta.gov.example/news", "", "2026-11-24T11:00:00Z",
                                     fetch_status="error", fetch_error="timeout")]
    app.state.runtime.trust_policy = helpers.scorer(records=failed)
    login_as(client, app, "investigator")
    out = client.post("/api/investigations", json={
        "url": "https://parking.example/", "page_text": "Synthetic Transport Authority announces a parking fee of AED 4 per hour."}).json()
    gov = out["gov_verification"]
    assert gov["status"] == "SOURCE_UNAVAILABLE" and out["tag"] == "WARNING" and out["manual_review"]
    assert "syn-transport" in gov["unchecked_sources"]


def test_invalid_url_is_rejected(live):
    client, app = live
    login_as(client, app, "investigator")
    for bad in ("javascript:alert(1)", "not a url", "ftp://x.example/", "https://u:p@x.example/"):
        assert client.post("/api/investigations", json={"url": bad}).status_code == 422, bad


# ------------------------------------------------------------------ security


def test_auth_roles_csrf_and_lockout(live):
    client, app = live
    assert client.get("/api/reports").status_code == 401
    assert client.post("/api/investigations", json={"url": "https://a.example/"}).status_code == 401
    login_as(client, app, "viewer")
    assert client.get("/api/reports").status_code == 200
    assert client.post("/api/investigations", json={"url": "https://a.example/"}).status_code == 403
    assert client.get("/api/admin/users").status_code == 403
    # CSRF: a session without the header is refused for state changes
    del client.headers["X-CSRF-Token"]
    assert client.post("/api/auth/logout").status_code == 403
    # lockout after repeated failures (per username)
    other = TestClient(app)
    for _ in range(5):
        assert other.post("/api/auth/login", json={"username": "test-viewer", "password": "wrong-password-x"}).status_code == 401
    locked = other.post("/api/auth/login", json={"username": "test-viewer", "password": TEST_PASSWORD})
    assert locked.status_code == 429
    outcomes = [e["outcome"] for e in app.state.runtime.repo.list_audit() if e["action"] == "auth.login"]
    assert "failed" in outcomes and "locked" in outcomes


def test_session_cookie_flags_and_logout(live):
    client, app = live
    from backend.app import security

    app.state.runtime.repo.create_user("cookie-user", security.hash_password(TEST_PASSWORD), "viewer")
    r = client.post("/api/auth/login", json={"username": "cookie-user", "password": TEST_PASSWORD})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "secure" not in cookie  # dev: no TLS
    client.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    assert client.get("/api/auth/me").json()["user"]["username"] == "cookie-user"
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_admin_user_management_and_audit(live):
    client, app = live
    login_as(client, app, "admin")
    r = client.post("/api/admin/users", json={"username": "officer.one", "password": "short", "role": "investigator"})
    assert r.status_code == 422
    r = client.post("/api/admin/users", json={"username": "officer.one", "password": "a-long-enough-pass", "role": "investigator"})
    assert r.status_code == 201
    assert client.post("/api/admin/users/officer.one/active", json={"active": False}).json()["active"] is False
    denied = TestClient(app).post("/api/auth/login", json={"username": "officer.one", "password": "a-long-enough-pass"})
    assert denied.status_code == 401  # disabled accounts cannot sign in
    assert any(e["action"] == "admin.user.create" for e in client.get("/api/admin/audit").json()["entries"])


def test_offer_claim_on_lookalike_is_capped_at_misleading_by_ws1(live):
    """WS1 policy: an offer claim without clone/feed/form confirmation stays MISLEADING."""
    client, app = live
    login_as(client, app, "investigator")
    out = client.post("/api/investigations", json={
        "url": "https://adcb-secure-login.xyz/login",
        "page_text": "Synthetic Ministry of Social Support is giving away AED 10,000. Claim your prize now."}).json()
    assert out["verdict"] == "MISLEADING" and out["tag"] == "MISLEADING"
    assert out["gov_verification"]["status"] == "CONTRADICTED"


def test_security_headers_and_scan_rate_limit(tmp_path):
    app = create_app(make_settings(tmp_path, scan_rate_per_min=3))
    with TestClient(app) as client:
        r = client.get("/api/status")
        assert r.headers["x-frame-options"] == "DENY"
        assert "default-src 'self'" in r.headers["content-security-policy"]
        assert r.headers["x-content-type-options"] == "nosniff"
        codes = [client.post("/api/scan", json={"kind": "url", "input": "https://a.example/", "lang": "en"}).status_code
                 for _ in range(4)]
        assert codes == [200, 200, 200, 429]


def test_production_mode_is_honest(tmp_path, monkeypatch):
    for var in ("SEARCH_LIVE_ENABLED", "MAPS_LIVE_ENABLED", "SERPER_API_KEY", "GOOGLE_PLACES_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    settings = Settings.from_env({
        "APP_ENV": "production", "MODE": "demo",
        "DB_PATH": str(tmp_path / "p.db"), "EVIDENCE_DIR": str(tmp_path / "e"), "GALLERY_DIR": str(tmp_path / "g"),
        "WEB_DIR": str(Path(__file__).resolve().parents[2] / "web"), "CORS_ORIGINS": "",
    })
    assert settings.mode == "live" and settings.cookie_secure is True  # MODE=demo is ignored
    app = create_app(settings)
    with TestClient(app, base_url="https://testserver") as client:  # Secure cookies need HTTPS
        assert client.get("/api/feed").json() == []                     # nothing is ever seeded
        assert "strict-transport-security" in client.get("/api/status").headers
        login_as(client, app, "admin")
        assert client.post("/api/mode", json={"mode": "demo"}).status_code == 422  # demo mode does not exist
        run = client.post("/api/sweep?wait=true", json={"channel": "web"}).json()
        assert run["status"] == "failed" and "no search/maps provider" in run["error"]
        assert client.get("/api/readiness").json()["app_env"] == "production"


def test_database_failure_is_reported(live, monkeypatch):
    client, app = live

    def broken(*a, **k):
        raise RuntimeError("disk I/O error")

    monkeypatch.setattr(app.state.runtime.repo, "get_meta", broken)
    assert client.get("/api/healthz").status_code == 503


# ------------------------------------------------------------------ sweeps & guard


def test_sweep_lifecycle_persists_and_creates_findings_for_live_fakes(live):
    client, app = live
    login_as(client, app, "investigator")
    from backend.app.api import sweep as sweep_api
    from backend.app.channels.search import RawResult

    class LiveProvider:
        name, source_kind = "serper", "live"

        def search(self, query, lang, limit):
            return [RawResult("https://adcb-secure-login.xyz/login", "ADCB login", "verify your account"),
                    RawResult("https://police.gov.example/", "Synthetic Police", "official")]

    service = sweep_api.get_service(type("R", (), {"app": app})())
    service.search.providers = [LiveProvider()]
    run = client.post("/api/sweep?wait=true", json={"channel": "web"}).json()
    assert run["status"] == "completed" and run["store"] == "sqlite" and run["source_kind"] == "live"
    tags = {r["url"]: r["tag"] for r in run["results"]}
    assert tags["https://adcb-secure-login.xyz/login"] == "FAKE" and tags["https://police.gov.example/"] == "SAFE"
    fake_row = next(r for r in run["results"] if r["tag"] == "FAKE")
    assert fake_row["finding_id"] and client.get(f"/api/finding/{fake_row['finding_id']}").json()["tag"] == "FAKE"
    assert client.get(f"/api/sweep/{run['id']}").json()["results"] == run["results"]
    assert run["id"] in [r["id"] for r in client.get("/api/sweep").json()["runs"]]
    # background mode returns 202 immediately with a running/completed status
    # (no maps provider configured → the background run ends "failed", never with sample data)
    started = client.post("/api/sweep", json={"channel": "maps"})
    assert started.status_code == 202 and started.json()["status"] in {"running", "failed"}


def test_search_provider_failure_falls_back_honestly(live):
    client, app = live
    login_as(client, app, "investigator")
    from backend.app.api import sweep as sweep_api
    from backend.app.channels.http_client import ProviderError

    class Down:
        name, source_kind = "serper", "live"

        def search(self, *a):
            raise ProviderError("timeout")

    service = sweep_api.get_service(type("R", (), {"app": app})())
    service.search.providers = [Down()]
    run = client.post("/api/sweep?wait=true", json={"channel": "web"}).json()
    # a live provider failure is reported, never replaced with sample results
    assert run["status"] == "failed" and run["results"] == [] and "serper: ProviderError" in run["error"]
    service.maps.providers = [Down()]
    failed = client.post("/api/sweep?wait=true", json={"channel": "maps"}).json()
    assert failed["status"] == "failed"  # maps provider unavailable, no fixture → honest failure


def test_registry_and_guard_never_block_official_domains(live):
    client, app = live
    rt = app.state.runtime
    rt.repo.insert_finding(domain="police.gov.example", score=0.9, verdict="MALICIOUS", reasons=["test"],
                           source="crt.sh", first_seen="2026-11-24T08:00:00Z")
    assert "police.gov.example" not in client.get("/api/guard/blocklist.txt").text
    assert all(row["domain"] != "police.gov.example"
               for row in (json.loads(l) for l in client.get("/api/guard/feed").text.splitlines() if l))


def test_stream_events_carry_central_tag_and_hide_investigations(live):
    client, app = live
    rt = app.state.runtime
    queue = rt.events.subscribe()
    rt.publish("finding", {"id": 1, "domain": "police.gov.example", "verdict": "UNKNOWN", "score": 0.0,
                           "reasons": [], "source": "crt.sh"})
    rt.publish("finding", {"id": 2, "domain": "x.example", "verdict": "MALICIOUS", "source": "investigation"})
    first = queue.get_nowait()
    assert first["data"]["tag"] == "SAFE" and first["data"]["domain_auth"]["authenticated"] is True
    assert queue.empty()  # the investigation finding was not broadcast
    rt.events.unsubscribe(queue)


def test_auto_filed_report_evidence_is_tagged_and_share_route_serves_shell(live):
    client, app = live
    rt = app.state.runtime
    finding = rt.repo.insert_finding(domain="adcb-clone-login.xyz", score=0.97, verdict="MALICIOUS",
                                     reasons=["visual clone 96% match to adcb.ae"], source="crt.sh",
                                     clone_score=96.0, first_seen="2026-11-24T08:00:00Z")
    assert rt.report_queue.maybe_auto_file(finding) is not None
    login_as(client, app, "viewer")
    reports = client.get("/api/reports").json()["reports"]
    assert reports and all(r["evidence"]["tag"] in {"WARNING", "MISLEADING", "FAKE", "SAFE"} for r in reports)
    share = client.get("/share?url=https://a.example")
    assert share.status_code == 200 and "text/html" in share.headers["content-type"]
