from __future__ import annotations

import asyncio
import json
from pathlib import Path

from backend.app.reports.builder import validate_zero_pii

FINDING_KEYS = {
    "id", "domain", "verdict", "score", "reasons", "cert_issued", "first_seen",
    "source", "clone", "evidence_url", "gallery_match", "is_case_file",
}
SCAN_KEYS = {
    "kind", "input", "verdict", "score", "reasons",
    "evidence_url", "scam_type", "offline_capable",
}
GUARD_KEYS = {"domain", "verdict", "reason", "flagged_at"}


def test_status_contract(api_env):
    client, _, _ = api_env
    response = client.get("/api/status")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"mode", "heartbeats", "counts", "uptime_s"}
    assert body["mode"] == "demo"
    assert set(body["heartbeats"]) == {"crt", "phishtank", "pipeline", "ai"}
    assert all(isinstance(value, int) for key, value in body["heartbeats"].items() if key != "ai")
    assert set(body["counts"]) == {"domains", "findings", "evidence"}
    assert body["counts"]["findings"] >= 6
    assert isinstance(body["uptime_s"], int)


def test_feed_and_finding_are_exact_c1(api_env):
    client, _, _ = api_env
    feed = client.get("/api/feed?limit=5").json()
    assert isinstance(feed, list) and len(feed) == 5
    assert all(set(row) == FINDING_KEYS for row in feed)
    assert feed[0]["id"] >= feed[1]["id"] or feed[0]["first_seen"] >= feed[1]["first_seen"]
    detail = client.get("/api/finding/42")
    assert detail.status_code == 200
    assert set(detail.json()) == FINDING_KEYS
    assert detail.json()["domain"] == "adcb-secure-login.xyz"
    assert isinstance(detail.json()["clone"], int)
    assert client.get("/api/finding/999999").status_code == 404


def test_scan_url_contract_and_evidence_lookup(api_env):
    client, _, _ = api_env
    response = client.post(
        "/api/scan",
        json={"kind": "url", "input": "https://adcb-secure-login.xyz/login", "lang": "en"},
    )
    assert response.status_code == 200
    body = response.json()
    assert set(body) == SCAN_KEYS
    assert body["kind"] == "url"
    assert body["verdict"] == "MALICIOUS"
    assert body["evidence_url"] == "/evidence/42.jpg"
    assert body["offline_capable"] is True


def test_scan_number_and_text_claims(api_env):
    client, _, _ = api_env
    number = client.post(
        "/api/scan",
        json={"kind": "number", "input": "+971900000042", "lang": "en"},
    ).json()
    assert set(number) == SCAN_KEYS
    assert number["verdict"] == "MALICIOUS"
    assert number["evidence_url"] is None

    claim = client.post(
        "/api/scan",
        json={"kind": "text", "input": "Abu Dhabi bank is giving away 1 million dirhams", "lang": "en"},
    ).json()
    assert set(claim) == SCAN_KEYS
    assert claim["verdict"] == "MISLEADING"
    assert claim["scam_type"] == "unverifiable-giveaway-claim"
    assert client.post(
        "/api/scan",
        json={"kind": "banana", "input": "x"},
    ).status_code == 422


def test_guard_feed_is_policy_filtered_jsonl(api_env):
    client, _, _ = api_env
    response = client.get("/api/guard/feed")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    rows = [json.loads(line) for line in response.text.splitlines() if line.strip()]
    assert rows
    assert all(set(row) == GUARD_KEYS for row in rows)
    assert all(row["verdict"] == "MALICIOUS" for row in rows)
    assert len({row["domain"] for row in rows}) == len(rows)
    assert "xn--mazon-3ve.ae" in {row["domain"] for row in rows}


def test_evidence_jpeg_is_served_by_api_and_static_mount(api_env):
    client, settings, _ = api_env
    for path in ("/api/evidence/42.jpg", "/evidence/42.jpg"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("image/jpeg")
        assert response.content[:2] == b"\xff\xd8"
    assert (settings.evidence_dir / "42.jpg").exists()


def test_mode_toggle_switches_fixture_and_sqlite_tables(api_env):
    client, _, _ = api_env
    assert client.get("/api/mode").json() == {"mode": "demo"}
    assert client.post("/api/mode", json={"mode": "live"}).json() == {"mode": "live"}
    assert client.get("/api/status").json()["mode"] == "live"
    live_feed = client.get("/api/feed?limit=10").json()
    assert live_feed and all(set(row) == FINDING_KEYS for row in live_feed)
    assert client.post("/api/mode", json={"mode": "venue"}).status_code == 422
    assert client.post("/api/mode", json={"mode": "demo"}).json() == {"mode": "demo"}


def test_seed_on_boot_creates_db_and_assets(api_env):
    _, settings, app = api_env
    assert settings.db_path.exists()
    assert (settings.evidence_dir / "42.jpg").stat().st_size > 10_000
    assert app.state.runtime.repo.get_meta("seeded_at")


def test_sse_heartbeat_and_sweep_event(api_env):
    _, _, app = api_env
    runtime = app.state.runtime

    async def not_disconnected():
        return False

    async def collect():
        stream = runtime.event_stream(not_disconnected)
        first = await anext(stream)
        assert first.startswith("event: heartbeat\ndata: ")
        runtime.publish("sweep", {"id": "sweep-1", "channel": "web"})
        second = await asyncio.wait_for(anext(stream), timeout=2)
        assert second.startswith("event: sweep\ndata: ")
        assert '"id":"sweep-1"' in second
        await stream.aclose()

    asyncio.run(collect())


def test_optional_routers_are_skipped_without_ws2_ws3(api_env):
    _, _, app = api_env
    states = app.state.runtime.optional_routers
    assert "backend.app.api.sweep" in states
    assert "backend.app.api.guard" in states
    assert states["backend.app.api.sweep"].startswith("skipped:")


def test_fixture_reports_pass_recursive_zero_pii_check(api_env):
    _, settings, _ = api_env
    reports = json.loads((settings.seed_dir / "fixtures" / "reports.json").read_text(encoding="utf-8"))
    assert reports
    for report in reports:
        validate_zero_pii(report)


def test_no_sql_outside_repo_module():
    app_dir = Path(__file__).resolve().parents[1] / "app"
    markers = ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "CREATE TABLE")
    offenders: list[str] = []
    for path in app_dir.rglob("*.py"):
        if path.name == "repo.py":
            continue
        text = path.read_text(encoding="utf-8")
        if any(marker in text for marker in markers):
            offenders.append(str(path.relative_to(app_dir)))
    assert offenders == []


def test_guard_misleading_policy_is_configurable(api_env):
    _, _, app = api_env
    rows = app.state.runtime.repo.get_guard_rows("demo", guard_block_misleading=True)
    assert any(row["verdict"] == "MISLEADING" for row in rows)
    assert any(row["domain"] == "adcb-giveaway-1m.top" for row in rows)


def test_seed_casefiles_are_three_prebuilt_cases(api_env):
    _, settings, _ = api_env
    cases = json.loads((settings.seed_dir / "casefiles" / "cases.json").read_text(encoding="utf-8"))
    assert len(cases) == 3
    assert {case["id"] for case in cases} == {42, 43, 44}


def test_scope_audit_no_ws2_ws3_or_redundant_files():
    root = Path(__file__).resolve().parents[2]
    forbidden = [
        "web",
        "guard",
        "channels",
        "extension",
        "backend/app/ai",
        "backend/app/api/sweep.py",
        "backend/app/api/guard.py",
        "backend/app/api/reports.py",
        "backend/app/api/ai.py",
        "ops",
        "requirements-render.txt",
        "pytest.ini",
        "docs/UI-KIT.md",
    ]
    assert not any((root / path).exists() for path in forbidden)
    assert not list((root / "docs").glob("daggers-*.md"))
    assert "backend/data/" in (root / ".gitignore").read_text(encoding="utf-8")


def test_enricher_failure_returns_complete_s5_shape(monkeypatch, tmp_path):
    from backend.app.catalog import load_catalogs
    from backend.app.config import Settings
    from backend.app.radar.enrich import Enricher

    seed_dir = Path(__file__).resolve().parents[1] / "seed"
    settings = Settings.from_env(
        {
            "MODE": "live",
            "DEMO_MODE": "0",
            "ENRICH_ENABLED": "1",
            "HTTP_TIMEOUT_S": "0.01",
            "DB_PATH": str(tmp_path / "db.sqlite"),
            "EVIDENCE_DIR": str(tmp_path / "evidence"),
            "GALLERY_DIR": str(tmp_path / "gallery"),
            "SEED_DIR": str(seed_dir),
            "WEB_DIR": str(tmp_path / "web"),
            "CORS_ORIGINS": "",
        }
    )
    enricher = Enricher(settings, load_catalogs())

    async def fail(*args, **kwargs):
        raise RuntimeError("offline")

    for method in ("_rdap", "_dns", "_tls", "_favicon"):
        monkeypatch.setattr(enricher, method, fail)
    result = asyncio.run(enricher.enrich("example.com", mode="live"))
    assert set(result) == {
        "rdap_created",
        "rdap_registrar",
        "dns_a",
        "tls_issued",
        "tls_issuer",
        "favicon_hash",
        "cert_age_hours",
    }
    assert result["dns_a"] == []
