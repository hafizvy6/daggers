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


def test_status_contract_on_empty_live_boot(api_env):
    client, _, _ = api_env
    response = client.get("/api/status")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"mode", "heartbeats", "counts", "uptime_s"}
    assert body["mode"] == "live"
    assert set(body["heartbeats"]) == {"crt", "phishtank", "pipeline", "ai"}
    assert all(isinstance(value, int) for key, value in body["heartbeats"].items() if key != "ai")
    assert body["counts"] == {"domains": 0, "findings": 0, "evidence": 0}
    assert isinstance(body["uptime_s"], int)


def test_healthz_exposes_adapter_readiness_without_secrets(api_env):
    client, _, _ = api_env
    body = client.get("/api/healthz").json()
    assert body["ok"] is True and body["mode"] == "live"
    assert {"crt", "feeds", "enrich", "render", "search", "maps", "ai", "guard"} <= set(body["adapters"])
    external = {k: v for k, v in body["adapters"].items() if k != "guard"}
    assert all(not adapter["enabled"] for adapter in external.values())
    assert body["adapters"]["guard"]["configured"] is False
    assert body["adapters"]["guard"]["manual_sync"] is True
    blob = json.dumps(body)
    assert "api_key" not in blob
    assert "GEMINI_KEY" not in blob and "NEXTDNS_API_KEY" not in blob


def test_boot_creates_empty_schema_without_seed_assets(api_env):
    _, settings, app = api_env
    assert settings.db_path.exists()
    assert list(settings.evidence_dir.glob("*.jpg")) == []
    assert app.state.runtime.repo.get_meta("mode") == "live"
    assert app.state.runtime.repo.get_meta("schema_version") == "1"
    assert app.state.runtime.repo.get_meta("seeded_at") is None


def test_feed_finding_and_evidence_are_empty_until_real_data_exists(api_env):
    client, _, _ = api_env
    assert client.get("/api/feed?limit=5").json() == []
    assert client.get("/api/finding/1").status_code == 404
    assert client.get("/api/evidence/1.jpg").status_code == 404
    assert client.get("/evidence/1.jpg").status_code == 404


def test_examples_expose_only_canonical_sweep_queries(api_env):
    client, _, _ = api_env
    body = client.get("/api/examples").json()
    assert body["check"] == []
    assert body["numbers"] == []
    assert body["sweep_web"] and body["sweep_maps"]
    assert all("q" in item and "lang" in item for item in body["sweep_web"] + body["sweep_maps"])


def test_scan_contracts_are_live_pure_brain_without_invented_evidence(api_env):
    client, _, _ = api_env
    response = client.post(
        "/api/scan",
        json={"kind": "url", "input": "https://adcb-secure-login.xyz/login", "lang": "en"},
    )
    assert response.status_code == 200
    body = response.json()
    assert set(body) == SCAN_KEYS
    assert body["kind"] == "url"
    assert body["verdict"] in {"MALICIOUS", "SUSPICIOUS", "MISLEADING", "UNKNOWN"}
    assert body["evidence_url"] is None
    assert body["offline_capable"] is True

    number = client.post("/api/scan", json={"kind": "number", "input": "+971900000042", "lang": "en"}).json()
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
    assert client.post("/api/scan", json={"kind": "banana", "input": "x"}).status_code == 422


def test_feed_default_hides_ct_only_unknowns(api_env, insert_test_finding):
    client, _, _ = api_env
    insert_test_finding(domain="ct-only-unknown.example", verdict="UNKNOWN", score=0.0)
    suspicious = insert_test_finding(domain="brand-bait.example", verdict="SUSPICIOUS", score=0.55)

    response = client.get("/api/feed")
    assert response.status_code == 200
    domains = {row["domain"] for row in response.json()}
    assert suspicious["domain"] in domains
    assert "ct-only-unknown.example" not in domains

    included = client.get("/api/feed?include_unknown=true").json()
    assert {row["domain"] for row in included} >= {"ct-only-unknown.example", "brand-bait.example"}


def test_analyst_label_hides_suppressed_domains_from_feed(api_env, insert_test_finding):
    client, _, _ = api_env
    first = insert_test_finding(domain="feed-suppress-me.example", verdict="SUSPICIOUS", score=0.55)
    second = insert_test_finding(domain="feed-keep-me.example", verdict="SUSPICIOUS", score=0.55)

    response = client.post(f"/api/finding/{first['id']}/label", json={"label": "official"})
    assert response.status_code == 200
    assert response.json()["label"] == "official"
    assert client.get(f"/api/finding/{first['id']}/label").json()["label"] == "official"

    domains = {row["domain"] for row in client.get("/api/feed").json()}
    assert second["domain"] in domains
    assert first["domain"] not in domains

    suppressed = {row["domain"] for row in client.get("/api/feed?include_suppressed=true").json()}
    assert {first["domain"], second["domain"]} <= suppressed

    assert client.post(f"/api/finding/{first['id']}/label", json={"label": "not-a-label"}).status_code == 422


def test_mode_is_locked_to_live(api_env):
    client, _, _ = api_env
    assert client.get("/api/mode").json() == {"mode": "live"}
    assert client.post("/api/mode", json={"mode": "live"}).json() == {"mode": "live"}
    assert client.post("/api/mode", json={"mode": "demo"}).status_code == 422
    assert client.post("/api/mode", json={"mode": "venue"}).status_code == 422
    assert client.get("/api/status").json()["mode"] == "live"


def test_guard_feed_is_empty_and_policy_filtered_with_test_double(api_env, insert_test_finding):
    client, _, app = api_env
    response = client.get("/api/guard/feed")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    assert response.text.strip() == ""

    malicious = insert_test_finding(domain="unit-malicious.example", verdict="MALICIOUS")
    misleading = insert_test_finding(domain="unit-misleading.example", verdict="MISLEADING")
    rows = app.state.runtime.repo.get_guard_rows(guard_block_misleading=True)
    assert {row["domain"] for row in rows} == {malicious["domain"], misleading["domain"]}
    assert {row["verdict"] for row in rows} == {"MALICIOUS", "MISLEADING"}
    strict_rows = app.state.runtime.repo.get_guard_rows(guard_block_misleading=False)
    assert {row["domain"] for row in strict_rows} == {malicious["domain"]}


def test_real_evidence_file_is_served_without_generated_stand_ins(api_env, insert_test_finding):
    client, settings, _ = api_env
    finding = insert_test_finding(evidence=True)
    assert (settings.evidence_dir / f"{finding['id']}.jpg").stat().st_size > 0
    for path in (f"/api/evidence/{finding['id']}.jpg", f"/evidence/{finding['id']}.jpg"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("image/jpeg")
        assert response.content[:2] == b"\xff\xd8"


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


def test_optional_routers_are_mounted_after_integration(api_env):
    _, _, app = api_env
    states = app.state.runtime.optional_routers
    expected = {
        "backend.app.api.sweep",
        "backend.app.api.guard",
        "backend.app.api.reports",
        "backend.app.api.ai",
    }
    assert expected <= set(states)
    assert all(states[name] == "mounted" for name in expected)


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


def test_no_demo_seed_or_fixture_product_data_in_runtime():
    root = Path(__file__).resolve().parents[2]
    banned = (
        "seed_dir", "DEMO_MODE", "MODE=demo", "FixtureProvider", "FixtureMapsProvider",
        "FIXTURE_ROOT", "web/fixtures", "backend/seed", "casefiles", "gallery_index.json",
        "injectDemoBeat", "stream_demo.json", "ai_cases.json", "ensure_evidence_image",
        "SYNTHETIC TEST FIXTURE",
    )
    paths = [
        *sorted((root / "backend" / "app").rglob("*.py")),
        *sorted((root / "web" / "js").rglob("*.js")),
        root / "web" / "index.html",
        root / "web" / "sw.js",
        root / "Makefile",
        root / "Dockerfile",
        root / ".env.example",
        root / "README.md",
        *sorted((root / "docs").rglob("*.md")),
    ]
    offenders = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for marker in banned:
            if marker in text:
                offenders.append(f"{path.relative_to(root)}: {marker}")
    assert offenders == []


def test_integration_scope_audit_no_deleted_product_data_paths():
    root = Path(__file__).resolve().parents[2]
    required = [
        "web/index.html",
        "web/js/api.js",
        "web/js/i18n/en.json",
        "web/js/i18n/ar.json",
        "guard/README.md",
        "extension/manifest.json",
        "backend/app/channels",
        "backend/app/api/examples.py",
        "backend/app/api/sweep.py",
        "backend/app/api/guard.py",
        "backend/app/ai/client.py",
        "backend/app/api/reports.py",
        "backend/app/api/ai.py",
        "backend/tests/ws2/data",
        "docs/UI-KIT.md",
    ]
    assert all((root / path).exists() for path in required)
    forbidden = [
        "daggers", "daggers-ws2-mohamed", "backend/app/server.py", "backend/app/store.py",
        "backend/requirements.txt", "backend/seed", "web/fixtures", "web/evidence", "ops/demo",
        "backend/app/channels/fixtures", "backend/app/channels/official/fixtures",
        "backend/app/channels/ws2.env.example", "requirements-render.txt", "pytest.ini",
    ]
    assert not any((root / path).exists() for path in forbidden)
    assert not list((root / "docs").glob("daggers-*.md"))
    assert "backend/data/" in (root / ".gitignore").read_text(encoding="utf-8")


def test_enricher_failure_returns_complete_s5_shape(monkeypatch, tmp_path):
    from backend.app.catalog import load_catalogs
    from backend.app.config import Settings
    from backend.app.radar.enrich import Enricher

    settings = Settings.from_env(
        {
            "ENRICH_ENABLED": "1",
            "HTTP_TIMEOUT_S": "0.01",
            "DB_PATH": str(tmp_path / "db.sqlite"),
            "EVIDENCE_DIR": str(tmp_path / "evidence"),
            "GALLERY_DIR": str(tmp_path / "gallery"),
            "WEB_DIR": str(tmp_path / "web"),
            "CORS_ORIGINS": "",
        }
    )
    enricher = Enricher(settings, load_catalogs())

    async def fail(*args, **kwargs):
        raise RuntimeError("offline")

    async def no_page(*args, **kwargs):
        return None

    monkeypatch.setattr("backend.app.radar.enrich.fetch_page_context", no_page)
    for method in ("_rdap", "_dns", "_tls", "_favicon"):
        monkeypatch.setattr(enricher, method, fail)
    result = asyncio.run(enricher.enrich("example.com"))
    assert set(result) == {
        "rdap_created", "rdap_registrar", "dns_a", "tls_issued",
        "tls_issuer", "favicon_hash", "cert_age_hours", "page_context",
    }
    assert result["dns_a"] == []


def test_font_loader_falls_back_when_freetype_is_broken(monkeypatch):
    from backend.app.vision import gallery

    class BrokenFontModule:
        @staticmethod
        def truetype(*args, **kwargs):
            raise ImportError("dlopen libhvf.dylib failed")

        @staticmethod
        def load_default(size=None):
            if size is not None:
                raise ImportError("dlopen libhvf.dylib failed")
            return "bitmap-font"

    monkeypatch.setattr(gallery, "ImageFont", BrokenFontModule)
    monkeypatch.setattr(gallery, "FONT_CANDIDATES", ())
    assert gallery.load_font(26, bold=True) == "bitmap-font"

    class AlwaysBrokenFontModule(BrokenFontModule):
        @staticmethod
        def load_default(size=None):
            raise ImportError("dlopen libhvf.dylib failed")

    monkeypatch.setattr(gallery, "ImageFont", AlwaysBrokenFontModule)
    assert gallery.load_font(26, bold=True) is None


def test_gallery_index_is_optional_operator_supplied_data(monkeypatch, tmp_path):
    from backend.app.vision import gallery

    assert gallery.load_gallery(tmp_path / "missing.json") == []
    index = tmp_path / "gallery_index.json"
    index.write_text(json.dumps([{"domain": "operator.example", "path": "real.jpg"}]), encoding="utf-8")
    assert gallery.load_gallery(index)[0]["domain"] == "operator.example"


def test_evidence_composition_requires_two_real_captures(tmp_path):
    from backend.app.vision import diff

    finding = {"id": 1, "domain": "unit.example", "verdict": "MALICIOUS", "score": 0.9, "reasons": []}
    destination = tmp_path / "1.jpg"
    assert diff.create_comparison_evidence(
        tmp_path / "missing-suspect.jpg",
        tmp_path / "missing-reference.jpg",
        finding,
        destination,
        0,
    ) is None
    assert not destination.exists()


def test_reports_are_empty_until_a_real_finding_is_inserted(api_env, insert_test_finding):
    client, _, _ = api_env
    assert client.get("/api/reports").json() == {"reports": []}
    assert client.post("/api/reports", json={"finding_id": 1}).status_code == 410
    # Test helper writes directly to the repository; production reaches the same
    # path automatically from the radar pipeline or startup backfill.
    finding = insert_test_finding()
    report = client.app.state.runtime.report_queue.maybe_auto_file(finding)
    assert report is not None
    validate_zero_pii(report)
    assert report["finding_id"] == finding["id"]


def test_integrated_app_serves_live_shell_share_target_and_examples(api_env):
    client, _, _ = api_env
    root = client.get("/")
    assert root.status_code == 200
    assert "text/html" in root.headers["content-type"]
    assert client.get("/share").status_code == 200
    examples = client.get("/api/examples")
    assert examples.status_code == 200
    assert "sweep_web" in examples.json()


def test_guard_stats_keep_blocked_and_alias_keys_with_zero_data(api_env):
    client, _, _ = api_env
    stats = client.get("/api/guard/stats").json()
    assert {
        "blocked_domains", "blocked_hits", "blocked_today", "feed_size", "mode",
    } <= set(stats)
    assert stats["blocked_domains"] == 0
    assert stats["feed_size"] == 0
    assert stats["mode"] == "live"


def test_ws2_sweep_is_empty_when_live_providers_are_unconfigured(api_env):
    client, _, _ = api_env
    created = client.post("/api/sweep", json={"channel": "web", "lang": "en"})
    assert created.status_code == 200
    run = created.json()
    assert run["source_kind"] == "unconfigured"
    assert run["synthetic"] is False
    assert run["results"] == []
    assert run["store"] == "sqlite"
    fetched = client.get(f"/api/sweep/{run['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["results"] == []
    blocklist = client.get("/api/guard/blocklist.txt")
    assert blocklist.status_code == 200
    assert "0.0.0.0 " not in blocklist.text
    sync = client.get("/api/guard/sync-status").json()
    assert sync["source"] == "guard_feed"


def test_ws3_reports_and_ai_routes_use_live_repository(api_env, insert_test_finding):
    client, _, _ = api_env
    finding = insert_test_finding()
    report = client.app.state.runtime.report_queue.maybe_auto_file(finding)
    assert report is not None
    report_id = report["id"]
    advanced = client.post(f"/api/reports/{report_id}/advance", json={"status": "SEEN"})
    assert advanced.status_code == 200
    assert advanced.json()["status"] == "SEEN"
    analysis = client.post(f"/api/report/{report_id}/analysis")
    assert analysis.status_code == 200
    assert "event: final" in analysis.text
    assert "summary_en" in analysis.text
    takedown = client.post(f"/api/report/{report_id}/takedown")
    assert takedown.status_code == 200
    assert "letter_en" in takedown.json()


def test_sweep_selfcheck_reports_per_adapter_outcome(api_env):
    client, _, _ = api_env
    response = client.get("/api/sweep/selfcheck")
    assert response.status_code == 200
    data = response.json()
    assert set(data) == {"query", "search", "maps", "live"}
    assert data["search"] == [] and data["maps"] == []  # no adapters configured in tests
    assert data["live"] is False
