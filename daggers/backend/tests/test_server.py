"""WS3 · live API tests — every endpoint Lane 3 owns, against the demo server.

Uses FastAPI TestClient so the whole stack (routers + store + SSE + AI chain) runs
in-process. These are the "does it work as it's supposed to" tests.
"""
import json, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import pytest
from fastapi.testclient import TestClient

from backend.app.server import app

client = TestClient(app)


def test_status_shape():
    r = client.get("/api/status")
    assert r.status_code == 200
    body = r.json()
    assert {"mode", "heartbeats", "counts", "uptime_s"} <= body.keys()


def test_feed_matches_contract():
    r = client.get("/api/feed")
    assert r.status_code == 200
    findings = r.json()["findings"]
    assert findings
    for f in findings[:5]:
        assert {"id", "domain", "verdict", "score", "reasons"} <= f.keys()
        assert f["evidence_url"].startswith("/evidence/")


def test_finding_detail_and_404_shape():
    ok = client.get("/api/finding/42")
    assert ok.status_code == 200 and ok.json()["id"] == 42
    missing = client.get("/api/finding/999999")
    assert missing.json() == {}


def test_reports_list_is_sorted_and_has_evidence():
    reports = client.get("/api/reports").json()["reports"]
    assert reports
    assert [r["id"] for r in reports] == sorted((r["id"] for r in reports), reverse=True)
    assert all(r.get("evidence") for r in reports)


def test_file_report_is_idempotent_per_finding():
    first = client.post("/api/reports", json={"finding_id": 42})
    assert first.status_code in (200, 201)
    second = client.post("/api/reports", json={"finding_id": 42})
    assert first.json()["id"] == second.json()["id"], "double-filing must not create duplicates"


def test_file_report_rejects_unknown_finding():
    assert client.post("/api/reports", json={"finding_id": 999999}).status_code == 404


def test_advance_status_walk_and_validation():
    rid = client.post("/api/reports", json={"finding_id": 41}).json()["id"]
    assert client.post(f"/api/reports/{rid}/advance", json={"status": "SUBMITTED"}).json()["status"] == "SUBMITTED"
    assert client.post(f"/api/reports/{rid}/advance", json={"status": "SEEN"}).json()["status"] == "SEEN"
    assert client.post(f"/api/reports/{rid}/advance", json={"status": "NONSENSE"}).status_code == 422
    assert client.post("/api/reports/999999/advance", json={"status": "SEEN"}).status_code == 404


def test_report_export_is_a_download():
    r = client.get("/api/reports/7/export")
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]


def test_ai_analysis_streams_deltas_then_final(monkeypatch):
    # force the template chain so no network is touched
    monkeypatch.setenv("AI_PROVIDER", "template")
    with client.stream("POST", "/api/report/7/analysis") as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        raw = "".join(r.iter_text())

    events = [e for e in raw.split("\n\n") if e.strip()]
    deltas = [e for e in events if e.startswith("event: delta")]
    finals = [e for e in events if e.startswith("event: final")]
    assert deltas, "the typewriter effect needs at least one delta"
    assert len(finals) == 1, "exactly one final event"

    payload = json.loads(finals[0].split("data: ", 1)[1])
    assert payload["summary_en"] and payload["summary_ar"]
    assert payload["provider"] == "template" and payload["fallback"] is True
    # the AI must not have written the verdict itself
    for forbidden in ("score_override", "new_verdict", "reasons\""):
        assert forbidden not in finals[0]


def test_ai_analysis_on_missing_report_is_404():
    assert client.post("/api/report/999999/analysis").status_code == 404


def test_takedown_returns_letter(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "template")
    r = client.post("/api/report/7/takedown")
    assert r.status_code == 200
    letter = r.json()["letter_en"]
    assert "adcb-secure-login.xyz" in letter
    assert "+971" not in letter and "@gmail" not in letter


def test_ai_never_receives_user_fields(monkeypatch):
    """Even if a hostile row leaked into the store, the prompt filter strips it."""
    from backend.app.ai import client as ai
    prompt = ai._prompt("case_summary", {
        "domain": "x.xyz", "verdict": "MALICIOUS",
        "user_phone": "+971500000000", "user_name": "Ali",
    })
    assert "+9715" not in prompt and "Ali" not in prompt
    assert "x.xyz" in prompt


def test_share_landing_serves_the_shell():
    r = client.get("/share?url=https%3A%2F%2Fexample.test")
    assert r.status_code == 200 and b"<!doctype html>" in r.content.lower()


def test_static_web_is_mounted():
    assert client.get("/").status_code == 200
    assert client.get("/manifest.json").json()["name"] == "Daggers"
    assert client.get("/css/tokens.css").status_code == 200


def test_examples_endpoint_feeds_the_ui():
    ex = client.get("/api/examples").json()
    assert ex["check"] and ex["numbers"] and ex["sweep_web"]


def test_sweep_create_then_fetch_by_id():
    """Contract C3: POST creates a SweepRun, GET /api/sweep/{id} returns that same run."""
    created = client.post("/api/sweep", json={"channel": "web", "query": "emirates nbd refund"})
    assert created.status_code == 200
    run = created.json()
    assert {"id", "query", "lang", "channel", "engine", "results"} <= run.keys()
    assert run["query"] == "emirates nbd refund" and run["channel"] == "web"

    fetched = client.get(f"/api/sweep/{run['id']}").json()
    assert fetched["id"] == run["id"] and fetched["query"] == run["query"]


def test_sweep_maps_channel_returns_maps_run():
    run = client.post("/api/sweep", json={"channel": "maps"}).json()
    assert run["channel"] == "maps" and run["results"]
    assert all({"position", "verdict", "score"} <= r.keys() for r in run["results"])
