"""The Checker is independent of the Police Portal: it SENDS results to the Portal and keeps its own
result store; it never reads Portal findings, cases or evidence. Stored results are reused without a
new analysis while they are valid (same input, same engine / policy / registry / reputation versions)."""
from __future__ import annotations

import itertools
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.config import Settings
from backend.app.main import create_app

_ids = itertools.count(1)
PORTAL_READS = ("get_finding", "get_findings", "search_findings", "check_request_finding", "recent_check_finding",
                "find_evidence_url", "findings_by_source", "get_reports", "get_report")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "template")
    settings = Settings(
        db_path=tmp_path / "portal.db", evidence_dir=tmp_path / "e", gallery_dir=tmp_path / "g",
        web_dir=Path(__file__).resolve().parents[2] / "web", cors_origins=[], heartbeat_interval_s=1,
        crt_poll_interval_s=20, feed_poll_interval_s=20, pipeline_poll_interval_s=1, ai_state="template",
        official_snapshot_dir=tmp_path / "snap", scan_rate_per_min=1000,
        checker_store_path=tmp_path / "checker-store.db",
    )
    app = create_app(settings)
    with TestClient(app) as client:
        yield client, app, tmp_path


def check(client, value, request_id=None):
    r = client.post("/api/check", json={"input": value, "lang": "en",
                                        "request_id": request_id or f"ind-{next(_ids):06d}"})
    assert r.status_code in (200, 201), r.text
    return r.json()


def block_portal_reads(monkeypatch, repo):
    def refuse(*_a, **_k):
        raise AssertionError("the Checker read the Police Portal")
    for name in PORTAL_READS:
        if hasattr(repo, name):
            monkeypatch.setattr(repo, name, refuse)


def test_checker_works_with_every_portal_read_blocked(env, monkeypatch):
    client, app, _ = env
    block_portal_reads(monkeypatch, app.state.runtime.repo)
    first = check(client, "https://adcb-secure-login.xyz/login")
    assert first["tag"] == "FAKE" and first["id"] > 0 and first["duplicate"] is False
    repeat = check(client, "https://adcb-secure-login.xyz/login")            # served from its own store
    assert repeat["id"] == first["id"] and repeat["cached"] is True
    msg = check(client, "Your parcel is held. Pay AED 12 now: https://parcel-fee-uae.top/pay")
    assert msg["tag"] in ("WARNING", "MISLEADING", "FAKE")


def test_result_is_sent_to_the_portal(env):
    client, app, _ = env
    f = check(client, "https://unknown-shop-for-portal.example/")
    stored = app.state.runtime.repo.get_finding(f["id"])        # the PORTAL reads its own data
    assert stored["tag"] == f["tag"] and stored["source"] == "checker"
    assert stored["trust_reasons"] == f["trust_reasons"] and stored["evidence"] == f["evidence"]


def test_repeated_input_is_not_analysed_again(env, monkeypatch):
    client, app, _ = env
    rt = app.state.runtime
    first = check(client, "https://repeat-me.example/")
    calls = []
    original = rt.scan
    monkeypatch.setattr(rt, "scan", lambda *a, **k: calls.append(a) or original(*a, **k))
    again = check(client, "  HTTPS://repeat-me.example/  ")
    assert calls == [] and again["cached"] is True and again["cached_at"]
    assert {k: v for k, v in again.items() if k not in ("cached", "cached_at", "duplicate")} == \
        {k: v for k, v in first.items() if k not in ("cached", "cached_at", "duplicate")}
    assert rt.repo.counts()["findings"] == 1                    # nothing sent twice


def test_same_request_id_returns_the_same_response(env):
    client, app, _ = env
    a = check(client, "https://click-twice.example/", request_id="double-click-01")
    b = client.post("/api/check", json={"input": "https://click-twice.example/", "request_id": "double-click-01"})
    assert b.status_code == 200 and b.json()["id"] == a["id"] and b.json()["duplicate"] is True


def test_stored_result_is_not_reused_after_registry_or_reputation_change(env):
    client, app, _ = env
    rt = app.state.runtime
    first = check(client, "https://changes-later.example/")
    rt.trust_policy.registry.version = "reg_changed_for_test"
    again = check(client, "https://changes-later.example/")
    assert again["id"] != first["id"] and "cached" not in again


def test_store_is_a_separate_file_from_the_portal_database(env):
    client, app, tmp = env
    check(client, "https://separate-store.example/")
    assert (tmp / "checker-store.db").exists()
    portal_tables = {r[0] for r in sqlite3.connect(tmp / "portal.db").execute("SELECT name FROM sqlite_master")}
    store_tables = {r[0] for r in sqlite3.connect(tmp / "checker-store.db").execute("SELECT name FROM sqlite_master")}
    assert "results" not in portal_tables and "findings" not in store_tables


def test_incomplete_checks_are_kept_only_briefly(env):
    client, app, tmp = env
    check(client, "https://brief-keep.example/")               # no feed data → a source was not checked
    row = sqlite3.connect(tmp / "checker-store.db").execute("SELECT expires_at FROM results").fetchone()
    assert row[0] - time.time() <= app.state.runtime.settings.check_cache_partial_ttl_s + 5


def test_reuse_can_be_switched_off(env):
    client, app, _ = env
    app.state.runtime.settings.__dict__["check_cache_ttl_s"] = 0
    a = check(client, "https://no-reuse.example/")
    b = check(client, "https://no-reuse.example/")
    assert a["id"] != b["id"] and "cached" not in b


def test_failed_send_is_not_stored(env, monkeypatch):
    client, app, _ = env
    rt = app.state.runtime

    def broken(**_k):
        raise RuntimeError("portal down")
    monkeypatch.setattr(rt.repo, "insert_check_finding", broken)
    r = client.post("/api/check", json={"input": "https://send-fails.example/", "request_id": "send-fails-01"})
    assert r.status_code == 503 and r.json()["detail"]["code"] == "persist_failed"
    monkeypatch.undo()
    ok = check(client, "https://send-fails.example/")
    assert ok["id"] and "cached" not in ok                    # analysed and sent on the next try
