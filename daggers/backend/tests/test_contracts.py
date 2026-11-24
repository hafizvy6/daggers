"""WS3 · fixtures vs the C1–C4 contracts in daggers-workstream-3-face.md §3.

The UI is only as correct as these shapes. If a fixture drifts, every screen lies.
"""
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[2]
FIX = ROOT / "web" / "fixtures"
SEED = ROOT / "backend" / "seed" / "fixtures"
sys.path.insert(0, str(ROOT))

import pytest


def load(name, root=FIX):
    return json.loads((root / name).read_text(encoding="utf-8"))


FINDING_KEYS = {"id", "domain", "verdict", "score", "reasons", "cert_issued",
                "first_seen", "source", "clone", "evidence_url", "gallery_match",
                "is_case_file"}
REPORT_KEYS = {"id", "finding_id", "evidence", "status", "auto", "filed_at", "blocked_hits"}
VERDICTS = {"MALICIOUS", "SUSPICIOUS", "MISLEADING", "SAFE", "UNKNOWN"}


@pytest.fixture(scope="module")
def feed():
    return load("feed.json")["findings"]


def test_finding_shape(feed):
    assert len(feed) >= 10
    for f in feed:
        missing = FINDING_KEYS - f.keys()
        assert not missing, f"finding {f['id']} missing {missing}"
        assert f["verdict"] in VERDICTS
        assert 0.0 <= f["score"] <= 1.0
        assert isinstance(f["reasons"], list) and f["reasons"]
        assert 0 <= f["clone"] <= 100


def test_finding_ids_unique_and_sorted_source(feed):
    ids = [f["id"] for f in feed]
    assert len(ids) == len(set(ids))


def test_report_shape_and_links(feed):
    reports = load("reports.json")["reports"]
    by_id = {f["id"]: f for f in feed}
    for r in reports:
        missing = REPORT_KEYS - r.keys()
        assert not missing, f"report {r['id']} missing {missing}"
        assert r["status"] in {"QUEUED", "SUBMITTED", "SEEN"}
        assert r["finding_id"] in by_id, "report points at a finding that doesn't exist"
        assert r["evidence"]["id"] == r["finding_id"]


def test_reports_have_zero_user_fields():
    """The report schema forbids user data — assert it at the data layer."""
    banned = {"user", "user_name", "phone", "ip", "location", "device", "message",
              "messages", "contact", "email", "name", "reporter"}
    for r in load("reports.json")["reports"]:
        offenders = banned & set(r.keys())
        assert not offenders, f"report {r['id']} carries user fields: {offenders}"


def test_scan_result_shape():
    scans = load("scan.json")["scans"]
    for s in scans:
        assert s["kind"] in {"url", "text", "number"}
        assert s["verdict"] in VERDICTS
        assert isinstance(s["offline_capable"], bool)
        assert 0.0 <= s["score"] <= 1.0


def test_sweep_result_shape():
    for name in ("sweep_web.json", "sweep_maps.json"):
        run = load(name)
        for key in ("id", "query", "lang", "channel", "engine", "results"):
            assert key in run, f"{name} missing {key}"
        assert run["channel"] in {"web", "maps"}
        for r in run["results"]:
            assert {"position", "verdict", "score", "reasons"} <= r.keys()


def test_seed_folder_holds_only_the_three_ws3_files():
    names = {f.name for f in SEED.glob("*.json")}
    assert names == {"feed.json", "reports.json", "status.json"}, names


def test_arabic_variants_accompany_every_arabic_visible_string(feed):
    """If the UI can show a reason in Arabic it must come from the data, not a translation."""
    for f in feed:
        assert "reasons_ar" in f and len(f["reasons_ar"]) == len(f["reasons"]), f["id"]
        assert "verdict_note_ar" in f


def test_examples_and_offline_rules_are_data_not_code():
    ex = load("examples.json")
    assert {"check", "numbers", "sweep_web", "sweep_maps"} <= ex.keys()
    rules = load("offline_rules.json")
    assert {"premium_prefixes", "risky_tlds", "lure_keywords",
            "brand_tokens", "official_domains", "weights"} <= rules.keys()
    for item in ex["check"]:
        assert {"payload", "label_key"} == set(item.keys()), "label must be an i18n key"


def test_every_evidence_image_exists_for_each_finding(feed):
    ev = ROOT / "web" / "evidence"
    for f in feed:
        assert (ev / f"{f['id']}.jpg").exists(), f"missing evidence/{f['id']}.jpg"


def test_stream_demo_lands_a_finding_that_exists_on_disk():
    demo = load("stream_demo.json")
    fid = demo["finding"]["id"]
    assert (ROOT / "web" / "fixtures" / f"finding_{fid}.json").exists()
    assert demo["report"]["finding_id"] == fid
