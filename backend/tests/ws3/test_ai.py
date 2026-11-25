"""WS3 · AI Analyst tests — the rules that must never break.

1. input is Report.evidence only (privacy filter drops anything else)
2. AI never writes verdict / score / reasons (template + prompt contract)
3. provider chain: gemini → groq → template, each with a kill switch
4. a stream that fails mid-way still ends with a final event (fallback:true)
5. bilingual output always carries both keys
"""
import asyncio, json, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3]))

import pytest
from backend.app.ai import client, fallback


EVIDENCE = {
    "id": 42, "domain": "adcb-secure-login.xyz", "verdict": "MALICIOUS", "score": 0.93,
    "brand": "ADCB", "clone": 97, "gallery_match": "adcb.ae/login",
    "reasons": ["brand typo 'adcb' (distance 1)", "certificate issued 42 minutes ago"],
    "reasons_ar": ["خطأ في اسم العلامة «adcb»", "صدرت الشهادة قبل 42 دقيقة"],
    "registrar": "NameCheap, Inc.", "scam_type": "fake-banking-login",
    # hostile/banned content that must never reach a provider:
    "user_phone": "+971 50 123 4567", "user_name": "Ali", "messages": ["hi"],
}


def test_privacy_filter_only_contract_fields():
    prompt = client._prompt("case_summary", EVIDENCE)
    assert "adcb-secure-login.xyz" in prompt
    assert "+971 50" not in prompt and "Ali" not in prompt and '"messages"' not in prompt
    assert "{EVIDENCE_JSON}" not in prompt


def test_template_never_invents_verdict_and_is_bilingual():
    out = fallback.case_summary(EVIDENCE)
    assert set(["summary_en", "summary_ar", "provider", "fallback"]) <= set(out)
    assert out["provider"] == "template" and out["fallback"] is True
    assert "adcb-secure-login.xyz" in out["summary_en"]
    assert "adcb-secure-login.xyz" in out["summary_ar"]
    # it must not claim a different verdict than the engine's:
    # MALICIOUS → the plan's plain word "fake" (EN) / «مزيّف» (AR), never a new verdict
    assert "fake" in out["summary_en"].lower()
    assert "مزيّف" in out["summary_ar"]
    assert "malicious" not in out["summary_en"].lower().split("flagged")[0]
    assert "P1" in out["summary_en"] and "P1" in out["summary_ar"]


def test_suspicious_never_reads_as_fake():
    out = fallback.case_summary({**EVIDENCE, "verdict": "SUSPICIOUS", "scam_type": "brand-impersonation", "clone": 40})
    assert "warning" in out["summary_en"].lower()
    assert "تحذير" in out["summary_ar"]
    assert "fake" not in out["summary_en"].lower()


def test_template_uses_central_tag_and_reports_missing_sources():
    ev = {**EVIDENCE, "tag": "MISLEADING", "verdict": "UNKNOWN",
          "official_verification": {"status": "SOURCE_UNAVAILABLE", "unchecked_sources": ["icp"], "sources": []}}
    out = fallback.case_summary(ev)
    assert "MISLEADING" in out["summary_en"]
    assert "SOURCE_UNAVAILABLE" in out["summary_en"]
    assert "not checked: icp" in out["summary_en"]
    assert "not found on official channels" not in out["summary_en"]


def test_priority_rule():
    assert fallback._priority(EVIDENCE) == "P1"
    assert fallback._priority({**EVIDENCE, "verdict": "SUSPICIOUS", "scam_type": "brand-impersonation", "clone": 40}) == "P2"


def test_kill_switch_template(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "template")
    assert client._provider_order() == []
    monkeypatch.setenv("AI_ON", "0")
    monkeypatch.setenv("AI_PROVIDER", "auto")
    assert client._provider_order() == []


def test_provider_order(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "auto")
    monkeypatch.setenv("GEMINI_KEY", "x")
    monkeypatch.setenv("GROQ_KEY", "y")
    assert client._provider_order() == ["gemini", "groq"]
    monkeypatch.delenv("GEMINI_KEY")
    assert client._provider_order() == ["groq"]


def test_failure_falls_back_and_final_event_always_arrives(monkeypatch):
    """Simulate every provider failing mid-stream → final event still emitted."""
    monkeypatch.setenv("AI_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_KEY", "broken")

    async def boom(*_a, **_k):
        yield "half a sen"
        raise RuntimeError("connection reset by peer")

    monkeypatch.setattr(client, "_openai_stream", boom)

    async def run():
        events = [e async for e in client.stream_case_summary(EVIDENCE)]
        return events

    events = asyncio.run(run())
    final = events[-1]
    assert "summary_en" in final and "summary_ar" in final
    assert final["fallback"] is True and final["provider"] == "template"
    assert any("delta_text" in e for e in events), "template path must still type on screen"


def test_block_parsing_survives_a_model_that_ignores_tags():
    en, ar = client._split_blocks("Just a plain English summary without tags.")
    assert en.startswith("Just") and ar == ""


def test_takedown_template_has_no_user_data():
    letter = fallback.takedown(EVIDENCE)["letter_en"]
    assert "adcb-secure-login.xyz" in letter
    assert "+971" not in letter and "Ali" not in letter
