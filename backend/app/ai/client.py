"""Daggers · AI client (WS3) — Gemini → Groq → template, with streaming.

Rules enforced here (WS3 §3):
  · input = Report.evidence ONLY (zero PII by design)
  · AI never writes verdict / score / reasons
  · any provider failure → template text, `fallback: true` — same UI shape
  · kill switches: AI_PROVIDER=auto|gemini|groq|template, AI_ON=0
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path
from typing import Any, AsyncIterator

import httpx

from . import fallback

PROMPTS = Path(__file__).parent / "prompts"
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
)
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
TIMEOUT = httpx.Timeout(connect=6.0, read=45.0, write=10.0, pool=6.0)

EN_RE = re.compile(r"<EN>(.*?)</EN>", re.S)
AR_RE = re.compile(r"<AR>(.*?)</AR>", re.S)


# The ONLY fields of Report.evidence that may reach a provider (zero PII by design).
ALLOWED_EVIDENCE_FIELDS = {
    "id", "domain", "verdict", "score", "reasons", "reasons_ar", "brand",
    "cert_issued", "first_seen", "clone", "gallery_match", "source",
    "scam_type", "registrar", "verdict_note", "verdict_note_ar", "signals",
    "maps_listing", "tag", "trust_reasons", "domain_authentication", "official_verification",
    "evidence_url",
}


def _provider_order() -> list[str]:
    forced = os.getenv("AI_PROVIDER", "auto").lower()
    if os.getenv("AI_ON", "1") == "0" or forced == "template":
        return []
    if forced in ("gemini", "groq"):
        return [forced]
    order = []
    if os.getenv("GEMINI_KEY"):
        order.append("gemini")
    if os.getenv("GROQ_KEY"):
        order.append("groq")
    return order


def _prompt(name: str, evidence: dict[str, Any]) -> str:
    template = (PROMPTS / f"{name}.txt").read_text(encoding="utf-8")
    safe = fallback.evidence_for_prompt(evidence, ALLOWED_EVIDENCE_FIELDS)
    return template.replace("{EVIDENCE_JSON}", safe)


async def _openai_stream(url: str, key: str, model: str, prompt: str) -> AsyncIterator[str]:
    """Yield text deltas from an OpenAI-compatible chat completions endpoint."""
    payload = {
        "model": model,
        "stream": True,
        "temperature": 0.3,
        "messages": [
            {"role": "system", "content": "You follow the instructions exactly and never add facts."},
            {"role": "user", "content": prompt},
        ],
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        async with client.stream("POST", url, json=payload, headers=headers) as res:
            if res.status_code >= 400:
                body = (await res.aread()).decode("utf-8", "ignore")[:400]
                raise RuntimeError(f"{url.split('/')[2]} {res.status_code}: {body}")
            async for line in res.aiter_lines():
                if not line.startswith("data:"):
                    continue
                chunk = line[5:].strip()
                if chunk == "[DONE]":
                    return
                try:
                    obj = json.loads(chunk)
                    delta = obj["choices"][0]["delta"].get("content") or ""
                except (KeyError, IndexError, json.JSONDecodeError):
                    continue
                if delta:
                    yield delta


def _split_blocks(text: str) -> tuple[str, str]:
    en = EN_RE.search(text)
    ar = AR_RE.search(text)
    if en and ar:
        return en.group(1).strip(), ar.group(1).strip()
    # model ignored the tags: treat the whole output as EN, template the AR
    return text.strip(), ""


async def _collect(stream: AsyncIterator[str]) -> str:
    parts = []
    async for delta in stream:
        parts.append(delta)
    return "".join(parts)


async def stream_case_summary(
    evidence: dict[str, Any], *, report_id: int | int = 0
) -> AsyncIterator[dict[str, Any]]:
    """SSE payloads: {"delta_text": …} … then {"summary_en","summary_ar","provider","fallback"}.

    The visible typing effect comes from real token deltas; AR is delivered whole in
    the final event (the UI flips instantly — that is the demo beat, not a lag).
    """
    prompt = _prompt("case_summary", evidence)
    for provider in _provider_order():
        url, key, model = (
            (GEMINI_URL, os.getenv("GEMINI_KEY", ""), GEMINI_MODEL)
            if provider == "gemini"
            else (GROQ_URL, os.getenv("GROQ_KEY", ""), GROQ_MODEL)
        )
        try:
            raw = await _collect(_openai_stream(url, key, model, prompt))
            en, ar = _split_blocks(raw)
            if not en:
                raise RuntimeError("empty model output")
            if not ar:
                ar = fallback.case_summary(evidence)["summary_ar"]
            for i in range(0, len(en), 3):
                yield {"delta_text": en[i:i + 3]}
                await asyncio.sleep(0.012)
            yield {
                "summary_en": en,
                "summary_ar": ar,
                "provider": provider,
                "fallback": False,
            }
            return
        except Exception as exc:  # noqa: BLE001 — any failure → next provider
            if os.getenv("AI_DEBUG"):
                print(f"[ai] {provider} failed: {exc}")
            continue

    # template path — streams char-by-char so rehearsal matches the real thing
    tpl = fallback.case_summary(evidence)
    en = tpl["summary_en"]
    for i in range(0, len(en), 3):
        yield {"delta_text": en[i:i + 3]}
        await asyncio.sleep(0.012)
    yield tpl


async def takedown_letter(evidence: dict[str, Any]) -> dict[str, str]:
    prompt = _prompt("takedown", evidence)
    for provider in _provider_order():
        url, key, model = (
            (GEMINI_URL, os.getenv("GEMINI_KEY", ""), GEMINI_MODEL)
            if provider == "gemini"
            else (GROQ_URL, os.getenv("GROQ_KEY", ""), GROQ_MODEL)
        )
        try:
            raw = await _collect(_openai_stream(url, key, model, prompt))
            if len(raw.strip()) > 80:
                return {"letter_en": raw.strip(), "provider": provider, "fallback": False}  # type: ignore[dict-item]
        except Exception:  # noqa: BLE001
            continue
    return {**fallback.takedown(evidence), "fallback": True}  # type: ignore[dict-item]


async def why_smells(evidence: dict[str, Any]) -> dict[str, Any]:
    prompt = _prompt("why_smells", evidence)
    for provider in _provider_order():
        url, key, model = (
            (GEMINI_URL, os.getenv("GEMINI_KEY", ""), GEMINI_MODEL)
            if provider == "gemini"
            else (GROQ_URL, os.getenv("GROQ_KEY", ""), GROQ_MODEL)
        )
        try:
            raw = (await _collect(_openai_stream(url, key, model, prompt))).strip()
            if len(raw) > 40:
                return {"text_en": raw, "provider": provider, "fallback": False}
        except Exception:  # noqa: BLE001
            continue
    return fallback.why_smells(evidence)
