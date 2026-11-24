"""Daggers · AI client — Gemini → Groq → template, with streaming.

Rules enforced here:
  · input = canonical Report.evidence ONLY (zero PII by design)
  · AI never writes verdict / score / reasons
  · any provider failure → deterministic template text, `fallback: true`
  · external adapters are opt-in: AI_STATE=template by default; AI_STATE=live uses keys
  · legacy switches still work: AI_PROVIDER=auto|gemini|groq|template, AI_ON=0
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Mapping

import httpx

from . import fallback

PROMPTS = Path(__file__).parent / "prompts"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
TIMEOUT = httpx.Timeout(connect=6.0, read=45.0, write=10.0, pool=6.0)

EN_RE = re.compile(r"<EN>(.*?)</EN>", re.S)
AR_RE = re.compile(r"<AR>(.*?)</AR>", re.S)

# The ONLY fields of Report.evidence that may reach a provider.
ALLOWED_EVIDENCE_FIELDS = {
    "id", "domain", "verdict", "score", "reasons", "reasons_ar", "brand",
    "cert_issued", "first_seen", "clone", "gallery_match", "source",
    "scam_type", "registrar", "verdict_note", "verdict_note_ar", "signals",
    "maps_listing",
}


@dataclass(frozen=True)
class AIConfig:
    """Resolved, request-scoped AI adapter settings; secrets are never serialized."""

    state: str = "template"
    provider: str = "auto"
    on: bool = True
    debug: bool = False
    gemini_key: str = ""
    groq_key: str = ""
    gemini_model: str = "gemini-2.0-flash"
    groq_model: str = "llama-3.3-70b-versatile"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "AIConfig":
        env = dict(os.environ if env is None else env)
        provider = (env.get("AI_PROVIDER", "auto") or "auto").strip().lower()
        raw_state = (env.get("AI_STATE") or "").strip().lower()
        if raw_state in {"off", "template", "live", "on", "auto", "ok"}:
            state = {"on": "live", "auto": "live", "ok": "live"}.get(raw_state, raw_state)
        elif provider == "template":
            state = "template"
        elif env.get("GEMINI_KEY") or env.get("GROQ_KEY"):
            state = "live"
        else:
            state = "template"
        return cls(
            state=state,
            provider=provider,
            on=env.get("AI_ON", "1") != "0",
            debug=env.get("AI_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"},
            gemini_key=env.get("GEMINI_KEY", ""),
            groq_key=env.get("GROQ_KEY", ""),
            gemini_model=env.get("GEMINI_MODEL", "gemini-2.0-flash"),
            groq_model=env.get("GROQ_MODEL", "llama-3.3-70b-versatile"),
        )

    @classmethod
    def from_settings(cls, settings: Any) -> "AIConfig":
        """Build from the app's authoritative Settings object, not ambient env."""
        state = str(getattr(settings, "ai_state", "template")).lower()
        provider = str(getattr(settings, "ai_provider", "auto")).lower()
        if state not in {"off", "template", "live"}:
            state = "template"
        return cls(
            state=state,
            provider=provider,
            on=bool(getattr(settings, "ai_on", True)),
            debug=bool(getattr(settings, "ai_debug", False)),
            gemini_key=str(getattr(settings, "gemini_key", "") or ""),
            groq_key=str(getattr(settings, "groq_key", "") or ""),
            gemini_model=str(getattr(settings, "gemini_model", "gemini-2.0-flash")),
            groq_model=str(getattr(settings, "groq_model", "llama-3.3-70b-versatile")),
        )


def _provider_order(config: AIConfig | None = None) -> list[str]:
    config = config or AIConfig.from_env()
    if not config.on or config.state in {"off", "template"}:
        return []
    if config.provider == "template":
        return []
    if config.provider in {"gemini", "groq"}:
        key = config.gemini_key if config.provider == "gemini" else config.groq_key
        return [config.provider] if key else []
    order = []
    if config.gemini_key:
        order.append("gemini")
    if config.groq_key:
        order.append("groq")
    return order


def _credentials(provider: str, config: AIConfig) -> tuple[str, str, str]:
    if provider == "gemini":
        return GEMINI_URL, config.gemini_key, config.gemini_model
    return GROQ_URL, config.groq_key, config.groq_model


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
    async with httpx.AsyncClient(timeout=TIMEOUT) as http:
        async with http.stream("POST", url, json=payload, headers=headers) as res:
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
    # Model ignored the tags: treat the whole output as EN, template the AR.
    return text.strip(), ""


async def _collect(stream: AsyncIterator[str]) -> str:
    parts = []
    async for delta in stream:
        parts.append(delta)
    return "".join(parts)


async def _stream_template(en: str) -> AsyncIterator[str]:
    for index in range(0, len(en), 3):
        yield en[index:index + 3]
        await asyncio.sleep(0.012)


async def stream_case_summary(
    evidence: dict[str, Any],
    *,
    report_id: int = 0,
    config: AIConfig | None = None,
) -> AsyncIterator[dict[str, Any]]:
    """SSE payloads: deltas, then {summary_en, summary_ar, provider, fallback}."""
    config = config or AIConfig.from_env()
    prompt = _prompt("case_summary", evidence)
    for provider in _provider_order(config):
        url, key, model = _credentials(provider, config)
        try:
            raw = await _collect(_openai_stream(url, key, model, prompt))
            en, ar = _split_blocks(raw)
            if not en:
                raise RuntimeError("empty model output")
            if not ar:
                ar = fallback.case_summary(evidence)["summary_ar"]
            async for delta in _stream_template(en):
                yield {"delta_text": delta}
            yield {"summary_en": en, "summary_ar": ar, "provider": provider, "fallback": False}
            return
        except Exception as exc:  # noqa: BLE001 — any failure → next provider
            if config.debug:
                print(f"[ai] {provider} failed: {exc}")
            continue

    template = fallback.case_summary(evidence)
    async for delta in _stream_template(template["summary_en"]):
        yield {"delta_text": delta}
    yield template


async def takedown_letter(
    evidence: dict[str, Any],
    *,
    config: AIConfig | None = None,
) -> dict[str, str]:
    config = config or AIConfig.from_env()
    prompt = _prompt("takedown", evidence)
    for provider in _provider_order(config):
        url, key, model = _credentials(provider, config)
        try:
            raw = await _collect(_openai_stream(url, key, model, prompt))
            if len(raw.strip()) > 80:
                return {"letter_en": raw.strip(), "provider": provider, "fallback": False}
        except Exception:  # noqa: BLE001
            continue
    return {**fallback.takedown(evidence), "fallback": True}


async def why_smells(
    evidence: dict[str, Any],
    *,
    config: AIConfig | None = None,
) -> dict[str, Any]:
    config = config or AIConfig.from_env()
    prompt = _prompt("why_smells", evidence)
    for provider in _provider_order(config):
        url, key, model = _credentials(provider, config)
        try:
            raw = (await _collect(_openai_stream(url, key, model, prompt))).strip()
            if len(raw) > 40:
                return {"text_en": raw, "provider": provider, "fallback": False}
        except Exception:  # noqa: BLE001
            continue
    return fallback.why_smells(evidence)
