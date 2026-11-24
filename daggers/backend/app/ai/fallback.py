"""Daggers · template fallback — the last link in the provider chain.

Design rule (WS3 §3): AI never writes verdict/score/reasons, and if the model is
down the structured summary still appears in the same UI shape. To keep that true
*without* baking prose into Python, the template text lives in prompts/*.txt:
  fallback_case.txt · fallback_takedown.txt
`render_template()` fills {slot} placeholders from Report.evidence only.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROMPTS = Path(__file__).parent / "prompts"
P1_TYPES = {"fake-banking-login", "fake-gov-fine", "fake-delivery-fee", "homograph"}
TEMPLATE_MAX_WORDS = 260  # template output is short by construction


def _priority(ev: dict[str, Any]) -> str:
    malicious = str(ev.get("verdict", "")).upper() == "MALICIOUS"
    if malicious and (ev.get("scam_type") in P1_TYPES or (ev.get("clone") or 0) >= 90):
        return "P1"
    return "P2"


def _fill(template: str, values: dict[str, Any]) -> str:
    out = template
    for key, val in values.items():
        out = out.replace("{" + key + "}", str(val))
    return out


def _template_file(name: str) -> str:
    return (PROMPTS / name).read_text(encoding="utf-8")


def _lines(ev: dict[str, Any], lang: str) -> str:
    reasons = ev.get(f"reasons_{lang}") or ev.get("reasons") or []
    if not reasons:
        return "• " + ("evidence recorded by the radar" if lang == "en" else "أدلة سجّلها الرادار")
    return "\n".join(f"• {r}" for r in reasons[:3])


def case_summary(ev: dict[str, Any]) -> dict[str, Any]:
    """Structured, bilingual summary — no model, no invention, same shape as AI output."""
    domain = ev.get("domain") or "the reported domain"
    brand = ev.get("brand") or "a UAE brand"
    clone = ev.get("clone")
    veredict_en = "fake" if str(ev.get("verdict", "")).upper() == "MALICIOUS" else "suspicious"
    veredict_ar = "مزيّف" if str(ev.get("verdict", "")).upper() == "MALICIOUS" else "مشبوه"

    # the sentence skeleton is a template file; slots are the evidence fields
    skeleton_en = _template_file("fallback_case_skeleton_en.txt")
    skeleton_ar = _template_file("fallback_case_skeleton_ar.txt")
    common = {
        "domain": domain,
        "verdict": veredict_en,
        "verdict_ar": veredict_ar,
        "score": f"{float(ev.get('score') or 0):.2f}",
        "brand": brand,
        "clone": clone if clone is not None else "—",
        "gallery_match": ev.get("gallery_match") or "the official page",
        "reasons_en": _lines(ev, "en"),
        "reasons_ar": _lines(ev, "ar"),
        "priority": _priority(ev),
        "priority_ar": "قصوى (P1)" if _priority(ev) == "P1" else "عالية (P2)",
    }
    return {
        "summary_en": _fill(skeleton_en, common).strip(),
        "summary_ar": _fill(skeleton_ar, common).strip(),
        "provider": "template",
        "fallback": True,
    }


def takedown(ev: dict[str, Any]) -> dict[str, str]:
    domain = ev.get("domain") or "the reported domain"
    reasons = "\n".join(f"  - {r}" for r in (ev.get("reasons") or [])[:4]) or \
              "  - evidence captured by the Daggers radar"
    letter = _fill(_template_file("fallback_takedown_template_en.txt"),
                   {"domain": domain, "reasons": reasons,
                    "registrar": ev.get("registrar") or "the domain registrar"})
    return {"letter_en": letter.strip()}


def why_smells(ev: dict[str, Any]) -> dict[str, Any]:
    reasons = (ev.get("reasons") or [])[:2]
    joined = " and ".join(r.rstrip(".") for r in reasons) if reasons else "the evidence on file"
    text = _fill(_template_file("fallback_why_template_en.txt"), {"reasons": joined})
    return {"text_en": text.strip(), "provider": "template", "fallback": True}


def evidence_for_prompt(ev: dict[str, Any], allowed: set[str]) -> str:
    safe = {k: v for k, v in (ev or {}).items() if k in allowed}
    return json.dumps(safe, ensure_ascii=False, indent=2)
