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


TAG_WORDS = {
    "FAKE": ("FAKE (confirmed fraud or impersonation evidence)", "مزيّف (أدلة احتيال مؤكدة)"),
    "MISLEADING": ("MISLEADING (claim contradicted or unverifiable)", "مضلّل (ادعاء متناقض أو غير قابل للتحقق)"),
    "WARNING": ("WARNING (not an authenticated official source / needs review)", "تحذير (ليس مصدراً رسمياً موثّقاً / يحتاج مراجعة)"),
    "SAFE": ("SAFE (authenticated official source, nothing suspicious)", "آمن (مصدر رسمي موثّق دون مؤشرات مريبة)"),
}
AUTH_WORDS = {
    "AUTHENTICATED": ("approved official domain", "نطاق رسمي معتمد"),
    "UNLISTED": ("not in the official registry", "غير مدرج في السجل الرسمي"),
    "PENDING": ("registry entry pending review", "قيد المراجعة في السجل"),
    "REVOKED": ("registry approval revoked", "اعتماد ملغى"),
    "EXPIRED": ("registry approval expired", "اعتماد منتهي الصلاحية"),
    "NOT_CHECKABLE": ("could not be checked", "تعذّر التحقق"),
    "INDEPENDENT_MEDIA": ("independent media, not an official source", "إعلام مستقل وليس مصدراً رسمياً"),
}


def _tag(ev: dict[str, Any]) -> str:
    tag = str(ev.get("tag") or "").upper()
    if tag in TAG_WORDS:
        return tag
    return "FAKE" if str(ev.get("verdict", "")).upper() == "MALICIOUS" else "WARNING"


def _verification(ev: dict[str, Any]) -> tuple[str, str, list[str]]:
    ov = ev.get("official_verification") or {}
    status = ov.get("status") or "NOT_APPLICABLE"
    missing: list[str] = []
    if status == "NOT_APPLICABLE":
        return ("no government claim was verified for this finding.", "لم يُتحقق من أي ادعاء حكومي لهذه النتيجة.", missing)
    cites = [s for s in ov.get("sources") or [] if s.get("role") in ("decisive", "superseded")]
    cite_en = "; ".join(f"{s.get('organization')} ({s.get('source_url')}, {s.get('comparison')})" for s in cites[:3])
    unchecked = ov.get("unchecked_sources") or []
    if unchecked:
        missing.append("official sources not checked: " + ", ".join(unchecked))
    en = f"status {status}" + (f" — sources: {cite_en}." if cite_en else " — no decisive official source on file.")
    ar = f"الحالة {status}" + (" — المصادر مذكورة في الأدلة." if cite_en else " — لا يوجد مصدر رسمي حاسم في الملف.")
    return en, ar, missing


def case_summary(ev: dict[str, Any]) -> dict[str, Any]:
    """Evidence-only bilingual summary — no model, no invented facts, same UI shape."""
    domain = ev.get("domain") or "the reported domain"
    tag = _tag(ev)
    auth = (ev.get("domain_authentication") or {}).get("status")
    auth_en, auth_ar = AUTH_WORDS.get(auth, ("not recorded", "غير مسجّل"))
    verification_en, verification_ar, missing = _verification(ev)
    if not ev.get("reasons"):
        missing.append("no detection reasons recorded")
    if not ev.get("evidence_url"):
        missing.append("no screenshot evidence captured")
    if ev.get("clone") in (None, 0):
        missing.append("no visual-clone comparison")
    if tag == "FAKE":
        assessment_en = "the recorded signals are consistent with a scam or impersonation site."
        assessment_ar = "المؤشرات المسجّلة تتوافق مع موقع احتيال أو انتحال."
        next_en = "Keep the domain on the Guard blocklist, request registrar/hosting takedown, and notify the impersonated organisation."
        next_ar = "إبقاء النطاق في قائمة الحجب، وطلب الإزالة من المسجّل أو الاستضافة، وإبلاغ الجهة المنتحَلة."
    elif tag == "MISLEADING":
        assessment_en = "the site carries a government-related claim that official evidence contradicts or does not confirm."
        assessment_ar = "يتضمن الموقع ادعاءً حكومياً تناقضه الأدلة الرسمية أو لا تؤكده."
        next_en = "Confirm the claim with the responsible authority, preserve the page, and consider a public advisory."
        next_ar = "التأكد من الادعاء لدى الجهة المختصة، وحفظ الصفحة، والنظر في إصدار تنبيه عام."
    else:
        assessment_en = "the evidence is not sufficient to confirm fraud; authenticity is not established."
        assessment_ar = "الأدلة غير كافية لتأكيد الاحتيال، ولم تثبت أصالة الموقع."
        next_en = "Review manually, check the official sources listed as missing, and re-scan if new evidence appears."
        next_ar = "مراجعة يدوية، والتحقق من المصادر الرسمية غير المفحوصة، وإعادة الفحص عند ظهور أدلة جديدة."
    malicious = tag == "FAKE"
    priority = "P1" if malicious and (ev.get("scam_type") in P1_TYPES or (ev.get("clone") or 0) >= 90) else "P2"
    values = {
        "domain": domain, "score": f"{float(ev.get('score') or 0):.2f}",
        "tag_en": TAG_WORDS[tag][0], "tag_ar": TAG_WORDS[tag][1],
        "auth_en": auth_en, "auth_ar": auth_ar,
        "reasons_en": _lines(ev, "en"), "reasons_ar": _lines(ev, "ar"),
        "verification_en": verification_en, "verification_ar": verification_ar,
        "assessment_en": assessment_en, "assessment_ar": assessment_ar,
        "missing_en": "; ".join(missing) or "nothing flagged as missing.",
        "missing_ar": "؛ ".join(missing) if missing else "لا توجد نواقص مسجّلة.",
        "next_en": next_en, "next_ar": next_ar,
        "priority": priority, "priority_ar": "قصوى (P1)" if priority == "P1" else "عالية (P2)",
    }
    return {
        "summary_en": _fill(_template_file("fallback_case_skeleton_en.txt"), values).strip(),
        "summary_ar": _fill(_template_file("fallback_case_skeleton_ar.txt"), values).strip(),
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
