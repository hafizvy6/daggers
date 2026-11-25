from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from .homograph import confusable_fold, is_official_host
from .verdicts import MISLEADING, SUSPICIOUS

OFFER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("giveaway", re.compile(r"\b(?:giveaway|give-away|giving\s+away|lottery|prize|winner|you\s+won|reward|gift|free\s+cash)\b", re.I)),
    ("amount", re.compile(r"(?:\b\d[\d,.]*\s*(?:million|m|k)?\s*(?:aed|dirhams?|دِرهم|درهم|dhs?)\b)|(?:\b(?:aed|dhs?)\s*\d[\d,.]*(?:\s*(?:million|m|k))?\b)|(?:\b1\s*million\b)|(?:\b1m\s*(?:aed|dirham)\b)", re.I)),
    ("prize_claim", re.compile(r"\b(?:claim|collect|redeem)\s+(?:your\s+)?(?:prize|reward|gift|cash|million|money|funds?)\b", re.I)),
    ("arabic_offer", re.compile(r"(?:توزيع|هدية|جائزة|ربح|ربحت|فزت|يانصيب|مليون|درهم|دِرهم|مبلغ|مكافأة|فرصة)")),
    ("arabizi_offer", re.compile(r"\b(?:rab7|rabah|jayza|hadya|7adya|mablagh|million|dirhams?|giveaway|winner)\b", re.I)),
)

# Phishing/urgency intents - common in UAE scams (suspension, KYC, fines, delivery fee, OTP).
# These produce a SUSPICIOUS-floor signal when paired with an entity on a non-official host.
INTENT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("suspend_threat", re.compile(r"\b(?:suspend(?:ed)?|blocked|locked|deactivat(?:ed|ion)|restricted|frozen|limited)\b", re.I)),
    ("verify_pressure", re.compile(r"\b(?:verify|confirm|update|validate|reactivate|restore|unlock)\s+(?:your\s+)?(?:account|card|details|identity|information|kyc|wallet|profile)\b", re.I)),
    ("otp_request", re.compile(r"\b(?:otp|one[- ]time\s+password|verification\s+code|security\s+code|pin\s+code)\b", re.I)),
    ("fine_penalty", re.compile(r"\b(?:fine|penalty|traffic\s+fine|violation|toll|salik|overdue|outstanding)\b", re.I)),
    ("delivery_fee", re.compile(r"\b(?:delivery\s+fee|shipping\s+fee|customs\s+fee|customs\s+duty|redelivery|reschedule\s+delivery|package\s+(?:held|pending|waiting)|parcel\s+(?:held|pending|waiting))\b", re.I)),
    ("urgent_action", re.compile(r"\b(?:urgent|immediately|within\s+\d+\s+(?:hours?|minutes?)|act\s+now|final\s+warning|last\s+chance)\b", re.I)),
    ("payment_request", re.compile(r"\b(?:pay\s+now|make\s+a\s+payment|payment\s+required|settle\s+(?:your\s+)?(?:dues?|fine|fee|amount))\b", re.I)),
    ("arabic_intent", re.compile(r"(?:تم\s+إيقاف|معلق|محظور|مجمد|تحديث\s+بيانات|تحقق\s+من\s+حسابك|رمز\s+التحقق|غرامة|مخالفة|رسوم\s+جمركية|طرد\s+معلق|دفعة\s+مستحقة|عاجل)")),
    ("arabizi_intent", re.compile(r"\b(?:mowqaf|muallaq|gharama|mokhalafa|ta7qeeq|ta7deeth|tahdeeth)\b", re.I)),
)

ENTITY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("generic_entity", re.compile(r"\b(?:bank|police|government|ministry|airline|delivery|customs|courier|uae|abu\s+dhabi|dubai|sharjah|post|postal|package|parcel|shipment|visa|residency|emirates\s+id|eid|traffic|salik|rta|dewa|etisalat|du|adnoc|account|card|wallet)\b", re.I)),
    ("arabic_entity", re.compile(r"(?:بنك|شرطة|حكومة|وزارة|طيران|توصيل|جمارك|الإمارات|أبوظبي|دبي|الشارقة|بريد|طرد|شحنة|تأشيرة|إقامة|هوية\s+إماراتية|مرور|سالك)")),
)


def _fold_patterns(patterns: tuple[tuple[str, re.Pattern[str]], ...]) -> tuple[tuple[str, re.Pattern[str]], ...]:
    folded: list[tuple[str, re.Pattern[str]]] = []
    for label, pattern in patterns:
        try:
            folded.append((label, re.compile(confusable_fold(pattern.pattern), pattern.flags)))
        except re.error:
            folded.append((label, pattern))
    return tuple(folded)


OFFER_PATTERNS = _fold_patterns(OFFER_PATTERNS)
INTENT_PATTERNS = _fold_patterns(INTENT_PATTERNS)
ENTITY_PATTERNS = _fold_patterns(ENTITY_PATTERNS)


def _brand_tokens(brands: list[dict] | tuple[dict, ...]) -> tuple[str, ...]:
    tokens: list[str] = []
    for brand in brands:
        tokens.append(str(brand.get("token", "")).lower())
        tokens.extend(str(alias).lower() for alias in brand.get("aliases", []))
    return tuple(token for token in dict.fromkeys(tokens) if token)


@dataclass(frozen=True)
class ClaimSignal:
    weight: float = 0.50
    reason: str = "unverifiable claim — not found on official channels"
    forced_min: str = MISLEADING
    scam_type: str = "unverifiable-giveaway-claim"
    matched_patterns: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return "claims.unverifiable"


@dataclass(frozen=True)
class IntentSignal:
    weight: float = 0.45
    reason: str = "phishing intent — impersonation/urgency on non-official channel"
    forced_min: str = SUSPICIOUS
    scam_type: str = "phishing-intent"
    matched_patterns: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return "claims.phishing_intent"


def _bare_host(value: str) -> str:
    candidate = str(value or "").strip().lower()
    if "://" in candidate:
        return (urlparse(candidate).hostname or "").rstrip(".")
    return candidate.split("/", 1)[0].rstrip(".")


def evaluate_claims(
    text: str,
    host: str,
    brands: list[dict] | tuple[dict, ...],
    official_domains: tuple[str, ...] | list[str],
) -> ClaimSignal | IntentSignal | None:
    """S3: an offer + entity on a non-official host forces >= MISLEADING.
    Phishing intent + entity on a non-official host forces >= SUSPICIOUS."""
    haystack = confusable_fold(f"{text or ''} {host or ''}")
    bare_host = _bare_host(host)
    official = bool(bare_host) and any(is_official_host(bare_host, domain) for domain in official_domains)
    if official:
        return None

    offer_hits = tuple(label for label, pattern in OFFER_PATTERNS if pattern.search(haystack))
    intent_hits = tuple(label for label, pattern in INTENT_PATTERNS if pattern.search(haystack))
    entity_hits = tuple(label for label, pattern in ENTITY_PATTERNS if pattern.search(haystack))
    brand_hits = tuple(token for token in _brand_tokens(brands) if len(token) >= 3 and confusable_fold(token) in haystack)
    has_entity = bool(entity_hits or brand_hits)
    entity_label = ("brand_claim",) if brand_hits else ()

    # Giveaway / unverifiable claim (strongest, MISLEADING floor)
    if offer_hits and has_entity:
        matched = offer_hits + entity_hits + entity_label
        detail = ", ".join(matched[:6])
        return ClaimSignal(
            reason=f"unverifiable claim — not found on official channels ({detail})",
            matched_patterns=matched,
        )

    # Phishing intent (SUSPICIOUS floor) - require intent + entity
    if intent_hits and has_entity:
        matched = intent_hits + entity_hits + entity_label
        detail = ", ".join(matched[:6])
        # Escalate to MISLEADING if multiple intent categories or urgent+payment
        strong = {"suspend_threat", "otp_request", "payment_request", "fine_penalty", "delivery_fee"}
        strong_hits = sum(1 for h in intent_hits if h in strong)
        if strong_hits >= 2 or ("urgent_action" in intent_hits and strong_hits >= 1):
            return ClaimSignal(
                weight=0.50,
                reason=f"high-risk phishing intent on non-official channel ({detail})",
                forced_min=MISLEADING,
                scam_type="phishing-intent",
                matched_patterns=matched,
            )
        return IntentSignal(
            reason=f"phishing intent — impersonation/urgency on non-official channel ({detail})",
            matched_patterns=matched,
        )

    return None
