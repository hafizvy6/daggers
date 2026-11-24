from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from .homograph import confusable_fold, is_official_host
from .verdicts import MISLEADING

OFFER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("giveaway", re.compile(r"\b(?:giveaway|give-away|giving\s+away|lottery|prize|winner|you\s+won|reward|gift|free\s+cash)\b", re.I)),
    ("amount", re.compile(r"(?:\b\d[\d,.]*\s*(?:million|m|k)?\s*(?:aed|dirhams?|درهم|دِرهم)\b)|(?:\b1\s*million\b)|(?:\b1m\s*(?:aed|dirham)\b)", re.I)),
    ("prize_claim", re.compile(r"\b(?:claim|collect|redeem)\s+(?:your\s+)?(?:prize|reward|gift|cash|million)\b", re.I)),
    ("arabic_offer", re.compile(r"(?:توزيع|هدية|جائزة|ربح|ربحت|فزت|يانصيب|مليون|درهم|دِرهم|مبلغ|مكافأة|فرصة)")),
    ("arabizi_offer", re.compile(r"\b(?:rab7|rabah|jayza|hadya|7adya|mablagh|million|dirhams?|giveaway|winner)\b", re.I)),
)

ENTITY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("generic_entity", re.compile(r"\b(?:bank|police|government|ministry|airline|delivery|customs|courier|uae|abu\s+dhabi|dubai)\b", re.I)),
    ("arabic_entity", re.compile(r"(?:بنك|شرطة|حكومة|وزارة|طيران|توصيل|جمارك|الإمارات|أبوظبي|دبي)")),
)


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
) -> ClaimSignal | None:
    """S3: an offer + an entity claim + a non-official host forces >= MISLEADING."""
    haystack = confusable_fold(f"{text or ''} {host or ''}")
    bare_host = _bare_host(host)
    official = bool(bare_host) and any(is_official_host(bare_host, domain) for domain in official_domains)
    if official:
        return None

    offer_hits = tuple(label for label, pattern in OFFER_PATTERNS if pattern.search(haystack))
    entity_hits = tuple(label for label, pattern in ENTITY_PATTERNS if pattern.search(haystack))
    brand_hits = tuple(token for token in _brand_tokens(brands) if len(token) >= 3 and confusable_fold(token) in haystack)
    if not offer_hits or not (entity_hits or brand_hits):
        return None

    matched = offer_hits + entity_hits + ("brand_claim",) if brand_hits else offer_hits + entity_hits
    detail = ", ".join(matched[:6])
    return ClaimSignal(
        reason=f"unverifiable claim — not found on official channels ({detail})",
        matched_patterns=matched,
    )
