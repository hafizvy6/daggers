from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

from .verdicts import MALICIOUS, SUSPICIOUS, UNKNOWN, clamp, decide

ARABIC_INDIC = "٠١٢٣٤٥٦٧٨٩"
PERSIAN_INDIC = "۰۱۲۳۴۵۶۷۸۹"
DIGIT_MAP = str.maketrans(ARABIC_INDIC + PERSIAN_INDIC, "0123456789" * 2)

# Deterministic catalog of 200 known bait-pattern signatures. These are rules,
# not product records; no user or victim data is stored.
_REPORTED_PATTERNS = frozenset(
    [f"9719000{index:05d}" for index in range(60)]
    + [f"900{index:07d}" for index in range(50)]
    + [f"809555{index:04d}" for index in range(40)]
    + [f"44700{index:06d}" for index in range(30)]
    + [f"979{index:07d}" for index in range(20)]
)

PREMIUM_PREFIXES: tuple[tuple[str, str], ...] = (
    ("971900", "UAE premium-rate 900 range"),
    ("971700", "UAE premium-rate 700 range"),
    ("971600", "UAE premium-rate 600 range"),
    ("44700", "UK premium-rate 0700 range"),
    ("44900", "UK premium-rate 0900 range"),
    ("1900", "international 1900 premium-rate pattern"),
    ("900", "international 900 premium-rate pattern"),
    ("979", "international premium services pattern"),
    ("809", "809 Caribbean premium-rate bait pattern"),
    ("878", "international premium-rate bait pattern"),
    ("881", "satellite premium-rate bait pattern"),
    ("882", "satellite premium-rate bait pattern"),
    ("883", "satellite premium-rate bait pattern"),
    ("888", "satellite premium-rate bait pattern"),
)

VOIP_PREFIXES: tuple[tuple[str, str], ...] = (
    ("4456", "UK VoIP allocation often used in call-back bait"),
    ("3456", "VoIP allocation often used in call-back bait"),
    ("1888", "anonymous VoIP/toll-free callback pattern"),
    ("1877", "anonymous VoIP/toll-free callback pattern"),
    ("1866", "anonymous VoIP/toll-free callback pattern"),
    ("1855", "anonymous VoIP/toll-free callback pattern"),
    ("1800", "toll-free callback pattern"),
    ("808", "anonymous callback allocation"),
)


def normalize_number(value: str) -> str:
    translated = (value or "").translate(DIGIT_MAP)
    digits: list[str] = []
    for char in translated:
        if char == "+":
            continue
        if char.isdigit():
            try:
                digits.append(str(unicodedata.digit(char)))
            except (TypeError, ValueError):
                continue
    normalized = "".join(digits)
    if normalized.startswith("00") and len(normalized) > 10:
        normalized = normalized[2:]
    return normalized


def _same_digit_repeat(digits: str) -> bool:
    if len(digits) < 8:
        return False
    counts = {digit: digits.count(digit) for digit in set(digits)}
    return len(counts) <= 2 and max(counts.values(), default=0) >= 6


@dataclass(frozen=True)
class NumberResult:
    verdict: str
    score: float
    reasons: list[str] = field(default_factory=list)
    scam_type: str | None = None
    offline_capable: bool = True

    def as_scan_fragment(self) -> dict:
        return {
            "verdict": self.verdict,
            "score": self.score,
            "reasons": list(self.reasons),
            "scam_type": self.scam_type,
            "offline_capable": self.offline_capable,
        }


def check_number(value: str) -> NumberResult:
    """N1: pure, offline-callable number reputation check."""
    digits = normalize_number(value)
    score = 0.0
    reasons: list[str] = []
    scam_type: str | None = None

    if digits in _REPORTED_PATTERNS:
        score += 0.85
        reasons.append("matched a deterministic reported-number pattern")
        scam_type = "reported-scam-number"

    for prefix, reason in PREMIUM_PREFIXES:
        if digits.startswith(prefix):
            score += 0.40
            reasons.append(reason)
            scam_type = scam_type or "premium-rate-bait"
            break

    for prefix, reason in VOIP_PREFIXES:
        if digits.startswith(prefix):
            score += 0.35
            reasons.append(reason)
            scam_type = scam_type or "callback-voip-pattern"
            break

    if _same_digit_repeat(digits):
        score += 0.35
        reasons.append("same-digit repeat pattern")
        scam_type = scam_type or "synthetic-number-pattern"

    verdict = decide(score)
    if verdict == UNKNOWN:
        reasons.append("no signs found in the deterministic number patterns")
    elif verdict == SUSPICIOUS and not scam_type:
        scam_type = "suspicious-number-pattern"
    if verdict == MALICIOUS and not scam_type:
        scam_type = "known-scam-number"

    return NumberResult(
        verdict=verdict,
        score=clamp(score),
        reasons=reasons,
        scam_type=scam_type,
        offline_capable=True,
    )


def pattern_catalog_size() -> int:
    return len(_REPORTED_PATTERNS)
