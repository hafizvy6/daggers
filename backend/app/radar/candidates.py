"""Candidate admission for radar sightings.

Certificate Transparency can emit thousands of names for a short brand token. A
name is admitted only when the brand appears as a real label or as a controlled
prefix/suffix with a generic banking/login suffix. Substring-only matches such
as fab7.com are rejected before they consume enrichment, rendering, or analyst
attention.
"""
from __future__ import annotations

import re
from typing import Iterable, Mapping

from ..core import homograph

_SPLIT_RE = re.compile(r"[^0-9a-z\u0600-\u06ff]+")
_GENERIC_CONCAT = re.compile(
    r"^(?:" + "|".join(sorted((re.escape(x) for x in [
        "account","alert","bank","banking","cards","help","home","login","mobile","online",
        "pay","payment","portal","secure","service","support","web"
    ]), key=len, reverse=True)) + r")$"
)
GENERIC_SUFFIXES = {
    "account",
    "account-login",
    "alert",
    "bank",
    "banking",
    "cards",
    "customer",
    "help",
    "home",
    "login",
    "mobile",
    "online",
    "pay",
    "payment",
    "portal",
    "secure",
    "secure-login",
    "service",
    "support",
    "uae",
    "web",
    "www",
    "ae",
}
MIN_CT_TERM = 4


def compact(value: str) -> str:
    folded = homograph.confusable_fold(str(value or "").casefold())
    return "".join(ch for ch in folded if ch.isalnum())


def labels_and_segments(domain: str) -> tuple[list[str], list[str]]:
    decoded = str(homograph.host_forms(str(domain or "").strip().lower().rstrip("."))["unicode_host"])
    labels = [homograph.confusable_fold(part.casefold()) for part in decoded.split(".") if part]
    segments: list[str] = []
    for label in labels:
        segments.extend(part for part in _SPLIT_RE.split(label) if part)
    return labels, segments



def match_terms(domain: str, terms: Iterable[str]) -> list[str]:
    clean = str(homograph.host_forms(str(domain or "").strip().lower().rstrip("."))["unicode_host"])
    if not clean:
        return []
    labels, segments = labels_and_segments(clean)
    matches: list[str] = []
    for raw in terms:
        term = compact(raw)
        if len(term) < MIN_CT_TERM:
            continue
        if any(segment == term for segment in segments):
            matches.append(term)
            continue
        for label in labels:
            if label == term:
                matches.append(term)
                break
            if label.startswith(term):
                remainder = label[len(term) :]
                if (
                    remainder in GENERIC_SUFFIXES
                    or remainder.split("-", 1)[0] in GENERIC_SUFFIXES
                    or bool(_GENERIC_CONCAT.match(remainder))
                ):
                    matches.append(term)
                    break
            if label.endswith(term):
                remainder = label[: -len(term)]
                if remainder in GENERIC_SUFFIXES or remainder.split("-", 1)[-1] in GENERIC_SUFFIXES:
                    matches.append(term)
                    break
    return list(dict.fromkeys(matches))


def is_official(domain: str, official_domains: Iterable[str]) -> bool:
    clean = str(domain or "").strip().lower().rstrip(".")
    for official in official_domains:
        if homograph.is_official_host(clean, str(official).strip().lower().rstrip(".")):
            return True
    return False


def admit_candidate(
    domain: str,
    terms: Iterable[str],
    official_domains: Iterable[str],
    *,
    enforce_suffix: bool = True,
) -> dict:
    """Return whether a radar sighting is worth enrichment and why."""
    clean = str(domain or "").strip().lower().rstrip(".")
    if not clean or "." not in clean:
        return {"admitted": False, "reason": "not-a-domain", "matched_terms": []}
    if is_official(clean, official_domains):
        return {"admitted": False, "reason": "official-registry", "matched_terms": []}
    matches = match_terms(clean, terms)
    if not matches:
        return {"admitted": False, "reason": "no-high-signal-brand-match", "matched_terms": []}
    return {"admitted": True, "reason": "high-signal-brand-match", "matched_terms": matches}
