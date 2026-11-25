from __future__ import annotations

from typing import Mapping

UNKNOWN = "UNKNOWN"
SUSPICIOUS = "SUSPICIOUS"
MISLEADING = "MISLEADING"
MALICIOUS = "MALICIOUS"

VERDICTS = (UNKNOWN, SUSPICIOUS, MISLEADING, MALICIOUS)
RANK = {UNKNOWN: 0, SUSPICIOUS: 1, MISLEADING: 2, MALICIOUS: 3}

# UNKNOWN means "no signals", not "authentic". SAFE is only ever produced by the
# WS2 trust policy for an approved, fresh official domain (channels/trust_policy.py).
UI_TAGS = {
    UNKNOWN: "WARNING",
    SUSPICIOUS: "WARNING",
    MISLEADING: "MISLEADING",
    MALICIOUS: "FAKE",
}

DEFAULT_THRESHOLDS = {
    "MALICIOUS": 0.65,
    "SUSPICIOUS": 0.35,
    "RENDER_SCORE_MIN": 0.45,
    "AUTOFILE_CLONE_MIN": 90.0,
}


def clamp(value: float) -> float:
    return round(max(0.0, min(1.0, value)), 4)


def decide(
    score: float,
    *,
    forced_min: str | None = None,
    cap: str | None = None,
    thresholds: Mapping[str, float] | None = None,
) -> str:
    """Deterministic S6 verdict.

    A claim can raise the floor. Claim-only cases can also be capped at
    MISLEADING so an unverifiable claim is not promoted to confirmed FAKE by
    unrelated lexical weight; clone/feed/content proof removes the cap.
    """
    active = dict(DEFAULT_THRESHOLDS)
    if thresholds:
        active.update(thresholds)
    score = clamp(score)
    if score >= active["MALICIOUS"]:
        verdict = MALICIOUS
    elif score >= active["SUSPICIOUS"]:
        verdict = SUSPICIOUS
    else:
        verdict = UNKNOWN
    if forced_min and RANK.get(forced_min, 0) > RANK[verdict]:
        verdict = forced_min
    if cap and RANK.get(cap, RANK[MALICIOUS]) < RANK[verdict]:
        verdict = cap
    return verdict


def policy(
    verdict: str,
    score: float,
    clone_score: float | None,
    *,
    thresholds: Mapping[str, float] | None = None,
    guard_block_misleading: bool = False,
) -> dict[str, bool]:
    """Config-driven policies, kept separate from the evidence score."""
    active = dict(DEFAULT_THRESHOLDS)
    if thresholds:
        active.update(thresholds)
    clone = float(clone_score or 0.0)
    return {
        "render": score >= active["RENDER_SCORE_MIN"] or verdict in {MISLEADING, MALICIOUS},
        "autofile": verdict == MALICIOUS and clone >= active["AUTOFILE_CLONE_MIN"],
        "guard_block": verdict == MALICIOUS
        or (guard_block_misleading and verdict == MISLEADING),
    }


def ui_tag(verdict: str) -> str:
    return UI_TAGS.get(verdict, "WARNING")
