"""Trust-policy adapter: the single place that turns evidence into a UI tag.

Four independent inputs are kept separate and reported separately:

1. domain authentication  (official registry; approved + fresh only)
2. claim verification      (official-source engine; may be absent)
3. maliciousness evidence  (core brain verdict / score / reasons)
4. final tag               (SAFE | WARNING | MISLEADING | FAKE)

Hard rules:
* SAFE requires an AUTHENTICATED domain AND no suspicious content.
* UNKNOWN (no signals) never becomes SAFE by itself — it becomes WARNING.
* A genuine official domain with a contradicted / unverifiable claim or flagged
  content gets WARNING + manual review, never automatic FAKE.
* Unknown domains are not automatically FAKE either.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .official import POLICY_VERSION
from .official.models import (
    AUTH_EXPIRED,
    AUTH_INDEPENDENT_MEDIA,
    AUTH_NOT_CHECKABLE,
    AUTH_PENDING,
    AUTH_REVOKED,
    AUTH_UNLISTED,
    CONFLICTING_SOURCES,
    CONTRADICTED,
    NOT_VERIFIABLE,
    SOURCE_EXPIRED,
    SOURCE_UNAVAILABLE,
    VERIFIED,
    DomainAuthentication,
    GovVerification,
)

SAFE = "SAFE"
WARNING = "WARNING"
MISLEADING = "MISLEADING"
FAKE = "FAKE"
TAGS = (SAFE, WARNING, MISLEADING, FAKE)
TAG_RANK = {SAFE: 0, WARNING: 1, MISLEADING: 2, FAKE: 3}

WS1_UNKNOWN, WS1_SUSPICIOUS, WS1_MISLEADING, WS1_MALICIOUS = "UNKNOWN", "SUSPICIOUS", "MISLEADING", "MALICIOUS"

_AUTH_REASON = {
    AUTH_UNLISTED: "domain is not an authenticated official source",
    AUTH_PENDING: "domain's registry entry is pending human review — not authenticated",
    AUTH_REVOKED: "domain's registry approval was revoked — not authenticated",
    AUTH_EXPIRED: "domain's registry approval has expired — not authenticated",
    AUTH_NOT_CHECKABLE: "domain authenticity could not be checked",
    AUTH_INDEPENDENT_MEDIA: "independent media outlet — not an official government source",
}


@dataclass(frozen=True)
class Maliciousness:
    ws1_verdict: str
    ws1_score: float
    reasons: tuple[str, ...] = ()
    content_flags: tuple[str, ...] = ()  # e.g. offer/giveaway pattern found in page content
    domain_name_only: bool = False       # every core signal came from the domain/URL name itself

    @property
    def confirmed(self) -> bool:
        return self.ws1_verdict == WS1_MALICIOUS

    @property
    def suspicious(self) -> bool:
        return self.ws1_verdict != WS1_UNKNOWN or bool(self.content_flags)

    def as_dict(self) -> dict:
        return {
            "ws1_verdict": self.ws1_verdict,
            "ws1_score": self.ws1_score,
            "confirmed_malicious": self.confirmed,
            "reasons": list(self.reasons),
            "content_flags": list(self.content_flags),
        }


@dataclass(frozen=True)
class TrustDecision:
    tag: str
    manual_review: bool
    domain_auth: DomainAuthentication
    gov_verification: GovVerification | None
    maliciousness: Maliciousness
    reasons: tuple[str, ...] = field(default_factory=tuple)
    policy_version: str = POLICY_VERSION

    @property
    def blockable(self) -> bool:
        """Guard may block only confirmed FAKE on a non-authenticated domain."""
        return self.tag == FAKE and self.maliciousness.confirmed and not self.domain_auth.authenticated

    def as_dict(self) -> dict:
        return {
            "tag": self.tag,
            "manual_review": self.manual_review,
            "domain_authentication": self.domain_auth.as_dict(),
            "claim_verification": self.gov_verification.as_dict() if self.gov_verification else None,
            "maliciousness": self.maliciousness.as_dict(),
            "reasons": list(self.reasons),
            "blockable": self.blockable,
            "policy_version": self.policy_version,
        }


def _max(current: str, candidate: str) -> str:
    return candidate if TAG_RANK[candidate] > TAG_RANK[current] else current


def decide(
    domain_auth: DomainAuthentication,
    maliciousness: Maliciousness,
    gov: GovVerification | None = None,
) -> TrustDecision:
    reasons: list[str] = []
    manual = False
    gov_status = gov.status if gov else None
    gov_claim = bool(gov and gov.claim.is_government_claim)

    if domain_auth.authenticated:
        tag = SAFE
        reasons.append(domain_auth.reason or "authenticated official domain")
        if maliciousness.confirmed:
            tag, manual = WARNING, True
            reasons.append(
                "strong malicious signals on an authenticated official domain — possible compromise or "
                "fraudulent hosted content; escalate for manual review (not auto-labelled FAKE)"
            )
        elif gov_claim and gov_status == VERIFIED:
            reasons.append("government claim on this official domain is verified by approved sources")
        elif maliciousness.content_flags or (
            maliciousness.ws1_verdict != WS1_UNKNOWN and not maliciousness.domain_name_only
        ):
            tag, manual = WARNING, True
            reasons.append("suspicious content on an authenticated official domain — manual review")
        elif maliciousness.ws1_verdict != WS1_UNKNOWN:
            reasons.append(
                "domain-name heuristics (look-alike/lexical) are superseded by registry authentication of this exact domain"
            )
        if gov_claim and gov_status != VERIFIED:
            tag, manual = _max(tag, WARNING), True
            reasons.append(
                f"government claim on this official domain is {gov_status} — content may be user-generated; "
                "manual review"
            )
        return TrustDecision(tag, manual, domain_auth, gov, maliciousness, tuple(dict.fromkeys(reasons)))

    # ---- not authenticated: SAFE is impossible.
    tag = WARNING
    reasons.append(_AUTH_REASON.get(domain_auth.status, "domain is not authenticated") +
                   (f" ({domain_auth.reason})" if domain_auth.status == AUTH_NOT_CHECKABLE and domain_auth.reason else ""))
    if maliciousness.ws1_verdict == WS1_MALICIOUS:
        tag = FAKE
        reasons.append("confirmed malicious by deterministic evidence")
    elif maliciousness.ws1_verdict == WS1_MISLEADING:
        tag = MISLEADING
        reasons.append("unverifiable or misleading claim pattern")
    elif maliciousness.ws1_verdict == WS1_SUSPICIOUS:
        reasons.append("suspicious signals present")
    else:
        reasons.append("no scam signals found, but absence of signals does not establish authenticity")

    if gov_claim:
        if gov_status == CONTRADICTED:
            tag = _max(tag, MISLEADING)
            reasons.append("government claim is contradicted by approved official evidence")
        elif gov_status == NOT_VERIFIABLE and gov is not None and gov.coverage == "checked":
            tag = _max(tag, MISLEADING)
            reasons.append("government claim could not be verified against the relevant approved sources")
        elif gov_status == NOT_VERIFIABLE:
            manual = True
            reasons.append("no approved official source covers this government claim — manual review")
        elif gov_status in (SOURCE_UNAVAILABLE, SOURCE_EXPIRED, CONFLICTING_SOURCES):
            manual = True
            reasons.append(f"government claim status {gov_status} — official sources not conclusively checked; manual review")
        elif gov_status == VERIFIED:
            reasons.append("claim matches an official source, but this site is not that official source")
    return TrustDecision(tag, manual, domain_auth, gov, maliciousness, tuple(dict.fromkeys(reasons)))


def ws1_verdict_to_tag_without_auth(verdict: str) -> str:
    """Tag for surfaces that have NO domain to authenticate (numbers, plain text)."""
    return {WS1_MALICIOUS: FAKE, WS1_MISLEADING: MISLEADING}.get(verdict, WARNING)


def worst(tags: Iterable[str]) -> str:
    result = SAFE
    seen = False
    for tag in tags:
        seen = True
        result = _max(result, tag)
    return result if seen else WARNING
