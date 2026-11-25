"""Trust policy: the ONE place that turns evidence into the final tag.

Inputs, kept separate and reported separately:

1. domain authentication  (registry: approved + fresh + exact host / listed subdomain)
2. claim verification      (official-source engine; may be absent)
3. maliciousness evidence  (intelligence engine verdict / score / signals)
4. final tag               (SAFE | WARNING | MISLEADING | FAKE)

Two independent SAFE paths, both requiring a clean security analysis:

* GOVERNMENT path   — approved, fresh Class A/B registry entry for the EXACT host (or an
                      explicitly listed subdomain) → AUTHENTICATED.
* NON-GOVERNMENT    — (a) approved Class C news outlet / Class P verified organisation
  path                (INDEPENDENT_MEDIA / VERIFIED_ORGANIZATION), or (b) a host the registry
                      does not know whose domain is ranked in the Tranco top-sites list, is not a
                      shared platform and is not a government zone (REPUTABLE_SITE, see
                      channels/reputation.py). (b) additionally needs ZERO engine signals.
                      SAFE here means "legitimate website", never "official government source".

Hard rules:
* Unlisted-and-not-reputable / pending / revoked / expired / uncheckable → never SAFE (WARNING at most clean).
* Authentication never overrides CONFIRMED malicious activity: content- or feed-based
  malicious evidence on an authenticated domain → FAKE + manual review (possible
  compromise; Guard still never blocks a registry domain).
* Suspicious content on an authenticated domain → WARNING + manual review.
* Domain-NAME heuristics (look-alike / lexical) are superseded by registry
  authentication of that exact host — the registry proves the name is genuine.
* Missing data is not evidence: claims that could not be checked because official
  records are unavailable/expired do not remove SAFE from an authenticated domain;
  a claim CONTRADICTED by approved sources, or conflicting sources, does.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
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
    "VERIFIED_ORGANIZATION": "verified organisation — not an official government source",
    "REPUTABLE_SITE": "widely used website — not an official government source",
    "ESTABLISHED_SITE": "established website — not an official government source",
}


@dataclass(frozen=True)
class Maliciousness:
    ws1_verdict: str
    ws1_score: float
    reasons: tuple[str, ...] = ()
    content_flags: tuple[str, ...] = ()  # e.g. offer/giveaway pattern found in page content
    domain_name_only: bool = False       # every WS1 signal came from the domain/URL name itself

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
    final_auth: DomainAuthentication | None = None     # host the link finally lands on (redirects)

    @property
    def reason_codes(self) -> list[str]:
        return [reason_code(r) for r in self.reasons]

    @property
    def blockable(self) -> bool:
        """Guard may block only confirmed FAKE on a domain that is neither authenticated nor a known
        legitimate site (blocking youtube.com because of one bad link would break the internet)."""
        return (self.tag == FAKE and self.maliciousness.confirmed
                and not (self.domain_auth.authenticated or self.domain_auth.legitimate_site))

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
            "reason_codes": self.reason_codes,
            "final_domain_authentication": self.final_auth.as_dict() if self.final_auth else None,
        }


def _max(current: str, candidate: str) -> str:
    return candidate if TAG_RANK[candidate] > TAG_RANK[current] else current


GAP_STATUSES = (SOURCE_UNAVAILABLE, SOURCE_EXPIRED)


def _clean_or_flagged(domain_auth, maliciousness, reasons) -> tuple[str, bool]:
    """Shared security gate for both SAFE paths. → (tag, manual_review)."""
    if maliciousness.confirmed and not maliciousness.domain_name_only:
        reasons.append(
            "CONFIRMED malicious activity on an approved domain — possible compromise or fraudulent "
            "hosted content; registry approval does not override it (manual review)"
        )
        return FAKE, True
    if maliciousness.content_flags or (
        maliciousness.ws1_verdict != WS1_UNKNOWN and not maliciousness.domain_name_only
    ):
        reasons.append("suspicious content on an approved domain — manual review")
        return WARNING, True
    if maliciousness.ws1_verdict != WS1_UNKNOWN:
        reasons.append(
            "domain-name heuristics (look-alike/lexical) are superseded by registry approval of this exact domain"
        )
    return SAFE, False


# Stable, backward-compatible reason codes. The human-readable reasons are unchanged; each one
# maps to exactly one code (first match wins). Clients may switch on codes; texts may evolve.
REASON_CODES: tuple[tuple[str, str], ...] = (
    ("approved official domain of", "AUTH_GOV_APPROVED"),
    ("approved independent news outlet", "AUTH_NEWS_APPROVED"),
    ("verified website of", "AUTH_ORG_VERIFIED"),
    ("widely used website", "REPUTATION_WIDELY_USED"),
    ("established website", "ESTABLISHED_SITE"),
    ("CONFIRMED malicious activity on an approved domain", "MALICIOUS_ON_TRUSTED_DOMAIN"),
    ("suspicious content on an approved domain", "SUSPICIOUS_CONTENT_ON_TRUSTED_DOMAIN"),
    ("domain-name heuristics", "NAME_HEURISTICS_SUPERSEDED"),
    ("popularity alone does not override", "REPUTATION_NOT_OVERRIDING_SIGNALS"),
    ("which is not an approved or reputable site", "REDIRECT_OFF_TRUSTED_SITE"),
    ("redirects to the approved site", "REDIRECT_TO_OFFICIAL_NOT_INHERITED"),
    ("the link redirects to", "REDIRECT_OBSERVED"),
    ("reputation check:", "REPUTATION_CHECK"),
    ("government domain that is not in the official registry", "GOV_ZONE_NOT_IN_REGISTRY"),
    ("pending human review", "AUTH_PENDING"),
    ("approval was revoked", "AUTH_REVOKED"),
    ("approval has expired", "AUTH_EXPIRED"),
    ("authenticity could not be checked", "AUTH_NOT_CHECKABLE"),
    ("not an authenticated official source", "AUTH_UNLISTED"),
    ("not authenticated", "AUTH_NOT_AUTHENTICATED"),
    ("independent media outlet", "AUTH_NEWS_APPROVED"),
    ("verified organisation", "AUTH_ORG_VERIFIED"),
    ("confirmed malicious by deterministic evidence", "ENGINE_MALICIOUS"),
    ("unverifiable or misleading claim pattern", "ENGINE_MISLEADING"),
    ("suspicious signals present", "ENGINE_SUSPICIOUS"),
    ("absence of signals does not establish authenticity", "NO_SIGNALS_NOT_PROOF"),
    ("is contradicted by approved official", "CLAIM_CONTRADICTED"),
    ("contradicted", "CLAIM_CONTRADICTED"),
    ("CONFLICTING", "CLAIM_CONFLICTING_SOURCES"),
    ("could not be verified", "CLAIM_NOT_VERIFIED"),
    ("not independently checked", "CLAIM_NOT_CHECKED"),
    ("no approved official source covers", "CLAIM_NO_SOURCE"),
    ("not conclusively checked", "CLAIM_SOURCES_UNAVAILABLE"),
    ("matches an official source", "CLAIM_VERIFIED"),
    ("NOT_VERIFIABLE", "CLAIM_NOT_VERIFIED"),
)


def reason_code(text: str) -> str:
    for needle, code in REASON_CODES:
        if needle in text:
            return code
    return "OTHER"


def decide(
    domain_auth: DomainAuthentication,
    maliciousness: Maliciousness,
    gov: GovVerification | None = None,
    final_auth: DomainAuthentication | None = None,
) -> TrustDecision:
    """Central verdict. `final_auth`: authentication of the host the link REDIRECTS to (when the
    page was retrieved). A link never inherits SAFE from where it redirects, and a SAFE site that
    sends the visitor off to an untrusted host loses SAFE."""
    d = _decide(domain_auth, maliciousness, gov)
    if final_auth is None or not final_auth.host or final_auth.host == domain_auth.host:
        return d
    reasons = list(d.reasons)
    tag, manual = d.tag, d.manual_review
    trusted_final = final_auth.authenticated or final_auth.legitimate_site
    if tag == SAFE and not trusted_final:
        tag, manual = WARNING, True
        reasons.append(f"the link redirects to {final_auth.host}, which is not an approved or reputable site — "
                       "SAFE does not carry over to a redirect target (manual review)")
    elif tag != SAFE and final_auth.authenticated:
        reasons.append(f"the link redirects to the approved site {final_auth.host}, but the link itself is not "
                       "that site — it does not inherit SAFE from the redirect target")
    else:
        reasons.append(f"the link redirects to {final_auth.host} ({final_auth.status})")
    return replace(d, tag=tag, manual_review=manual, reasons=tuple(dict.fromkeys(reasons)), final_auth=final_auth)


def _decide(
    domain_auth: DomainAuthentication,
    maliciousness: Maliciousness,
    gov: GovVerification | None = None,
) -> TrustDecision:
    reasons: list[str] = []
    manual = False
    gov_status = gov.status if gov else None
    gov_claim = bool(gov and gov.claim.is_government_claim)

    # ---- SAFE path 1: approved, fresh government domain
    if domain_auth.authenticated:
        reasons.append(domain_auth.reason or "authenticated official domain")
        tag, manual = _clean_or_flagged(domain_auth, maliciousness, reasons)
        if gov_claim and tag != FAKE:
            own = domain_auth.entry_id in tuple(getattr(gov.claim, "entity_ids", ()) or ())
            if gov_status in (CONTRADICTED, CONFLICTING_SOURCES):
                tag, manual = _max(tag, WARNING), True
                reasons.append(f"a government claim on this page is {gov_status} by approved official sources "
                               "— content may be user-generated or outdated; manual review")
            elif gov_status == NOT_VERIFIABLE and gov.coverage == "checked" and not own:
                tag, manual = _max(tag, WARNING), True
                reasons.append("a claim about another authority could not be verified against its approved sources "
                               "— manual review")
            elif gov_status in GAP_STATUSES or gov_status == NOT_VERIFIABLE:
                reasons.append(f"claim on this page not independently checked ({gov_status}) — missing official "
                               "records are not evidence against an authenticated official domain")
        return TrustDecision(tag, manual, domain_auth, gov, maliciousness, tuple(dict.fromkeys(reasons)))

    # ---- SAFE path 2: approved, fresh non-government site (news outlet / verified organisation)
    if domain_auth.legitimate_site:
        reasons.append(domain_auth.reason or "verified legitimate website — not a government source")
        tag, manual = _clean_or_flagged(domain_auth, maliciousness, reasons)
        if (domain_auth.status in ("REPUTABLE_SITE", "ESTABLISHED_SITE") and tag == SAFE
                and maliciousness.ws1_verdict != WS1_UNKNOWN):
            # Popularity is weaker evidence than a human-reviewed registry entry: it never
            # supersedes ANY engine signal, not even domain-name heuristics.
            tag = WARNING
            reasons[:] = [r for r in reasons if not r.startswith("domain-name heuristics")]
            reasons.append("the engine found warning signs; popularity alone does not override them")
        if gov_claim and tag != FAKE:
            if gov_status == CONTRADICTED:
                tag, manual = _max(tag, MISLEADING), True
                reasons.append("a government claim on this site is contradicted by approved official evidence")
            elif gov_status == CONFLICTING_SOURCES or (gov_status == NOT_VERIFIABLE and gov.coverage == "checked"):
                tag, manual = _max(tag, WARNING), True
                reasons.append(f"a government claim on this site is {gov_status} — check the official source")
            elif gov_status == VERIFIED:
                reasons.append("the government claim matches an official source")
            else:
                reasons.append(f"a government claim on this site was not independently checked ({gov_status})")
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
    rep = getattr(domain_auth, "reputation", None)
    if rep and not rep.get("trusted") and rep.get("reason"):
        reasons.append(f"reputation check: {rep['reason']}")

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


class StoredGov:
    """A stored ``gov_verification`` dict, viewed through the attributes decide() reads.
    Used to re-evaluate stored findings after a registry change (no re-fetching, no new evidence)."""

    class _Claim:
        def __init__(self, data: dict) -> None:
            self.entity_ids = tuple(data.get("entity_ids") or ())
            self.categories = tuple(data.get("categories") or ())
            self.generic_government = bool(data.get("generic_government"))

        @property
        def is_government_claim(self) -> bool:
            return bool(self.categories) and (bool(self.entity_ids) or self.generic_government)

    def __init__(self, data: dict) -> None:
        self.data = dict(data)
        self.status = data.get("status")
        self.coverage = data.get("coverage")
        self.claim = self._Claim(data.get("claim") or {})

    def as_dict(self) -> dict:
        return dict(self.data)


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
