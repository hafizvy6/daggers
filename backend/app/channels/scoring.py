"""Shared-scorer integration for every WS2 surface.

There is exactly one scoring engine: WS1's ``core.scorer``. This module calls it
in-process, then applies the WS2 trust policy (registry authentication +
official claim verification). Search, Maps, Sweep and — once WS1 merges the
integration patch — ``POST /api/scan`` all go through ``ShieldScorer``.
"""
from __future__ import annotations

from datetime import datetime
from typing import Callable, Iterable, Mapping

from ..catalog import Catalog, load_catalogs
from ..core import claims as ws1_claims
from ..core import scorer as ws1_scorer
from . import trust_policy
from .official import POLICY_VERSION
from .official.extract import Lexicon, extract_claim
from .official.models import (
    AUTH_NOT_CHECKABLE,
    DomainAuthentication,
    GovVerification,
    OfficialRecord,
    RegistryEntry,
    utc_now,
)
from .official.registry import Registry
from .official.verify import select_sources, verify_claim

DOMAIN_NAME_SIGNAL_PREFIXES = ("lexical.", "identity.", "homograph.")
RecordProvider = Callable[[list[RegistryEntry]], Iterable[OfficialRecord]]


def domain_name_only(signals: list[dict]) -> bool:
    """True when every WS1 signal is about the URL/domain string itself (not content/infra/feeds)."""
    return bool(signals) and all(str(s.get("name", "")).startswith(DOMAIN_NAME_SIGNAL_PREFIXES) for s in signals)


def no_records(_entries: list[RegistryEntry]) -> list[OfficialRecord]:
    """Default provider: nothing pre-fetched → sources are honestly 'not checked'."""
    return []


class ShieldScorer:
    def __init__(
        self,
        *,
        catalog: Catalog | None = None,
        registry: Registry | None = None,
        lexicon: Lexicon | None = None,
        record_provider: RecordProvider | None = None,
        thresholds: Mapping[str, float] | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.catalog = catalog or load_catalogs()
        self.registry = registry or Registry.load()
        self.lexicon = lexicon or Lexicon.load()
        self.record_provider = record_provider or no_records
        self.thresholds = dict(thresholds or {})
        self.clock = clock

    # ------------------------------------------------------------ building blocks

    def verify_text(self, text: str | None, now: datetime) -> GovVerification | None:
        if not text or not text.strip():
            return None
        claim = extract_claim(text, self.registry, self.lexicon)
        if not claim.is_government_claim:
            return None
        sources, _ = select_sources(claim, self.registry, now)
        records = list(self.record_provider(sources)) if sources else []
        return verify_claim(claim, registry=self.registry, lexicon=self.lexicon, records=records, now=now)

    def _content_flags(self, text: str | None) -> tuple[str, ...]:
        """Examine content even on official hosts (WS1 skips official hosts entirely)."""
        if not text:
            return ()
        signal = ws1_claims.evaluate_claims(
            text, "", list(self.catalog.brands), self.catalog.official_domains
        )
        return (signal.reason,) if signal else ()

    # ------------------------------------------------------------ public API

    def assess_url(
        self,
        url: str,
        *,
        text: str | None = None,
        context: Mapping[str, object] | None = None,
    ) -> dict:
        """Score one URL (+ optional title/snippet/page text) and apply the trust policy."""
        now = self.clock()
        ws1 = ws1_scorer.score_url(
            url,
            **self.catalog.scoring_kwargs(),
            context=context,
            text=f"{url} {text}" if text else None,
            thresholds=self.thresholds or None,
        )
        auth = self.registry.authenticate(url, now)
        gov = self.verify_text(text, now)
        flags = self._content_flags(text) if auth.authenticated else ()
        decision = trust_policy.decide(
            auth,
            trust_policy.Maliciousness(
                ws1.verdict, ws1.score, tuple(ws1.reasons), flags, domain_name_only(ws1.signals)
            ),
            gov,
        )
        return {
            "url": url,
            "verdict": ws1.verdict,
            "score": ws1.score,
            "reasons": list(ws1.reasons),
            "scam_type": ws1.scam_type,
            "registrable_domain": ws1.normalized.get("registrable_domain"),
            **self._policy_fields(decision),
        }

    def apply_to_scan_result(self, result: dict, *, kind: str, input_value: str) -> dict:
        """Add tag / domain_auth / gov_verification to a WS1 ScanResult (additive only).

        The WS1 fields (verdict, score, reasons, …) are never modified.
        """
        now = self.clock()
        maliciousness = trust_policy.Maliciousness(
            str(result.get("verdict", "UNKNOWN")),
            float(result.get("score", 0.0) or 0.0),
            tuple(result.get("reasons") or ()),
        )
        if kind == "number":
            auth = DomainAuthentication(AUTH_NOT_CHECKABLE, "", reason="phone numbers have no domain to authenticate",
                                        registry_version=self.registry.version)
            tag = trust_policy.ws1_verdict_to_tag_without_auth(maliciousness.ws1_verdict)
            reasons = ["a phone number cannot be authenticated as official; no SAFE label is given"]
            decision = trust_policy.TrustDecision(tag, False, auth, None, maliciousness, tuple(reasons))
            return {**result, **self._policy_fields(decision)}

        if kind == "url":
            target, text = input_value, None
        else:
            urls = ws1_scorer.extract_urls(input_value)
            target, text = (urls[0] if urls else ""), input_value
        name_only = False
        if target:
            auth = self.registry.authenticate(target, now)
            if auth.authenticated:
                # Re-derive WS1 signal names (pure, cheap) to separate name heuristics from content.
                probe = ws1_scorer.score_url(target, **self.catalog.scoring_kwargs(), text=text,
                                             thresholds=self.thresholds or None)
                name_only = domain_name_only(probe.signals)
        else:
            auth = DomainAuthentication(AUTH_NOT_CHECKABLE, "", reason="message contains no link to authenticate",
                                        registry_version=self.registry.version)
        gov = self.verify_text(text, now)
        flags = self._content_flags(text) if auth.authenticated else ()
        maliciousness = trust_policy.Maliciousness(
            maliciousness.ws1_verdict, maliciousness.ws1_score, maliciousness.reasons, flags, name_only
        )
        decision = trust_policy.decide(auth, maliciousness, gov)
        return {**result, **self._policy_fields(decision)}

    @staticmethod
    def _policy_fields(decision: trust_policy.TrustDecision) -> dict:
        return {
            "tag": decision.tag,
            "manual_review": decision.manual_review,
            "domain_auth": decision.domain_auth.as_dict(),
            "gov_verification": decision.gov_verification.as_dict() if decision.gov_verification else None,
            "trust_reasons": list(decision.reasons),
            "blockable": decision.blockable,
            "policy_version": POLICY_VERSION,
        }


_DEFAULT: ShieldScorer | None = None


def default_scorer() -> ShieldScorer:
    """Process-wide scorer (lazy). Registry/lexicon load failures propagate loudly."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = ShieldScorer()
    return _DEFAULT
