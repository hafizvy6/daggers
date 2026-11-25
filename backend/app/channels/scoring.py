"""Shared-scorer integration for every WS2 surface.

There is exactly one scoring engine: WS1's ``core.scorer``. This module calls it
in-process, then applies the WS2 trust policy (registry authentication +
official claim verification). Search, Maps, Sweep, ``POST /api/scan`` and the
live Checker (``POST /api/check``) all go through ``ShieldScorer``.
"""
from __future__ import annotations

import re

from dataclasses import replace
from datetime import datetime
from typing import Callable, Iterable, Mapping

from ..catalog import Catalog, load_catalogs
from ..core import claims as ws1_claims
from ..core import message as ws1_message
from ..core import scorer as ws1_scorer
from . import trust_policy
from .official import POLICY_VERSION
from .official.extract import Lexicon, extract_claim
from .official.models import (
    AUTH_NOT_CHECKABLE,
    AUTH_ESTABLISHED_SITE,
    AUTH_PENDING,
    AUTH_REPUTABLE_SITE,
    AUTH_UNLISTED,
    DomainAuthentication,
    GovVerification,
    OfficialRecord,
    RegistryEntry,
    utc_now,
)
from .official.registry import Registry
from . import established
from .reputation import Reputation
from ..core.rules import rules as _rules

# Government zones are authenticated ONLY through the official registry (exact host or listed
# sub-domain). Popularity never makes a government host SAFE.
GOVERNMENT_ZONES = tuple(str(z).lower() for z in _rules()["government_zones"])   # data: core/rules.yaml
from .official.verify import select_sources, verify_claim

DOMAIN_NAME_SIGNAL_PREFIXES = ("lexical.", "identity.", "homograph.")
MONEY = re.compile(r"(?:\b(?:aed|dhs?|dirhams?)\s*\d)|(?:\d[\d,.]*\s*(?:aed|dhs?|dirhams?|million)\b)|(?:درهم|مليون)", re.I)
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
        reputation: Reputation | None = None,
    ) -> None:
        self.catalog = catalog or load_catalogs()
        self.registry = registry or Registry.load()
        self.lexicon = lexicon or Lexicon.load()
        self.record_provider = record_provider or no_records
        self.thresholds = dict(thresholds or {})
        self.clock = clock
        self.reputation = reputation          # None → reputation path disabled (registry only)
        self.gatherer = None                  # intel.evidence.EvidenceGatherer (live lookups), set by the runtime

    # ------------------------------------------------------------ evidence (intel layer)

    def _host(self, url: str) -> str:
        norm = ws1_scorer.normalize_url(url, self.catalog.suffix_resolver)
        return str(norm.punycode_host or norm.host or "")

    def host_trusted(self, host: str) -> bool:
        auth = self.authenticate(f"https://{host}/", self.clock())
        return auth.authenticated or auth.legitimate_site

    def host_is_shared(self, host: str) -> bool:
        """Hosts whose content is not all the operator's own (shared platforms), plus widely used and
        registry hosts: a host-level feed listing is not applied to them — only exact-URL listings."""
        if self._registry_organisation(host):
            return True
        if self.reputation is not None:
            if self.reputation.shared_platform(host):
                return True
            if self.reputation.lookup(host, self.clock()).trusted:
                return True
        return False

    def offline_signals(self, url: str) -> list[dict]:
        """Pure host checks (no network): obfuscated hosts, deceptive sub-domains, registry look-alikes."""
        from ..intel import hostname
        out = [s.as_context() for s in hostname.obfuscation_signals(url)]
        host = self._host(url)
        if host:
            out += [s.as_context() for s in hostname.identity_signals(host, self.registry)]
        return out

    def evidence_context(self, url: str, *, live: bool) -> tuple[dict, object | None]:
        """→ (scorer context, LiveEvidence | None). Live lookups only when asked AND configured."""
        ctx: dict = {"extra_signals": self.offline_signals(url)}
        ev = None
        if live and self.gatherer is not None:
            host = self._host(url)
            if host:
                ev = self.gatherer.gather(url, host, registry=self.registry, brands=self.catalog.brands,
                                          host_authenticated=self.host_trusted, host_is_shared=self.host_is_shared)
                live_ctx = ev.context()
                ctx["extra_signals"] = ctx["extra_signals"] + live_ctx.get("extra_signals", [])
                if "domain_age_days" in live_ctx:
                    ctx["domain_age_days"] = live_ctx["domain_age_days"]
        return ctx, ev

    def established_auth(self, auth: DomainAuthentication, live: Mapping | None, signals: list[dict],
                         ws1_verdict: str, content_flags, now: datetime) -> DomainAuthentication:
        """Established-website path (channels/established.py; thresholds in core/rules.yaml). Only for
        hosts that are not already SAFE-capable: unlisted, or a PENDING company/news entry. Never for
        government zones, government registry organisations or shared platforms."""
        pending_private = auth.status == AUTH_PENDING and auth.source_class in ("C", "P")
        if not auth.host or not (auth.status == AUTH_UNLISTED or pending_private):
            return auth
        host = auth.host
        if any(host == z or host.endswith("." + z) for z in GOVERNMENT_ZONES):
            return auth
        if not pending_private and self._registry_organisation(host):
            return auth
        from ..intel import psl as psl_mod
        if psl_mod.default().platform(host) or (self.reputation is not None and self.reputation.shared_platform(host)):
            return auth
        facts, why = established.evaluate(dict(live or {}), signals, ws1_verdict, content_flags, host=host)
        if facts is None:
            return replace(auth, established={"status": "not_established", "reason": why})
        site = psl_mod.default().site(host) or host
        reason = why + (f" (registry entry for {auth.organization} is pending review)" if pending_private else "")
        return DomainAuthentication(AUTH_ESTABLISHED_SITE, host, auth.entry_id if pending_private else None,
                                    auth.organization if pending_private else site, "E", reason,
                                    self.registry.version, established={"status": "established", **facts})

    def final_auth(self, auth: DomainAuthentication, final_host: str | None, now: datetime) -> DomainAuthentication | None:
        if not final_host or final_host == auth.host:
            return None
        return self.authenticate(f"https://{final_host}/", now)

    def evidence_records(self, auth: DomainAuthentication, gov, ev, now: datetime) -> list[dict]:
        """What was checked, by which source, when — with freshness. Shown in Checker + Portal."""
        records: list[dict] = [{
            "id": "registry", "source": "official source registry", "status": auth.status,
            "checked_at": iso_now(now), "version": self.registry.version,
            "approved_at": auth.verified_at, "expires_at": auth.expires_at,
            "summary": auth.reason,
        }]
        if self.reputation is not None and auth.status not in ("AUTHENTICATED", "INDEPENDENT_MEDIA",
                                                                "VERIFIED_ORGANIZATION", "PENDING", "REVOKED", "EXPIRED"):
            rep = auth.reputation or {}
            st = self.reputation.status(now)
            records.append({"id": "reputation", "source": "Tranco top-sites list",
                            "status": rep.get("status") or ("not_used" if not rep else None),
                            "checked_at": iso_now(now), "data_updated_at": st.get("retrieved_at"),
                            "stale": st.get("stale"), "summary": rep.get("reason") or
                            "not used for government zones or registry organisations"})
        if ev is not None:
            records.extend(ev.records)
        if gov is not None:
            g = gov.as_dict()
            decisive = [e for e in g.get("evidence") or [] if e.get("role") == "decisive"]
            records.append({"id": "claim_verification", "source": "approved official sources",
                            "status": g.get("status"), "checked_at": g.get("verified_at"),
                            "checked": g.get("checked_sources"), "not_checked": g.get("unchecked_sources"),
                            "decided_by": [{"entry_id": e.get("entry_id"), "source_class": e.get("source_class"),
                                            "retrieved_at": e.get("retrieved_at"), "comparison": e.get("comparison")}
                                           for e in decisive],
                            "summary": "; ".join(g.get("notes") or [])[:400]})
        return records

    @property
    def reputation_version(self) -> str:
        return self.reputation.version if self.reputation is not None else "rep_off"

    def _registry_organisation(self, host: str) -> bool:
        """The host belongs to a registry organisation (any status): the registry alone decides it."""
        return any(host == d or host.endswith("." + d) for e in self.registry.entries for d in e.domains)

    def authenticate(self, target: str, now: datetime) -> DomainAuthentication:
        """Registry authentication, then — only for hosts the registry does not know — the
        independent reputation check (widely used, non-government, not a shared platform)."""
        auth = self.registry.authenticate(target, now)
        if self.reputation is None or not auth.host:
            return auth
        # A PENDING company / news entry (class P / C) is "not reviewed yet", not a negative finding:
        # the independent popularity path still applies. Government entries (A/B), revoked and expired
        # entries, and unlisted sub-domains of registry organisations are decided by the registry alone.
        pending_private = auth.status == AUTH_PENDING and auth.source_class in ("C", "P")
        if auth.status != AUTH_UNLISTED and not pending_private:
            return auth
        host = auth.host
        if not pending_private and self._registry_organisation(host):
            return auth
        if any(host == z or host.endswith("." + z) for z in GOVERNMENT_ZONES):
            return replace(auth, reason="government domain that is not in the official registry — "
                                        "government sites are authenticated only through the registry")
        rep = self.reputation.lookup(host, now)
        if not rep.trusted:
            return replace(auth, reputation=rep.as_dict())
        reason = rep.reason + (f" (registry entry for {auth.organization} is pending review)" if pending_private else "")
        return DomainAuthentication(AUTH_REPUTABLE_SITE, host, auth.entry_id if pending_private else None,
                                    auth.organization if pending_private else rep.domain, "R", reason,
                                    self.registry.version, reputation=rep.as_dict())

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
        """Suspicious CONTENT on an approved site (the engine trusts approved names, not content):
        prize / giveaway offers, requests for codes or card details, payment demands."""
        if not text:
            return ()
        flags: list[str] = []
        signal = ws1_claims.evaluate_claims(
            text, "", list(self.catalog.brands), self.catalog.official_domains
        )
        if signal:
            flags.append(signal.reason)
        if ws1_scorer.GIVEAWAY_WORDS.search(text) and MONEY.search(text):
            flags.append("prize / giveaway offer with a money amount in the page content")
        for sig in ws1_message.analyze_message(text, [], self.catalog.brands):
            if sig.name in ("message.credential_request", "message.payment_demand"):
                flags.append(sig.reason)
        return tuple(dict.fromkeys(flags))

    # ------------------------------------------------------------ public API

    def assess_url(
        self,
        url: str,
        *,
        text: str | None = None,
        context: Mapping[str, object] | None = None,
        live: bool = False,
    ) -> dict:
        """Score one URL (+ optional title/snippet/page text) and apply the trust policy.
        `live`: run live lookups (RDAP, page retrieval, feeds) — investigations; Sweep stays offline."""
        now = self.clock()
        ev_ctx, ev = self.evidence_context(url, live=live)
        merged = {**(context or {}), **ev_ctx,
                  "extra_signals": list((context or {}).get("extra_signals") or []) + ev_ctx["extra_signals"]}
        ws1 = ws1_scorer.score_url(
            url,
            **self.catalog.scoring_kwargs(),
            context=merged,
            text=f"{url} {text}" if text else None,
            thresholds=self.thresholds or None,
        )
        auth = self.authenticate(url, now)
        gov = self.verify_text(text, now)
        if ev is not None:
            auth = self.established_auth(auth, ev.summary(), [dict(s) for s in ws1.signals], ws1.verdict,
                                         self._content_flags(text), now)
        flags = self._content_flags(text) if (auth.authenticated or auth.legitimate_site) else ()
        decision = trust_policy.decide(
            auth,
            trust_policy.Maliciousness(
                ws1.verdict, ws1.score, tuple(ws1.reasons), flags, domain_name_only(ws1.signals)
            ),
            gov,
            self.final_auth(auth, ev.final_host if ev else None, now),
        )
        return {
            "url": url,
            "evidence": self.evidence_records(auth, gov, ev, now),
            "live_evidence": ev.summary() if ev else None,
            "verdict": ws1.verdict,
            "score": ws1.score,
            "reasons": list(ws1.reasons),
            "scam_type": ws1.scam_type,
            "registrable_domain": ws1.normalized.get("registrable_domain"),
            "host": ws1.normalized.get("unicode_host"),
            "signals": [dict(sig) for sig in ws1.signals],
            **self._policy_fields(decision),
        }

    def tag_finding(self, finding: dict) -> dict:
        """Apply the trust policy to a stored finding that has no tag yet (radar, seed, legacy rows).

        Uses the finding's own WS1 verdict/score/reasons plus registry authentication of its
        domain. Never upgrades to SAFE without authentication; never invents verification.
        """
        if finding.get("tag"):
            return finding
        now = self.clock()
        auth = self.authenticate(f"https://{finding.get('domain') or ''}/", now)
        decision = trust_policy.decide(
            auth,
            trust_policy.Maliciousness(
                str(finding.get("verdict") or "UNKNOWN"),
                float(finding.get("score") or 0.0),
                tuple(finding.get("reasons") or ()),
            ),
            None,
        )
        out = dict(finding)
        out.update({
            "tag": decision.tag,
            "manual_review": decision.manual_review,
            "domain_auth": decision.domain_auth.as_dict(),
            "trust_reasons": list(decision.reasons),
            "policy_version": POLICY_VERSION,
            "reputation_version": self.reputation_version,
        })
        out.setdefault("gov_verification", None)
        return out

    def retag(self, finding: dict) -> dict | None:
        """Re-evaluate a STORED, already-tagged finding against the CURRENT registry/policy.

        Uses only the finding's own stored evidence (engine verdict, score, reasons, signals,
        content flags, stored claim verification) — nothing is re-fetched or invented. Returns
        the new policy fields when the result differs from what is stored, else None.
        """
        stored_auth = finding.get("domain_auth") or {}
        if (stored_auth.get("registry_version") == self.registry.version
                and finding.get("policy_version") == POLICY_VERSION
                and finding.get("reputation_version") == self.reputation_version):
            return None
        target = (finding.get("analyzed_url") or finding.get("submitted_url") or finding.get("normalized_url")
                  or (f"https://{finding['domain']}/" if finding.get("domain") else ""))
        now = self.clock()
        if target:
            auth = self.authenticate(target, now)
        else:
            auth = DomainAuthentication(AUTH_NOT_CHECKABLE, "", reason="message contains no link to authenticate",
                                        registry_version=self.registry.version)
        stored_flags = tuple((finding.get("maliciousness") or {}).get("content_flags") or ())
        if finding.get("live_evidence") and target:
            auth = self.established_auth(auth, finding["live_evidence"], list(finding.get("signals") or []),
                                         str(finding.get("verdict") or "UNKNOWN"), stored_flags, now)
        gov = trust_policy.StoredGov(finding["gov_verification"]) if finding.get("gov_verification") else None
        page = ((finding.get("live_evidence") or {}).get("page") or {})
        final = self.final_auth(auth, page.get("final_host"), now) if page.get("final_host") else None
        decision = trust_policy.decide(
            auth,
            trust_policy.Maliciousness(
                str(finding.get("verdict") or "UNKNOWN"), float(finding.get("score") or 0.0),
                tuple(finding.get("reasons") or ()), stored_flags,
                domain_name_only(list(finding.get("signals") or [])),
            ),
            gov,
            final,
        )
        return self._policy_fields(decision)

    def apply_to_scan_result(self, result: dict, *, kind: str, input_value: str,
                             live_evidence: Mapping[str, object] | None = None) -> dict:
        """Add tag / domain_auth / gov_verification to a WS1 ScanResult (additive only).

        The WS1 fields (verdict, score, reasons, …) are never modified.
        """
        now = self.clock()
        maliciousness = trust_policy.Maliciousness(
            str(result.get("verdict", "UNKNOWN")),
            float(result.get("score", 0.0) or 0.0),
            tuple(result.get("reasons") or ()),
        )
        if kind == "url":
            target, text = input_value, None
        else:
            # Authenticate the link the engine judged riskiest (the one that drives the verdict).
            urls = ws1_scorer.extract_urls(input_value)
            target = str(result.get("analyzed_url") or (urls[0] if urls else ""))
            text = input_value
        name_only = False
        if target:
            auth = self.authenticate(target, now)
            if auth.authenticated or auth.legitimate_site:
                # EVERY signal of the analysis counts (URL, claims AND message content): a phishing
                # message that links to a genuine site is not "domain-name heuristics only".
                all_signals = result.get("signals")
                if all_signals is None:
                    all_signals = ws1_scorer.score_url(target, **self.catalog.scoring_kwargs(), text=text,
                                                       thresholds=self.thresholds or None).signals
                name_only = domain_name_only(list(all_signals))
        else:
            auth = DomainAuthentication(AUTH_NOT_CHECKABLE, "", reason="message contains no link to authenticate",
                                        registry_version=self.registry.version)
        gov = self.verify_text(text, now)
        ev = (live_evidence or {}).get(target) if target else None
        if ev is not None:
            auth = self.established_auth(auth, ev.summary(), list(result.get("signals") or []),
                                         maliciousness.ws1_verdict, self._content_flags(text), now)
        flags = self._content_flags(text) if (auth.authenticated or auth.legitimate_site) else ()
        maliciousness = trust_policy.Maliciousness(
            maliciousness.ws1_verdict, maliciousness.ws1_score, maliciousness.reasons, flags, name_only
        )
        decision = trust_policy.decide(auth, maliciousness, gov,
                                       self.final_auth(auth, getattr(ev, "final_host", None), now) if ev else None)
        return {**result, **self._policy_fields(decision),
                "evidence": self.evidence_records(auth, gov, ev, now),
                "live_evidence": ev.summary() if ev is not None else None}

    def _policy_fields(self, decision: trust_policy.TrustDecision) -> dict:
        return {
            "reputation_version": self.reputation_version,
            "maliciousness": decision.maliciousness.as_dict(),
            "tag": decision.tag,
            "manual_review": decision.manual_review,
            "domain_auth": decision.domain_auth.as_dict(),
            "gov_verification": decision.gov_verification.as_dict() if decision.gov_verification else None,
            "trust_reasons": list(decision.reasons),
            "blockable": decision.blockable,
            "policy_version": POLICY_VERSION,
            "reason_codes": decision.reason_codes,
            "final_domain_auth": decision.final_auth.as_dict() if decision.final_auth else None,
        }


def iso_now(now: datetime) -> str:
    return now.replace(microsecond=0).isoformat().replace("+00:00", "Z")


_DEFAULT: ShieldScorer | None = None


def default_scorer() -> ShieldScorer:
    """Process-wide scorer (lazy). Registry/lexicon load failures propagate loudly."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = ShieldScorer()
    return _DEFAULT
