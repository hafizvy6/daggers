"""Signals from the inspected page (markup facts) and from threat feeds.

Signals carry an evidence GROUP. Several signals derived from the same underlying observation
(the same form, the same feed listing, the same host string) share a group, and the engine counts
only the strongest signal of a group — they are not independent confirmation.

Groups: ``form`` (one credential/payment form), ``page_identity`` (who the page says it is),
``script`` (inline script analysis), ``feeds`` (threat-feed listing), ``redirect``.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from . import psl as psl_mod
from .hostname import HostSignal
from .probe import ProbeResult

PROVIDERS_FILE = Path(__file__).with_name("providers.yaml")
_PROVIDERS: tuple[frozenset[str], frozenset[str]] | None = None


def providers() -> tuple[frozenset[str], frozenset[str]]:
    global _PROVIDERS
    if _PROVIDERS is None:
        data = yaml.safe_load(PROVIDERS_FILE.read_text(encoding="utf-8")) or {}
        _PROVIDERS = (frozenset(d.lower() for d in data.get("identity") or []),
                      frozenset(d.lower() for d in data.get("payment") or []))
    return _PROVIDERS


def _under(host: str, domains: frozenset[str]) -> str | None:
    for d in domains:
        if host == d or host.endswith("." + d):
            return d
    return None


def known_provider(host: str | None) -> str | None:
    if not host:
        return None
    ident, pay = providers()
    return _under(host, ident) or _under(host, pay)


def same_site(a: str | None, b: str | None, psl: psl_mod.PublicSuffixList) -> bool:
    if not a or not b:
        return False
    return (psl.site(a) or a) == (psl.site(b) or b)


def claimed_government(text: str, registry) -> list:
    """Registry GOVERNMENT bodies (class A/B) the page names in its title / visible text."""
    try:
        entities = registry.resolve_entities(text)
    except Exception:  # noqa: BLE001
        return []
    return [e for e in entities if e.source_class in ("A", "B")]


def page_signals(probe: ProbeResult, *, host_authenticated: bool, registry, brands=(),
                 psl: psl_mod.PublicSuffixList | None = None) -> list[HostSignal]:
    """Signals from the inspected page. `host_authenticated`: the FINAL host is an approved
    registry domain (its own forms are expected and are not 'impersonation')."""
    psl = psl or psl_mod.default()
    facts = probe.facts
    if facts is None:
        return []
    out: list[HostSignal] = []
    page_host = probe.final_host or probe.original_host
    identity_text = f"{facts.title}\n{facts.text_excerpt[:2000]}"
    gov = [] if host_authenticated else claimed_government(identity_text, registry)
    brand_names = []
    if not host_authenticated:
        low = identity_text.lower()
        for brand in brands:
            token = str(brand.get("token") or "").lower()
            official = str(brand.get("official_domain") or "").lower()
            if len(token) >= 4 and token in low and not (page_host == official or page_host.endswith("." + official)):
                brand_names.append(str(brand.get("name") or token))

    sensitive = [f for f in facts.forms if f.password or f.otp or f.card or f.iban or f.identity]
    offsite = []
    for form in sensitive:
        dest = form.action_host
        if dest and same_site(dest, page_host, psl):
            continue
        provider = known_provider(dest)
        if provider:
            continue                       # SSO / hosted checkout — normal, not a mismatch
        offsite.append(form)

    if sensitive and not host_authenticated:
        kinds = sorted({k for f in sensitive for k in ("password", "otp", "card", "iban", "identity") if getattr(f, k)})
        if any(f.card or f.iban for f in sensitive):
            out.append(HostSignal("content.payment_harvest_fields", 0.25,
                                  f"page asks for payment details ({', '.join(kinds)})", "form"))
        else:
            out.append(HostSignal("content.credential_form", 0.15,
                                  f"page has a sign-in / verification form ({', '.join(kinds)})", "form"))
    if offsite and not host_authenticated:
        dests = sorted({f.action_host or "an unknown (script-controlled) destination" for f in offsite})
        out.append(HostSignal("content.form_action_mismatch", 0.30,
                              f"sensitive form sends data to {', '.join(dests[:2])}, not to this site", "form"))
    # The decisive COMBINATION: claims to be a government body + not that body's approved host +
    # collects credentials / payment / identity data.
    if gov and sensitive:
        names = ", ".join(sorted({e.organization for e in gov})[:2])
        out.append(HostSignal("content.gov_identity_credential_harvest", 0.75,
                              f"page presents itself as {names} but is not an approved {names} domain, and it "
                              "collects sign-in / payment / identity data", "form"))
    elif gov:
        names = ", ".join(sorted({e.organization for e in gov})[:2])
        out.append(HostSignal("content.claims_government_identity", 0.20,
                              f"page names {names} but is not an approved domain of it", "page_identity"))
    elif brand_names and sensitive:
        out.append(HostSignal("content.brand_identity_credential_form", 0.45,
                              f"page uses the name {brand_names[0]} and collects sign-in / payment data on a "
                              "domain that is not that organisation's", "form"))
    if facts.obfuscated_script:
        out.append(HostSignal("content.obfuscated_script", 0.15, "obfuscated / packed script in the page", "script"))
    return out


def redirect_signals(probe: ProbeResult, psl: psl_mod.PublicSuffixList | None = None) -> list[HostSignal]:
    psl = psl or psl_mod.default()
    out: list[HostSignal] = []
    if probe.error_code == "private_address" and len(probe.hops) >= 1:
        out.append(HostSignal("infra.redirect_to_private_network", 0.40,
                              "the link redirects to a private / internal network address", "redirect"))
    sites = [psl.site(h.url_host) or h.url_host for h in probe.hops]
    if len(set(sites)) >= 3:
        out.append(HostSignal("infra.redirect_chain", 0.10,
                              f"redirect chain through {len(set(sites))} different sites", "redirect"))
    return out


def feed_signals(hit: dict | None, *, host_is_shared: bool) -> list[HostSignal]:
    """`hit`: FeedIndex.lookup result. URL listing = confirmed bad URL. Host listing = the host has
    carried confirmed bad URLs — not applied to shared platforms / reputable hosts (others' content)."""
    if not hit:
        return []
    if hit.get("url_listed"):
        return [HostSignal("feeds.phishtank_confirmed", 0.70,
                           f"this exact URL is listed in a phishing / malware feed ({', '.join(hit.get('sources') or [])})",
                           "feeds")]
    if hit.get("host_listed") and not host_is_shared:
        return [HostSignal("feeds.host_listed", 0.40,
                           f"other URLs on this host are listed in a phishing / malware feed "
                           f"({', '.join(hit.get('sources') or [])})", "feeds")]
    return []
