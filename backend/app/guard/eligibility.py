"""Who may be blocked by the Guard. Strict by design — when in doubt, NOT blocked.

Blocked only when ALL hold:
  * the central verdict is FAKE and the engine verdict is MALICIOUS (confirmed), and the central policy
    did not mark it non-blockable (``blockable: false``) — or, only when GUARD_BLOCK_MISLEADING=1,
    MISLEADING with a government claim CONTRADICTED by approved official sources;
  * the analysis was of the LINK itself (URL input, Radar, Sweep, Investigation) — never a message,
    whose text could make an innocent link look bad;
  * the host is a valid DNS name (not an IP literal, not a bare public suffix);
  * it is not: an approved / authenticated / legitimate site, a government zone, a registry
    organisation (any status), a brand-catalogue official domain, a shared platform root
    (github.io, docs.google.com …), or a widely used site (Tranco ranking).
A tenant of a shared platform (evil.github.io) may be blocked EXACTLY (never its platform).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from ..core import homograph
from ..core.rules import rules
from ..intel import psl as psl_mod

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
LINK_INPUTS = ("url", "domain")
LINK_SOURCES = ("radar", "sweep", "investigation", "crt", "feeds", "seed")


@dataclass(frozen=True)
class Decision:
    eligible: bool
    reason: str
    domain: str | None = None
    scope: str = "exact"          # "site" → the registrable site and all its sub-domains
    protected: bool = False       # refused because the domain is protected (registry, official, shared,
                                  # widely used, government zone, legitimate) → also removes an old listing


def normalize_host(raw: str) -> str | None:
    host = str(raw or "").strip().lower().rstrip(".")
    if host.startswith("*."):
        return None
    if "://" in host:
        from urllib.parse import urlsplit
        try:
            host = (urlsplit(host).hostname or "").rstrip(".")
        except ValueError:
            return None
    if not host or "/" in host or ":" in host or "@" in host or " " in host:
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2 or len(host) > 253 or not all(_LABEL.match(lbl) for lbl in labels):
        return None
    if labels[-1].isdigit():
        return None
    return host


def evaluate(item: dict, *, source: str, registry, official_domains, reputation=None,
             include_misleading: bool = False, psl: psl_mod.PublicSuffixList | None = None) -> Decision:
    psl = psl or psl_mod.default()
    tag = str(item.get("tag") or "").upper()
    verdict = str(item.get("verdict") or "").upper()
    if tag == "FAKE":
        if verdict != "MALICIOUS":
            return Decision(False, "FAKE without confirmed malicious evidence")
    elif tag == "MISLEADING" and include_misleading:
        gov = item.get("gov_verification") or {}
        if gov.get("status") != "CONTRADICTED":
            return Decision(False, "MISLEADING without a government claim contradicted by official sources")
    else:
        return Decision(False, f"verdict {tag or 'unknown'} is never blocked")
    if item.get("blockable") is False:
        return Decision(False, "the central verdict marked it not blockable", protected=True)
    auth = item.get("domain_auth") or {}
    if auth.get("authenticated") or auth.get("legitimate_site"):
        return Decision(False, "approved / legitimate site — manual review, never an automatic block", protected=True)
    input_type = str(item.get("input_type") or "")
    if source == "checker" and input_type not in LINK_INPUTS:
        return Decision(False, "only analyses of the link itself are blocked (not message text)")
    raw = item.get("domain") or item.get("host") or (item.get("normalized") or {}).get("host") or ""
    host = normalize_host(raw)
    if host is None:
        return Decision(False, "not a valid DNS name (IP literal, wildcard or invalid host)")
    site = psl.site(host)
    if site is None:
        return Decision(False, f"{host} is a public suffix / platform root", protected=True)
    if host == "www." + site:
        host = site                                   # list the site itself, covering www and others
    zones = tuple(str(z).lower() for z in rules()["government_zones"])
    if any(host == z or host.endswith("." + z) for z in zones):
        return Decision(False, "government zone — handled by the official registry, never blocked", protected=True)
    if registry is not None:
        if registry.entries_for_host(host):
            return Decision(False, "official registry domain", protected=True)
        for entry in registry.entries:
            for d in entry.domains:
                if host == d or host.endswith("." + d) or d.endswith("." + host):
                    return Decision(False, f"belongs to the registry organisation {entry.organization}", protected=True)
    for official in official_domains:
        official = str(official).lower()
        if homograph.is_official_host(host, official) or official.endswith("." + host):
            return Decision(False, f"official domain of a catalogued brand ({official})", protected=True)
    if reputation is not None:
        if reputation.shared_platform(host) or reputation.shared_platform(site):
            return Decision(False, "shared platform — only exact URLs are listed, never the host", protected=True)
        try:
            if reputation.lookup(host).trusted:
                return Decision(False, "widely used website — never blocked domain-wide", protected=True)
        except Exception:  # noqa: BLE001 — reputation unavailable: no effect
            pass
    scope = "site" if host == site and not psl.platform(host) else "exact"
    return Decision(True, "confirmed malicious", host, scope)
