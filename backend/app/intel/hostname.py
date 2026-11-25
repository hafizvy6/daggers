"""Strict hostname normalisation and identity checks that complement ``core.scorer``.

* Obfuscated hosts: numeric / hex / octal IPv4 forms, percent-encoding, invisible characters.
* Deceptive sub-domains: an official domain written into the LEFT part of an unrelated domain
  (``icp.gov.ae.verify-id.com``, ``icp-gov-ae.secure.top``).
* Look-alikes of REGISTRY organisations (the core engine covers the brand catalogue).

Internationalised names are NOT suspicious by themselves: a fully Arabic (or any single-script)
domain produces no signal here. Only confusable mixing is handled (by ``core.homograph``).
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..core import homograph
from ..core.rules import rules as _rules
from ..core.scorer import levenshtein
from . import psl as psl_mod

# Common words (not an organisation's distinctive name) — data: core/rules.yaml
GENERIC_LABELS = frozenset(str(w).lower() for w in _rules()["generic_labels"])

_HEX_OCT_PART = re.compile(r"^(0x[0-9a-f]+|0[0-7]+|\d+)$", re.I)


@dataclass(frozen=True)
class HostSignal:
    name: str
    weight: float
    reason: str
    group: str

    def as_context(self) -> dict:
        return {"name": self.name, "weight": self.weight, "reason": self.reason, "group": self.group}


def raw_host(url: str) -> str:
    """The host exactly as written (no IDNA decoding, no percent decoding)."""
    value = url.strip()
    if "://" not in value:
        value = "https://" + value
    netloc = urlsplit(value).netloc
    netloc = netloc.rsplit("@", 1)[-1]
    if netloc.startswith("["):
        return netloc.split("]")[0] + "]"
    return netloc.split(":")[0]


def numeric_ip(host: str) -> str | None:
    """'2130706433', '0x7f000001', '0177.0.0.1', '127.1' → the IPv4 address they resolve to."""
    host = host.strip(".").lower()
    if not host or not all(_HEX_OCT_PART.match(p) for p in host.split(".")):
        return None
    try:
        ipaddress.ip_address(host)
        return None                      # a normal dotted IPv4: handled by the engine (lexical.ip_host)
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) > 4:
        return None
    try:
        nums = [int(p, 16) if p.startswith("0x") else int(p, 8) if len(p) > 1 and p.startswith("0") else int(p)
                for p in parts]
    except ValueError:
        return None
    # inet_aton semantics: the last part fills the remaining bytes
    value = 0
    for n in nums[:-1]:
        if n > 255:
            return None
        value = (value << 8) | n
    rest_bytes = 4 - (len(nums) - 1)
    if nums[-1] >= 1 << (8 * rest_bytes):
        return None
    value = (value << (8 * rest_bytes)) | nums[-1]
    return str(ipaddress.IPv4Address(value))


def obfuscation_signals(url: str) -> list[HostSignal]:
    host = raw_host(url)
    out: list[HostSignal] = []
    ip = numeric_ip(host)
    if ip:
        out.append(HostSignal("lexical.obfuscated_ip_host", 0.45,
                              f"host '{host}' is an encoded IP address ({ip})", "host_form"))
    if "%" in host:
        out.append(HostSignal("lexical.percent_encoded_host", 0.40, "percent-encoded characters in the host name",
                              "host_form"))
    invisible = [ch for ch in host if unicodedata.category(ch) in ("Cf", "Zs", "Zl", "Zp")]
    if invisible:
        out.append(HostSignal("lexical.invisible_chars_host", 0.45,
                              "invisible / zero-width characters in the host name", "host_form"))
    return out


def official_domains(registry) -> list[tuple[str, str, str]]:
    """(domain, organisation, class) for every registry entry (any status: impersonating a
    pending entry is still impersonation)."""
    out = []
    for entry in getattr(registry, "entries", ()):
        for domain in entry.domains:
            out.append((domain.lower(), entry.organization, entry.source_class))
    return out


def identity_signals(host: str, registry, psl: psl_mod.PublicSuffixList | None = None) -> list[HostSignal]:
    """Deceptive sub-domain / look-alike of a registry organisation. `host` = normalised host."""
    psl = psl or psl_mod.default()
    forms = homograph.host_forms(host)
    ascii_host = str(forms["punycode_host"])
    site = psl.site(ascii_host) or ascii_host
    left = ascii_host[: -len(site)].rstrip(".") if ascii_host.endswith(site) and ascii_host != site else ""
    out: list[HostSignal] = []
    for domain, org, cls in official_domains(registry):
        if ascii_host == domain or ascii_host.endswith("." + domain):
            return []                                    # the genuine domain (or its sub-domain)
    folded_host = homograph.confusable_fold(ascii_host)
    folded_left = homograph.confusable_fold(left)
    host_flat = re.sub(r"[^0-9a-z]+", "", folded_host)
    labels = [homograph.confusable_fold(lbl) for lbl in ascii_host.split(".")[:-1]]
    gov = {"A": "government", "B": "official media"}
    for domain, org, cls in official_domains(registry):
        kind = gov.get(cls, "organisation")
        flat = re.sub(r"[^0-9a-z]+", "", domain)
        strong = cls in ("A", "B")
        # 1) the official domain spelled out inside an unrelated host
        #    (icp.gov.ae.verify-id.com, login.uaepass.ae-verify.com, tamm-abudhabi.com)
        if (left and ("." + domain + ".") in ("." + folded_left + ".")) or (len(flat) >= 8 and flat in host_flat):
            out.append(HostSignal("identity.deceptive_subdomain", 0.65 if strong else 0.55,
                                  f"'{domain}' ({org}, {kind}) is written into the unrelated domain {site}",
                                  "identity_host"))
            break
        # 2) look-alike of the organisation's domain label (edit distance 1, label ≥ 5)
        label = domain.split(".")[0]
        if len(label) >= 5 and any(lbl != label and levenshtein(lbl, label) == 1 for lbl in labels):
            out.append(HostSignal("identity.registry_lookalike", 0.55 if strong else 0.45,
                                  f"'{ascii_host}' differs by one character from {domain} ({org}, {kind})",
                                  "identity_host"))
            break
        # 3) the organisation's distinctive name reused on another domain (mohre.org, emiratesnbd-rewards.com)
        segments = {seg for lbl in labels for seg in re.split(r"[^0-9a-z]+", lbl) if seg} | set(labels)
        if len(label) >= 5 and label not in GENERIC_LABELS and label in segments:
            out.append(HostSignal("identity.registry_name_reuse", 0.40 if strong else 0.35,
                                  f"uses the name '{label}' of {org} ({kind}) on the unrelated domain {site}",
                                  "identity_host"))
            break
    return out
