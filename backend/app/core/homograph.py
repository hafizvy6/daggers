from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from .rules import rules as _rules

MIXABLE_SCRIPTS = {"CYRILLIC", "GREEK", "ARMENIAN", "GEORGIAN"}
KNOWN_SCRIPTS = (
    "LATIN",
    "CYRILLIC",
    "GREEK",
    "ARABIC",
    "HEBREW",
    "ARMENIAN",
    "GEORGIAN",
    "CJK",
    "HIRAGANA",
    "KATAKANA",
    "HANGUL",
)

# Characters that visually impersonate Latin letters. Keys are NFKC + casefold forms.
CONFUSABLES = dict(_rules()["confusables"])   # data: core/rules.yaml

# Fallback only (the Public Suffix List is used first) — data: core/rules.yaml
MULTI_SUFFIXES = frozenset(_rules()["fallback_multi_suffixes"])


def _decode_label(label: str) -> str:
    lower = label.lower()
    if not lower.startswith("xn--"):
        return label
    try:
        return lower[4:].encode("ascii").decode("punycode")
    except Exception:
        try:
            import idna  # type: ignore[import-not-found]

            return idna.decode(lower)
        except Exception:
            return label


def _punycode_label(label: str) -> str:
    if label.isascii():
        return label.lower()
    try:
        return "xn--" + label.casefold().encode("punycode").decode("ascii")
    except Exception:
        try:
            import idna  # type: ignore[import-not-found]

            return idna.encode(label).decode("ascii")
        except Exception:
            return label.casefold()


def host_forms(host: str) -> dict[str, object]:
    """Return Unicode and punycode representations of an IDN host."""
    clean = (host or "").strip().rstrip(".").lower()
    labels = clean.split(".") if clean else []
    unicode_labels = [_decode_label(label) for label in labels]
    unicode_host = ".".join(unicode_labels)
    punycode_labels = [_punycode_label(label) for label in unicode_labels]
    punycode_host = ".".join(punycode_labels)
    if any(label.startswith("xn--") for label in labels):
        # Preserve the exact wire form when the caller supplied punycode.
        punycode_host = clean
    return {
        "unicode_host": unicode_host,
        "punycode_host": punycode_host,
        "labels": unicode_labels,
        "has_punycode": any(label.startswith("xn--") for label in labels),
    }


def confusable_fold(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text or "").casefold()
    folded_chars: list[str] = []
    for char in normalized:
        folded_chars.append(CONFUSABLES.get(char, char))
    return "".join(folded_chars)


def script_of(char: str) -> str:
    if not char.isalpha():
        return "COMMON"
    name = unicodedata.name(char, "")
    for script in KNOWN_SCRIPTS:
        if script in name:
            return script
    return "OTHER"


def label_scripts(label: str) -> set[str]:
    return {script for script in (script_of(char) for char in label) if script != "COMMON"}


def has_mixed_script(label: str) -> tuple[bool, tuple[str, ...]]:
    scripts = label_scripts(label)
    if "LATIN" in scripts and any(script in MIXABLE_SCRIPTS for script in scripts):
        return True, tuple(sorted(scripts))
    return False, tuple(sorted(scripts))


def is_official_host(host: str, official_domain: str) -> bool:
    """Exact allowlist check. Deliberately does NOT confusable-fold: аmazon.ae must not equal amazon.ae."""
    candidate_forms = host_forms(host)
    official_forms = host_forms(official_domain)
    candidates = {
        str(candidate_forms["unicode_host"]),
        str(candidate_forms["punycode_host"]),
    }
    officials = {
        str(official_forms["unicode_host"]),
        str(official_forms["punycode_host"]),
    }
    return any(
        candidate == official or candidate.endswith("." + official)
        for candidate in candidates
        for official in officials
    )


def simple_registrable(host: str) -> str:
    labels = str(host_forms(host)["unicode_host"]).split(".")
    if len(labels) < 2:
        return ".".join(labels)
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


@dataclass(frozen=True)
class HomographResult:
    unicode_host: str
    punycode_host: str
    mixed_script: bool
    spoof: bool
    spoofed_domain: str | None
    reasons: tuple[str, ...]

    @property
    def signal(self) -> bool:
        return self.mixed_script or self.spoof

    def as_dict(self) -> dict:
        return {
            "unicode_host": self.unicode_host,
            "punycode_host": self.punycode_host,
            "mixed_script": self.mixed_script,
            "spoof": self.spoof,
            "spoofed_domain": self.spoofed_domain,
            "reasons": list(self.reasons),
        }


def audit(
    host: str,
    official_domains: tuple[str, ...] | list[str],
    registrable_domain: str | None = None,
) -> HomographResult:
    """Detect mixed-script labels and confusable folds against the official brand set."""
    forms = host_forms(host)
    unicode_host = str(forms["unicode_host"])
    punycode_host = str(forms["punycode_host"])
    labels = [str(label) for label in forms["labels"]]  # type: ignore[index]
    reg_forms = host_forms(registrable_domain) if registrable_domain else None
    registrable = str(reg_forms["unicode_host"]) if reg_forms else simple_registrable(unicode_host)

    reasons: list[str] = []
    mixed_script = False
    for label in labels:
        mixed, scripts = has_mixed_script(label)
        if mixed:
            mixed_script = True
            reasons.append(f"mixed-script domain label ({' + '.join(scripts)})")
            break

    spoofed_domain: str | None = None
    # A host that IS one of the official domains (a brand may own several) is never a spoof.
    genuine = any(is_official_host(unicode_host, str(o).lower()) for o in official_domains)
    for official in (() if genuine else official_domains):
        official = str(official).lower()
        if is_official_host(unicode_host, official):
            continue
        official_unicode = str(host_forms(official)["unicode_host"])
        official_label = official_unicode.split(".")[0]
        folded_official = confusable_fold(official_unicode)
        folded_registrable = confusable_fold(registrable)
        label_match = len(official_label) >= 3 and any(
            confusable_fold(label) == confusable_fold(official_label) for label in labels
        )
        if folded_registrable == folded_official or confusable_fold(unicode_host) == folded_official or label_match:
            spoofed_domain = official
            reasons.append(f"confusable spoof of {official} (look-alike letters from another alphabet)")
            break

    return HomographResult(
        unicode_host=unicode_host,
        punycode_host=punycode_host,
        mixed_script=mixed_script,
        spoof=spoofed_domain is not None,
        spoofed_domain=spoofed_domain,
        reasons=tuple(reasons),
    )
