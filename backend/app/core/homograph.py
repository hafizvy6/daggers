from __future__ import annotations

import unicodedata
from dataclasses import dataclass

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
CONFUSABLES = {
    "а": "a",  # Cyrillic a
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ѕ": "s",
    "ԁ": "d",
    "ց": "g",
    "һ": "h",
    "і": "i",
    "ј": "j",
    "ԛ": "q",
    "т": "t",
    "ν": "v",
    "ο": "o",  # Greek omicron
    "α": "a",
    "ρ": "p",
    "τ": "t",
    "ε": "e",
    "χ": "x",
    "κ": "k",
    "μ": "m",
    "β": "b",
    "ι": "i",
    "η": "n",
    "υ": "u",
    "ζ": "z",
    "ı": "i",  # dotless i
    "ſ": "s",  # long s
    "ƒ": "f",
    "ℓ": "l",
    "ɑ": "a",
    "ɡ": "g",
    "ϲ": "c",
    "ө": "o",
    "ө": "o",
}

MULTI_SUFFIXES = {
    "co.ae", "com.ae", "net.ae", "org.ae", "gov.ae", "ac.ae", "sch.ae",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.nz",
    "com.sa", "com.qa", "com.kw", "com.bh", "com.om", "com.eg", "com.jo",
    "com.tr", "com.br", "com.mx", "com.sg", "com.my", "com.ph", "com.pk",
    "com.hk", "com.cn", "com.tw", "co.jp", "co.kr", "co.in", "co.id",
    "co.th", "co.za", "com.ua", "com.ru", "com.pl", "com.es", "com.pt",
}


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


DIGIT_CONFUSABLES = {"0": "o", "1": "l", "3": "e", "5": "s", "7": "t"}


def confusable_fold(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text or "").casefold()
    folded_chars: list[str] = []
    for char in normalized:
        if unicodedata.combining(char):
            continue
        folded_chars.append(CONFUSABLES.get(char, char))
    return "".join(folded_chars)


def visual_fold(text: str) -> str:
    """Like confusable_fold but also maps common digit lookalikes (0->o, 1->l, ...).
    Use for homograph/spoof detection; do not use for numeric/amount parsing."""
    normalized = unicodedata.normalize("NFKD", text or "").casefold()
    folded_chars: list[str] = []
    for char in normalized:
        if unicodedata.combining(char):
            continue
        mapped = CONFUSABLES.get(char)
        if mapped is None:
            mapped = DIGIT_CONFUSABLES.get(char, char)
        folded_chars.append(mapped)
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

    has_confusable_evidence = mixed_script or bool(forms["has_punycode"])
    if not has_confusable_evidence:
        for label in labels:
            for char in label:
                if char == ".":
                    continue
                folded = char.casefold()
                if confusable_fold(char) != folded or visual_fold(char) != folded:
                    has_confusable_evidence = True
                    break
            if has_confusable_evidence:
                break

    spoofed_domain: str | None = None
    for official in official_domains:
        official = str(official).lower()
        if is_official_host(unicode_host, official):
            continue
        official_unicode = str(host_forms(official)["unicode_host"])
        official_label = official_unicode.split(".")[0]
        folded_official = visual_fold(official_unicode)
        folded_registrable = visual_fold(registrable)
        folded_official_plain = confusable_fold(official_unicode)
        folded_registrable_plain = confusable_fold(registrable)
        label_match = len(official_label) >= 3 and any(
            visual_fold(label) == visual_fold(official_label) for label in labels
        )
        fold_match = (
            folded_registrable == folded_official
            or folded_registrable_plain == folded_official_plain
            or visual_fold(unicode_host) == folded_official
            or confusable_fold(unicode_host) == folded_official_plain
            or label_match
        )
        if fold_match and has_confusable_evidence:
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
