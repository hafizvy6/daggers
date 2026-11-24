from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable, Mapping
from urllib.parse import urlparse

from . import claims as claim_engine
from . import homograph
from . import numbers
from . import verdicts
from .verdicts import MALICIOUS, MISLEADING, SUSPICIOUS, UNKNOWN

RISKY_TLDS = {
    "top", "xyz", "icu", "click", "live", "cfd", "rest", "sbs", "shop", "online",
    "site", "fun", "buzz", "work", "loan", "gq", "cf", "tk", "ml", "ga",
}
CONFIRMATION_SIGNALS = frozenset(
    {
        "vision.clone_ge_90",
        "feeds.phishtank_confirmed",
        "content.form_action_mismatch",
        "content.payment_harvest_fields",
    }
)
HEX_RUN = re.compile(r"[a-f0-9]{12,}", re.I)
CONSONANT_RUN = re.compile(r"[bcdfghjklmnpqrstvwxz]{12,}", re.I)
URL_RE = re.compile(
    r"(?:(?:https?://|www\.)[^\s<>\"'`]+|[\w\u0600-\u06ff-]+(?:\.[\w\u0600-\u06ff-]+)+(?:/[^\s<>\"'`]*)?)",
    re.UNICODE,
)


@dataclass(frozen=True)
class Signal:
    name: str
    weight: float
    reason: str

    def as_dict(self) -> dict:
        return {"name": self.name, "weight": self.weight, "reason": self.reason}


@dataclass(frozen=True)
class NormalizedURL:
    raw: str
    scheme: str
    host: str
    unicode_host: str
    punycode_host: str
    registrable_domain: str
    subdomain: str
    path: str
    query: str
    tld: str
    path_depth: int
    authority_has_at: bool
    has_punycode: bool
    is_ip: bool

    def as_dict(self) -> dict:
        return {
            "raw": self.raw,
            "scheme": self.scheme,
            "host": self.host,
            "unicode_host": self.unicode_host,
            "punycode_host": self.punycode_host,
            "registrable_domain": self.registrable_domain,
            "subdomain": self.subdomain,
            "path": self.path,
            "query": self.query,
            "tld": self.tld,
            "path_depth": self.path_depth,
            "authority_has_at": self.authority_has_at,
            "has_punycode": self.has_punycode,
            "is_ip": self.is_ip,
        }


@dataclass(frozen=True)
class ScoreResult:
    score: float
    verdict: str
    reasons: list[str] = field(default_factory=list)
    signals: list[dict] = field(default_factory=list)
    l1_detail: dict[str, float] = field(default_factory=dict)
    normalized: dict = field(default_factory=dict)
    homograph: dict = field(default_factory=dict)
    brand_hit: bool = False
    claim_hit: bool = False
    scam_type: str | None = None

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "signals": list(self.signals),
            "l1_detail": dict(self.l1_detail),
            "normalized": dict(self.normalized),
            "homograph": dict(self.homograph),
            "brand_hit": self.brand_hit,
            "claim_hit": self.claim_hit,
            "scam_type": self.scam_type,
        }


def levenshtein(left: str, right: str, max_distance: int = 3) -> int:
    """Small bounded edit distance; pure and fast enough for brand-length tokens."""
    if left == right:
        return 0
    if abs(len(left) - len(right)) > max_distance:
        return max_distance + 1
    previous = list(range(len(right) + 1))
    for i, char_left in enumerate(left, 1):
        current = [i] + [0] * len(right)
        row_min = current[0]
        for j, char_right in enumerate(right, 1):
            cost = 0 if char_left == char_right else 1
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            row_min = min(row_min, current[j])
        if row_min > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def _registrable(host_unicode: str, suffix_resolver: Callable[[str], str | None] | None) -> str:
    if suffix_resolver:
        for candidate in (host_unicode, homograph.host_forms(host_unicode)["punycode_host"]):
            resolved = suffix_resolver(str(candidate))
            if resolved:
                return str(resolved).lower()
    return homograph.simple_registrable(host_unicode)


def normalize_url(
    raw: str,
    suffix_resolver: Callable[[str], str | None] | None = None,
) -> NormalizedURL:
    """S0: scheme/host/eTLD+1/path/query plus Unicode and punycode host forms."""
    value = (raw or "").strip()
    candidate = value if "://" in value or value.startswith("//") else f"https://{value.lstrip('/')}"
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").strip().rstrip(".").lower()
    forms = homograph.host_forms(host)
    unicode_host = str(forms["unicode_host"])
    punycode_host = str(forms["punycode_host"])
    registrable = _registrable(unicode_host, suffix_resolver)
    reg_suffix_len = len(registrable.split("."))
    host_labels = unicode_host.split(".") if unicode_host else []
    subdomain = ".".join(host_labels[:-reg_suffix_len]) if len(host_labels) > reg_suffix_len else ""
    path = parsed.path or ""
    query = parsed.query or ""
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    tld = registrable.split(".")[-1] if registrable else ""
    return NormalizedURL(
        raw=value,
        scheme=parsed.scheme or "https",
        host=host,
        unicode_host=unicode_host,
        punycode_host=punycode_host,
        registrable_domain=registrable,
        subdomain=subdomain,
        path=path,
        query=query,
        tld=tld,
        path_depth=len([segment for segment in path.split("/") if segment]),
        authority_has_at="@" in (parsed.netloc or ""),
        has_punycode=bool(forms["has_punycode"]) or "xn--" in punycode_host,
        is_ip=is_ip,
    )


def _flat_lures(lures: Mapping[str, object] | list[object] | tuple[object, ...]) -> tuple[str, ...]:
    if isinstance(lures, Mapping):
        values = [str(term).lower() for group in lures.values() for term in group]  # type: ignore[union-attr]
    else:
        values = [str(term).lower() for term in lures]
    return tuple(dict.fromkeys(values))


def _gibberish_run(host: str) -> bool:
    return bool(HEX_RUN.search(host) or CONSONANT_RUN.search(host))


def _lexical_signals(
    norm: NormalizedURL,
    raw: str,
    lures: Mapping[str, object] | list[object] | tuple[object, ...],
    audit: homograph.HomographResult,
) -> list[Signal]:
    signals: list[Signal] = []
    if norm.is_ip:
        signals.append(Signal("lexical.ip_host", 0.40, "IP-literal host instead of a domain name"))
    if norm.authority_has_at:
        signals.append(Signal("lexical.at_in_authority", 0.30, "'user@host' trick in URL authority"))
    if norm.tld in RISKY_TLDS:
        signals.append(Signal("lexical.risky_tld", 0.15, f"risky low-cost TLD .{norm.tld}"))
    if norm.path_depth > 4:
        signals.append(Signal("lexical.path_depth", 0.10, f"URL path depth {norm.path_depth}"))
    if _gibberish_run(norm.unicode_host):
        signals.append(Signal("lexical.gibberish_run", 0.15, "12+ character hex/gibberish run in domain"))
    path_query = homograph.confusable_fold(f"{norm.path}?{norm.query}")
    for term in _flat_lures(lures):
        if len(term) >= 3 and homograph.confusable_fold(term) in path_query:
            signals.append(Signal("lexical.lure_keyword", 0.20, f"lure keyword '{term}' in URL path/query"))
            break
    # A legitimate fully non-Latin IDN is not a signal. Punycode counts only when
    # the decoded form is mixed-script or folds into an official brand.
    suspicious_punycode = audit.signal or (
        "xn--" in raw.lower()
        and any("LATIN" in homograph.label_scripts(label) for label in norm.unicode_host.split("."))
    )
    if ("xn--" in norm.punycode_host or "xn--" in raw.lower()) and suspicious_punycode:
        signals.append(Signal("lexical.punycode_xn", 0.35, "punycode IDN label (xn--)"))
    return signals


def _token_distance(label: str, token: str) -> int:
    folded_label = homograph.confusable_fold(label)
    folded_token = homograph.confusable_fold(token)
    if not folded_label or not folded_token:
        return 99
    segments = [segment for segment in re.split(r"[^0-9a-z\u0600-\u06ff]+", folded_label) if segment]
    # Compare whole labels and delimited segments only. Prefix/suffix windows
    # create false positives on short or gibberish labels (e.g. abcd -> addc).
    candidates = {folded_label, *segments}
    return min(levenshtein(candidate, folded_token) for candidate in candidates if candidate)


def _token_present(token: str, folded_url: str) -> bool:
    folded_token = homograph.confusable_fold(token)
    if not folded_token:
        return False
    if folded_token.isascii():
        pattern = r"(?<![a-z0-9])" + re.escape(folded_token) + r"(?![a-z0-9])"
        return bool(re.search(pattern, folded_url, re.I))
    return folded_token in folded_url


def _brand_candidates(
    norm: NormalizedURL,
    raw: str,
    brands: list[dict] | tuple[dict, ...],
) -> list[dict]:
    """One candidate per brand; exact host matches and bounded URL mentions are kept separate."""
    folded_url = homograph.confusable_fold(f"{raw} {norm.unicode_host} {norm.path} {norm.query}")
    labels = norm.unicode_host.split(".")[:-1] or norm.unicode_host.split(".")
    segments: list[str] = []
    for label in labels:
        segments.extend(
            segment
            for segment in re.split(r"[^0-9a-z\u0600-\u06ff]+", homograph.confusable_fold(label))
            if segment
        )
    candidates: list[dict] = []
    for brand in brands:
        canonical = str(brand.get("token", "")).lower()
        official = str(brand.get("official_domain", "")).lower()
        official_label = official.split(".")[0]
        aliases = [str(alias).lower() for alias in brand.get("aliases", [])]
        tokens = tuple(dict.fromkeys([canonical, *aliases]))
        url_token = next(
            (token for token in tokens if len(token) >= 3 and _token_present(token, folded_url)),
            None,
        )
        exact_host = any(
            homograph.confusable_fold(segment) == homograph.confusable_fold(token)
            for segment in [*segments, *labels]
            for token in tokens
            if len(token) >= 3
        ) or any(
            homograph.confusable_fold(label) == homograph.confusable_fold(official_label)
            for label in labels
        )
        best_distance = 99
        best_token = canonical
        if not exact_host:
            for label in [*labels, *segments]:
                if len(homograph.confusable_fold(label)) < 4:
                    continue
                for token in tokens:
                    if len(token) < 4:
                        continue
                    distance = _token_distance(label, token)
                    if distance < best_distance:
                        best_distance, best_token = distance, token
        else:
            best_distance, best_token = 0, url_token or canonical
        candidates.append(
            {
                "canonical": canonical,
                "official": official,
                "token": best_token if best_distance <= 2 else (url_token or canonical),
                "url_token": url_token,
                "exact_host": exact_host,
                "distance": best_distance,
            }
        )
    return candidates


def _identity_signals(
    norm: NormalizedURL,
    raw: str,
    brands: list[dict] | tuple[dict, ...],
    official_domains: tuple[str, ...],
) -> tuple[list[Signal], bool]:
    """S2: avoid pile-on false positives from short tokens; emit at most one typo signal."""
    del official_domains  # allowlist was already checked by score_url
    candidates = _brand_candidates(norm, raw, brands)
    exact = [item for item in candidates if item["exact_host"]]
    if exact:
        chosen = max(exact, key=lambda item: len(item["token"]))
        signals = [
            Signal(
                "identity.brand_typo_d1",
                0.55,
                f"brand typo/name '{chosen['token']}' (distance 0) outside {chosen['official']}",
            )
        ]
        url_token = chosen["url_token"] or chosen["token"]
        signals.append(
            Signal(
                "identity.brand_in_url",
                0.25,
                f"brand name '{url_token}' appears outside its official domain",
            )
        )
        return signals, True

    typos = [item for item in candidates if item["distance"] <= 2]
    mentions = [item for item in candidates if item["url_token"]]
    signals: list[Signal] = []
    brand_hit = bool(mentions)
    if typos:
        chosen = min(typos, key=lambda item: (item["distance"], -len(item["token"])))
        if chosen["distance"] <= 1:
            signals.append(
                Signal(
                    "identity.brand_typo_d1",
                    0.55,
                    f"brand typo '{chosen['token']}' (distance {chosen['distance']}) outside {chosen['official']}",
                )
            )
        else:
            signals.append(
                Signal(
                    "identity.brand_typo_d2",
                    0.35,
                    f"brand typo '{chosen['token']}' (distance 2) outside {chosen['official']}",
                )
            )
        brand_hit = True
    if mentions:
        chosen = max(mentions, key=lambda item: len(item["url_token"] or ""))
        signals.append(
            Signal(
                "identity.brand_in_url",
                0.25,
                f"brand name '{chosen['url_token']}' appears outside its official domain",
            )
        )
    return signals, brand_hit


def _context_signals(context: Mapping[str, object], brand_hit: bool) -> list[Signal]:
    signals: list[Signal] = []
    if context.get("phishtank_confirmed"):
        signals.append(Signal("feeds.phishtank_confirmed", 0.70, "confirmed in a phishing URL feed"))
    cert_age = context.get("cert_age_hours")
    if isinstance(cert_age, (int, float)) and cert_age < 24:
        signals.append(Signal("infra.cert_age_lt_24h", 0.25, "TLS certificate issued less than 24h ago"))
    clone = context.get("clone_score")
    if isinstance(clone, (int, float)) and clone >= 90 and brand_hit:
        match = str(context.get("gallery_match") or "an official page")
        signals.append(Signal("vision.clone_ge_90", 0.60, f"visual clone {int(clone)}% match to {match}"))
    if context.get("form_action_mismatch"):
        signals.append(Signal("content.form_action_mismatch", 0.30, "form posts to foreign host"))
    if context.get("payment_harvest_fields"):
        signals.append(Signal("content.payment_harvest_fields", 0.25, "payment-harvest fields (iban, cvv, otp)"))
    if context.get("obfuscated_script"):
        signals.append(Signal("content.obfuscated_script", 0.15, "obfuscated script"))
    return signals


def _infer_scam_type(
    claim_hit: bool,
    audit: homograph.HomographResult,
    signals: list[Signal],
    context: Mapping[str, object],
    brand_hit: bool,
) -> str | None:
    names = {signal.name for signal in signals}
    has_confirmation = bool(names & CONFIRMATION_SIGNALS)
    if claim_hit and not has_confirmation:
        return "unverifiable-giveaway-claim"
    if "vision.clone_ge_90" in names and brand_hit:
        return "fake-banking-login"
    if "feeds.phishtank_confirmed" in names:
        return "known-phishing-url"
    if audit.spoof or audit.mixed_script:
        return "lookalike-domain"
    if "content.payment_harvest_fields" in names or "content.form_action_mismatch" in names:
        return "credential-harvesting"
    if claim_hit:
        return "claim-with-confirmed-evidence"
    if "lexical.lure_keyword" in names:
        return "lure-link"
    if context.get("clone_score"):
        return "visual-imitation"
    return None


def score_url(
    raw_url: str,
    *,
    brands: list[dict] | tuple[dict, ...],
    lures: Mapping[str, object] | list[object] | tuple[object, ...],
    context: Mapping[str, object] | None = None,
    suffix_resolver: Callable[[str], str | None] | None = None,
    text: str | None = None,
    thresholds: Mapping[str, float] | None = None,
) -> ScoreResult:
    """S0–S3 + S5 + S6. Pure: all I/O (feeds, enrichment, vision) arrives via context."""
    context = dict(context or {})
    official_domains = tuple(str(brand["official_domain"]).lower() for brand in brands)
    norm = normalize_url(raw_url, suffix_resolver)
    audit = homograph.audit(norm.unicode_host, official_domains, norm.registrable_domain)
    is_official = any(homograph.is_official_host(norm.unicode_host, domain) for domain in official_domains)
    if is_official:
        return ScoreResult(
            score=0.0,
            verdict=UNKNOWN,
            reasons=["matches official domain allowlist"],
            normalized=norm.as_dict(),
            homograph=audit.as_dict(),
            scam_type=None,
        )

    signals = _lexical_signals(norm, raw_url, lures, audit)
    identity, brand_hit = _identity_signals(norm, raw_url, brands, official_domains)
    signals.extend(identity)
    if audit.signal:
        signals.append(Signal("homograph.mixed_or_spoof", 0.45, "; ".join(audit.reasons)))

    claim = claim_engine.evaluate_claims(
        text if text is not None else f"{raw_url} {norm.path} {norm.query}",
        norm.unicode_host,
        list(brands),
        official_domains,
    )
    claim_hit = claim is not None
    if claim:
        signals.append(Signal(claim.name, claim.weight, claim.reason))

    signals.extend(_context_signals(context, brand_hit))
    total = verdicts.clamp(sum(signal.weight for signal in signals))
    has_confirmation = any(signal.name in CONFIRMATION_SIGNALS for signal in signals)
    claim_only_cap = verdicts.MISLEADING if claim_hit and not has_confirmation else None
    verdict = verdicts.decide(
        total,
        forced_min=claim.forced_min if claim else None,
        cap=claim_only_cap,
        thresholds=thresholds,
    )
    reasons = list(dict.fromkeys(signal.reason for signal in signals if signal.weight > 0))
    if not reasons:
        reasons.append("no signs found in the offline rules")
    return ScoreResult(
        score=total,
        verdict=verdict,
        reasons=reasons,
        signals=[signal.as_dict() for signal in signals],
        l1_detail={signal.name: signal.weight for signal in signals},
        normalized=norm.as_dict(),
        homograph=audit.as_dict(),
        brand_hit=brand_hit,
        claim_hit=claim_hit,
        scam_type=_infer_scam_type(claim_hit, audit, signals, context, brand_hit),
    )


def _score_claim_only(
    text: str,
    brands: list[dict] | tuple[dict, ...],
    thresholds: Mapping[str, float] | None,
) -> ScoreResult:
    official_domains = tuple(str(brand["official_domain"]).lower() for brand in brands)
    claim = claim_engine.evaluate_claims(text, "", list(brands), official_domains)
    if not claim:
        return ScoreResult(
            score=0.0,
            verdict=UNKNOWN,
            reasons=["no URL or verifiable claim pattern found"],
            scam_type=None,
        )
    score = verdicts.clamp(claim.weight)
    return ScoreResult(
        score=score,
        verdict=verdicts.decide(score, forced_min=claim.forced_min, thresholds=thresholds),
        reasons=[claim.reason],
        signals=[Signal(claim.name, claim.weight, claim.reason).as_dict()],
        l1_detail={claim.name: claim.weight},
        claim_hit=True,
        scam_type=claim.scam_type,
    )


def _clean_url_candidate(candidate: str) -> str:
    return candidate.strip().rstrip(".,;:!?)]}'\"").lstrip("([{'\"")


def extract_urls(text: str) -> list[str]:
    found: list[str] = []
    for match in URL_RE.findall(text or ""):
        candidate = _clean_url_candidate(match)
        if candidate and candidate not in found:
            found.append(candidate)
    return found[:5]


def score_request(
    kind: str,
    input_value: str,
    lang: str = "en",
    *,
    brands: list[dict] | tuple[dict, ...],
    lures: Mapping[str, object] | list[object] | tuple[object, ...],
    suffix_resolver: Callable[[str], str | None] | None = None,
    context: Mapping[str, object] | None = None,
    thresholds: Mapping[str, float] | None = None,
    evidence_lookup: Callable[[str], str | None] | None = None,
) -> dict:
    """Build the exact C2 ScanResult. No caller input is persisted by this function."""
    if kind not in {"url", "text", "number"}:
        raise ValueError("kind must be url, text, or number")
    if lang not in {"en", "ar"}:
        raise ValueError("lang must be en or ar")

    evidence_url: str | None = None
    if kind == "number":
        result = numbers.check_number(input_value).as_scan_fragment()
        verdict = str(result["verdict"])
        score = float(result["score"])
        reasons = list(result["reasons"])
        scam_type = result["scam_type"]
    else:
        candidates = [input_value] if kind == "url" else extract_urls(input_value)
        best: ScoreResult | None = None
        best_norm: NormalizedURL | None = None
        for candidate in candidates:
            candidate_result = score_url(
                candidate,
                brands=brands,
                lures=lures,
                context=context,
                suffix_resolver=suffix_resolver,
                text=input_value if kind == "text" else None,
                thresholds=thresholds,
            )
            if best is None or candidate_result.score > best.score:
                best = candidate_result
                best_norm = normalize_url(candidate, suffix_resolver)
        if best is None:
            best = _score_claim_only(input_value, brands, thresholds)
        if best_norm and evidence_lookup:
            lookup_key = best_norm.registrable_domain or best_norm.unicode_host
            try:
                evidence_url = evidence_lookup(lookup_key)
            except Exception:
                evidence_url = None
        verdict = best.verdict
        score = best.score
        reasons = list(best.reasons)
        scam_type = best.scam_type

    return {
        "kind": kind,
        "input": input_value,
        "verdict": verdict,
        "score": score,
        "reasons": reasons,
        "evidence_url": evidence_url,
        "scam_type": scam_type,
        "offline_capable": True,
    }


# Explicit public aliases for channel adapters importing the brain in-process.
scan = score_request
