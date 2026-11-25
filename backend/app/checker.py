"""Live Checker: input handling around the intelligence engine.

Pure helpers (no I/O):

* ``classify``        — validate the submission, decide URL/domain vs message, normalise it
* ``redact``          — remove personal data from a message before it is stored
* ``check_statuses``  — which checks ran, which could not be completed, and why
* ``precautions``     — precaution codes for the user (rendered by the UI in EN/AR)
* ``content_hash``    — key used to stop refreshes / double clicks creating duplicate findings

The verdict itself is never computed here: it comes from ``core.scorer`` (engine)
and ``channels.trust_policy`` (central tag) via ``Runtime.check``.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .channels.urls import TRACKING_PARAMS
from .core.scorer import URL_RE

MAX_INPUT = 4000
MAX_URL = 2048
INPUT_URL = "url"
INPUT_TEXT = "text"


class CheckInputError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Classified:
    input_type: str          # "url" | "text"
    value: str               # what the engine analyses (normalised URL, or the message)
    original: str            # trimmed submission
    normalized_url: str | None
    domain: str | None


_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.I)


def _clean(raw: str) -> str:
    text = unicodedata.normalize("NFC", raw or "")
    return _CONTROL.sub("", text).strip()


def normalize_url(raw: str) -> tuple[str, str]:
    """→ (normalised URL, host). Raises CheckInputError.

    Adds https:// to bare domains, lower-cases scheme/host, drops the fragment and
    tracking parameters. User-info (``user@host``) is KEPT: it is phishing evidence.
    """
    value = raw.strip()
    if len(value) > MAX_URL:
        raise CheckInputError("url_too_long", f"URL is longer than {MAX_URL} characters")
    if value.lower().startswith("www.") or not _SCHEME.match(value) or re.match(r"^[^:/]+:\d+(/|$)", value):
        value = "https://" + value
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise CheckInputError("invalid_url", "the URL could not be parsed") from None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise CheckInputError("unsupported_scheme", f"only web links (http/https) can be checked, not '{scheme}:'")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host or ("." not in host and ":" not in host):
        raise CheckInputError("invalid_host", "the link has no valid domain name")
    if any(ch.isspace() for ch in host) or len(host) > 253:
        raise CheckInputError("invalid_host", "the link has no valid domain name")
    userinfo = ""
    if parts.username is not None:
        userinfo = parts.username + (":" + parts.password if parts.password else "") + "@"
    netloc_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    netloc = userinfo + netloc_host + (f":{port}" if port not in (None, default_port) else "")
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if not k.lower().startswith("utm_") and k.lower() not in TRACKING_PARAMS]
    return urlunsplit((scheme, netloc, parts.path or "/", urlencode(query, doseq=True), "")), host


def classify(raw: str) -> Classified:
    text = _clean(raw)
    if not text:
        raise CheckInputError("empty", "enter a link or paste a message to check")
    if len(text) > MAX_INPUT:
        raise CheckInputError("too_long", f"input is longer than {MAX_INPUT} characters")
    single_token = not any(ch.isspace() for ch in text)
    looks_like_link = single_token and (
        bool(_SCHEME.match(text)) and not text.lower().startswith(("mailto:", "tel:", "sms:"))
        or bool(URL_RE.fullmatch(text))
    )
    if single_token and text.lower().startswith(("javascript:", "data:", "file:", "vbscript:")):
        raise CheckInputError("unsupported_scheme", "only web links (http/https) can be checked")
    if looks_like_link:
        url, host = normalize_url(text)
        return Classified(INPUT_URL, url, text, url, host)
    if len(text) < 4:
        raise CheckInputError("too_short", "the message is too short to analyse")
    return Classified(INPUT_TEXT, text, text, None, None)


# ---------------------------------------------------------------- privacy

_REDACTIONS = (
    ("email", re.compile(r"(?<![/\w.-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w/])")),
    ("emirates_id", re.compile(r"\b784[- ]?\d{4}[- ]?\d{7}[- ]?\d\b")),
    ("iban", re.compile(r"\bAE\d{2}\s?(?:\d{4}\s?){4}\d{3}\b", re.I)),
    ("card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("phone", re.compile(r"(?:(?<=\s)|^)(?:\+|00)?(?:971|0)[\s-]?(?:5\d|[2-79])[\s-]?\d{3}[\s-]?\d{4}\b")),
    ("phone", re.compile(r"\+\d[\d\s-]{8,15}\d")),
)


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


def redact(text: str | None) -> tuple[str, dict[str, int]]:
    """Mask personal data (e-mail, phone, Emirates ID, IBAN, card numbers) in a message.

    URLs are left intact: they are the evidence being reported.
    """
    if not text:
        return text or "", {}
    counts: dict[str, int] = {}
    urls = [(m.start(), m.end()) for m in URL_RE.finditer(text) if "@" not in m.group(0) or "/" in m.group(0)]

    def inside_url(start: int, end: int) -> bool:
        return any(s <= start and end <= e for s, e in urls)

    out = text
    for label, pattern in _REDACTIONS:
        def repl(match: re.Match[str], label: str = label) -> str:
            if inside_url(match.start(), match.end()) and label != "email":
                return match.group(0)
            if label == "card" and not _luhn(re.sub(r"\D", "", match.group(0))):
                return match.group(0)
            counts[label] = counts.get(label, 0) + 1
            return f"[{label} removed]"
        out = pattern.sub(repl, out)
        urls = [(m.start(), m.end()) for m in URL_RE.finditer(out)]
    return out, counts


def redact_signals(signals: list[dict]) -> list[dict]:
    out = []
    for signal in signals:
        item = dict(signal)
        if item.get("part") == "message" and item.get("excerpt"):
            item["excerpt"] = redact(str(item["excerpt"]))[0]
        out.append(item)
    return out


def content_hash(input_type: str, value: str) -> str:
    folded = re.sub(r"\s+", " ", value.strip().lower())
    return hashlib.sha256(f"{input_type}\n{folded}".encode("utf-8")).hexdigest()


def client_hash(ip: str) -> str:
    return hashlib.sha256(f"daggers-client\n{ip}".encode("utf-8")).hexdigest()[:24]


# ---------------------------------------------------------------- reporting

def check_statuses(result: dict, input_type: str, trust_policy_ok: bool) -> list[dict]:
    """Every check, with an honest status: completed | not_applicable | unavailable | incomplete."""
    checks = [{
        "id": "engine",
        "status": "completed",
        "detail": f"{len(result.get('signals') or [])} detection signal(s); "
                  f"{len(result.get('urls') or [])} link(s) analysed",
    }]
    auth = result.get("domain_auth") or {}
    if not trust_policy_ok:
        checks.append({"id": "domain_authentication", "status": "unavailable",
                       "detail": "official-source registry could not be loaded — authenticity not checked"})
        checks.append({"id": "official_verification", "status": "unavailable",
                       "detail": "official-source verification could not run"})
        return checks
    if auth.get("status") == "NOT_CHECKABLE":
        checks.append({"id": "domain_authentication", "status": "not_applicable",
                       "detail": auth.get("reason") or "no link to authenticate"})
    else:
        checks.append({"id": "domain_authentication", "status": "completed",
                       "detail": f"{auth.get('host') or ''}: {auth.get('status')}"})
    gov = result.get("gov_verification")
    if not gov:
        checks.append({"id": "official_verification", "status": "not_applicable",
                       "detail": "no government claim found in the input" if input_type == INPUT_TEXT
                       else "a link alone contains no government claim to verify"})
    else:
        status = gov.get("status")
        unchecked = gov.get("unchecked_sources") or []
        incomplete = status in ("SOURCE_UNAVAILABLE", "SOURCE_EXPIRED", "CONFLICTING_SOURCES") or (
            status == "NOT_VERIFIABLE" and gov.get("coverage") != "checked")
        detail = f"claim {status}"
        if unchecked:
            detail += f"; not checked: {', '.join(map(str, unchecked))}"
        checks.append({"id": "official_verification", "status": "incomplete" if incomplete else "completed",
                       "detail": detail})
    return checks


def precautions(tag: str, signals: list[dict], input_type: str, domain_auth: dict | None = None) -> list[str]:
    """Precaution codes; the UI renders them in the user's language."""
    names = {str(s.get("name", "")) for s in signals}
    categories = {str(s.get("category", "")) for s in signals}
    codes: list[str] = []
    if tag in ("FAKE", "MISLEADING", "WARNING"):
        codes.append("dont_click" if input_type == INPUT_URL or any(s.get("part") != "message" for s in signals)
                     else "dont_reply")
    if "message.credential_request" in names or "phishing" in categories:
        codes.append("never_share_codes")
    if "message.payment_demand" in names or "fraudulent_offer" in categories:
        codes.append("dont_pay")
    if categories & {"brand_impersonation", "government_impersonation", "homograph"}:
        codes.append("use_official_channel")
    if tag == "MISLEADING":
        codes.append("verify_official_source")
    if tag == "FAKE":
        codes.append("report_block")
    if tag == "SAFE":
        status = (domain_auth or {}).get("status")
        codes.append("stay_alert_established" if status == "ESTABLISHED_SITE"
                     else "stay_alert_popular" if status == "REPUTABLE_SITE"
                     else "stay_alert_site" if (domain_auth or {}).get("legitimate_site") else "stay_alert")
    if tag == "WARNING" and not signals:
        codes.append("unverified_not_safe")
    if tag != "SAFE" and (names & {"message.credential_request", "message.payment_demand"} or "phishing" in categories):
        codes.append("if_shared_contact_bank")
    return list(dict.fromkeys(codes))
