"""Zero-PII guard for WS2 channels.

* Sweep queries containing personal identifiers are refused outright.
* Third-party titles/snippets are redacted before they are stored or returned.
Business listing phone numbers are treated as business data (they are checked,
not collected about a person); victim information is never accepted.
"""
from __future__ import annotations

import re

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.UNICODE)
_EMIRATES_ID = re.compile(r"\b784[-\s]?\d{4}[-\s]?\d{7}[-\s]?\d\b")
_IBAN = re.compile(r"\bAE\d{2}\s?(?:\d{4}\s?){4}\d{3}\b", re.I)
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_PHONE = re.compile(r"(?:\+|00)?\d[\d\s().-]{7,}\d")
_PASSPORT_HINT = re.compile(r"\bpassport\s*(?:no\.?|number|#)?\s*[A-Z0-9]{6,9}\b", re.I)

_PATTERNS = (
    ("email", _EMAIL), ("emirates_id", _EMIRATES_ID), ("iban", _IBAN),
    ("passport", _PASSPORT_HINT), ("card_number", _CARD), ("phone", _PHONE),
)


def pii_kinds(text: str) -> list[str]:
    found = []
    for name, pattern in _PATTERNS:
        if pattern.search(text or ""):
            found.append(name)
    return found


def redact(text: str | None, max_len: int = 400) -> str:
    value = (text or "")[: max_len * 2]
    for name, pattern in _PATTERNS:
        value = pattern.sub(f"[{name} removed]", value)
    return " ".join(value.split())[:max_len]
