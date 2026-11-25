"""Message-content analysis (SMS, WhatsApp, e-mail, copied announcements).

Pure and deterministic: no network, no database, no clock. Every signal records
the exact excerpt of the submitted text that triggered it, so the Checker and the
Police Portal can show *which part* of the message was suspicious.

What it detects (English, Arabic, common Arabizi):

* requests for credentials or one-time codes (OTP, PIN, password, CVV, card / bank
  details, Emirates ID);
* demands for a payment or fee (customs / delivery / release / redelivery fees);
* delivery lures (parcel held, failed delivery, address update);
* urgency or threats (account suspended, within 24 hours, final notice, legal action);
* impersonation: the text names a bank, courier or government body, but its link
  points somewhere other than that organisation's official domain;
* link shorteners that hide the real destination.

Prize / giveaway claims are handled by ``claims.py`` and URL heuristics by
``scorer.score_url``; this module never duplicates them.

What it does NOT do: it does not decide that a message is genuine. A message with
no signals is "no indicators found", never "safe".
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Mapping
from urllib.parse import urlsplit

from .homograph import confusable_fold, is_official_host

AR = r"(?<![؀-ۿ])"  # Arabic has no \b; require a non-Arabic letter before the match

SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy",
    "shorturl.at", "tiny.cc", "rebrand.ly", "s.id", "t.ly", "bl.ink", "short.io", "v.gd", "lnkd.in",
    "qrco.de", "shorturl.asia",
})

# Brand / entity names that are ordinary words in a message and must not count as an
# impersonation mention on their own ("United Arab Emirates", "at noon", "du").
AMBIGUOUS_NAMES = frozenset({
    "emirates", "الإمارات", "noon", "نون", "du", "دو", "e&", "fab", "cbd", "sib", "wio", "ويو",
    "اتصالات", "كريم", "careem", "rta", "icp", "dib", "adib",
})


@dataclass(frozen=True)
class MessageSignal:
    name: str
    weight: float
    reason: str
    excerpt: str
    category: str

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "weight": self.weight,
            "reason": self.reason,
            "excerpt": self.excerpt,
            "part": "message",
            "category": self.category,
        }


def _rx(*parts: str) -> re.Pattern[str]:
    return re.compile("|".join(parts), re.I | re.UNICODE)


CREDENTIAL = _rx(
    r"\b(?:otp|one[- ]?time\s+(?:password|passcode|code|pin)|verification\s+code|security\s+code|"
    r"activation\s+code|pin(?:\s+code)?|password|passcode|cvv|cvc|card\s+(?:number|details|info)|"
    r"(?:bank|account)\s+(?:details|number|credentials|login)|iban|emirates\s+id|login\s+details)\b",
    AR + r"(?:رمز\s*(?:التحقق|التفعيل|التأكيد|السري|otp)|كلمة\s*(?:المرور|السر)|الرقم\s*السري|"
    r"بيانات\s*(?:البطاقة|الحساب|الدخول)|رقم\s*البطاقة|رقم\s*الحساب|الهوية\s*الإماراتية|آيبان)",
    r"\b(?:kalamat\s+al\s+morour|ramz\s+al\s+ta7a?qo?q)\b",
)
CREDENTIAL_ASK = _rx(
    r"\b(?:send|share|enter|provide|confirm|update|verify|submit|reply\s+with|give|type|re-?enter|validate)\b",
    AR + r"(?:أرسل|ارسل|شارك|أدخل|ادخل|حدّث|حدث|تحديث|أكد|تأكيد|قم\s*ب|زودنا)",
)
PAYMENT = _rx(
    r"\b(?:pay|payment|settle|transfer|remit)\b[^.\n]{0,60}?\b(?:fee|fees|charge|charges|duty|duties|aed|dhs?|dirhams?|amount|fine|fines)\b",
    r"\b(?:customs|delivery|shipping|redelivery|re-delivery|release|handling|clearance|processing|storage|unpaid)\s+(?:fee|fees|charge|charges|duty|duties)\b",
    r"\b(?:outstanding|unpaid|pending)\s+(?:balance|amount|payment|fine|fines|bill)\b",
    AR + r"(?:ادفع|دفع|سداد|تسديد)[^.\n]{0,40}?(?:رسوم|مبلغ|غرامة|درهم)",
    AR + r"رسوم\s*(?:التوصيل|الشحن|الجمارك|جمركية|التخليص|إعادة\s*التوصيل)",
)
DELIVERY = _rx(
    r"\b(?:parcel|package|shipment|consignment|courier|delivery|redelivery|tracking)\b[^.\n]{0,60}?"
    r"\b(?:held|hold|on\s+hold|pending|suspended|failed|unsuccessful|could\s+not|couldn'?t|unable|incomplete|"
    r"returned|awaiting|reschedul\w*|update|confirm)\b",
    r"\b(?:failed|unsuccessful|missed)\s+(?:delivery|delivery\s+attempt)\b",
    r"\b(?:address|delivery\s+address)\b[^.\n]{0,30}?\b(?:incomplete|incorrect|invalid|update|confirm)\b",
    AR + r"(?:الشحنة|شحنتك|الطرد|طردك|التوصيل)[^.\n]{0,40}?(?:معلق|متوقف|تعذر|فشل|محتجز|بانتظار|تحديث|تأكيد)",
    AR + r"تعذر\s*(?:توصيل|التوصيل)",
)
URGENCY = _rx(
    r"\b(?:urgent(?:ly)?|immediately|act\s+now|right\s+away|final\s+(?:notice|warning|reminder)|last\s+(?:chance|warning)|"
    r"within\s+\d{1,3}\s*(?:hours?|hrs?|h|minutes?|mins?|days?)|today\s+only|expires?\s+(?:today|soon|in)|"
    r"(?:will\s+be|has\s+been|have\s+been|is)\s+(?:suspended|blocked|deactivated|disabled|closed|locked|frozen|terminated|cancelled)|"
    r"legal\s+action|arrest\s+warrant|penalt(?:y|ies))\b",
    AR + r"(?:عاجل|فورا|فوراً|حالا|حالاً|إنذار\s*نهائي|آخر\s*فرصة|خلال\s*\d{1,3}\s*(?:ساعة|ساعات|دقيقة|يوم|أيام)|"
    r"سيتم\s*(?:إيقاف|ايقاف|حظر|إغلاق|اغلاق|تجميد|تعليق|إلغاء)|تم\s*(?:إيقاف|ايقاف|حظر|تعليق|تجميد)|إجراء\s*قانوني)",
    r"\b(?:3ajel|fawran)\b",
)


def _excerpt(text: str, match: re.Match[str], pad: int = 24) -> str:
    start, end = max(0, match.start() - pad), min(len(text), match.end() + pad)
    snippet = text[start:end].strip()
    return ("…" if start > 0 else "") + re.sub(r"\s+", " ", snippet) + ("…" if end < len(text) else "")


def _host(url: str) -> str:
    candidate = url if "://" in url else f"http://{url}"
    try:
        return (urlsplit(candidate).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _mention(folded_text: str, alias: str) -> re.Match[str] | None:
    folded = confusable_fold(alias)
    if not folded:
        return None
    if folded.isascii():
        return re.search(r"(?<![a-z0-9])" + re.escape(folded) + r"(?![a-z0-9])", folded_text)
    return re.search(r"(?<![؀-ۿ])" + re.escape(folded) + r"(?![؀-ۿ])", folded_text)


def named_entities(text: str, brands: Iterable[Mapping]) -> list[dict]:
    """Organisations named in the text (unambiguous names only)."""
    folded = confusable_fold(text or "")
    found: list[dict] = []
    for brand in brands:
        names = [str(brand.get("token", "")), *[str(a) for a in brand.get("aliases", [])]]
        for name in sorted(dict.fromkeys(n.lower() for n in names if n), key=len, reverse=True):
            if len(name) < 3 or name in AMBIGUOUS_NAMES:
                continue
            match = _mention(folded, name)
            if match:
                found.append({
                    "name": name,
                    "official_domain": str(brand.get("official_domain", "")).lower(),
                    "sector": str(brand.get("sector", "")),
                    "match": match,
                })
                break
    return found


def analyze_message(
    text: str,
    urls: list[str],
    brands: Iterable[Mapping],
) -> list[MessageSignal]:
    """Content signals for a message. ``urls`` are the links extracted from it."""
    text = text or ""
    signals: list[MessageSignal] = []
    if not text.strip():
        return signals

    cred = CREDENTIAL.search(text)
    if cred and CREDENTIAL_ASK.search(text):
        signals.append(MessageSignal(
            "message.credential_request", 0.35,
            "asks for a one-time code, password, card or bank details — legitimate organisations do not ask for these by message",
            _excerpt(text, cred), "phishing",
        ))

    pay = PAYMENT.search(text)
    if pay:
        signals.append(MessageSignal(
            "message.payment_demand", 0.25,
            "demands a payment or fee through the message",
            _excerpt(text, pay), "fraudulent_offer",
        ))

    delivery = DELIVERY.search(text)
    if delivery:
        signals.append(MessageSignal(
            "message.delivery_lure", 0.15,
            "parcel / delivery problem used as a lure",
            _excerpt(text, delivery), "suspicious_message",
        ))

    urgent = URGENCY.search(text)
    if urgent:
        signals.append(MessageSignal(
            "message.urgency_threat", 0.15,
            "pressure tactic: urgency, deadline or threat of suspension / penalty",
            _excerpt(text, urgent), "suspicious_message",
        ))

    hosts = [h for h in (_host(u) for u in urls) if h]
    entities = named_entities(text, brands)
    asks_credentials = any(sig.name == "message.credential_request" for sig in signals)
    if entities and not hosts and asks_credentials:
        entity = entities[0]
        government = entity["sector"] == "government"
        signals.append(MessageSignal(
            "message.impersonation_government" if government else "message.impersonation_brand",
            0.30,
            f"claims to be '{entity['name']}' and asks for credentials by message — {entity['official_domain']} "
            "never asks for codes or passwords this way",
            _excerpt(text, entity["match"]),
            "government_impersonation" if government else "brand_impersonation",
        ))
    if hosts and entities:
        for entity in entities:
            official = entity["official_domain"]
            foreign = [h for h in hosts if official and not is_official_host(h, official)]
            if foreign and len(foreign) == len(hosts):
                government = entity["sector"] == "government"
                signals.append(MessageSignal(
                    "message.impersonation_government" if government else "message.impersonation_brand",
                    0.30,
                    f"names '{entity['name']}' but the link goes to {foreign[0]}, not the official {official}",
                    _excerpt(text, entity["match"]),
                    "government_impersonation" if government else "brand_impersonation",
                ))
                break

    short = next((h for h in hosts if h in SHORTENERS or h.removeprefix("www.") in SHORTENERS), None)
    if short:
        signals.append(MessageSignal(
            "message.link_shortener", 0.15,
            f"link uses the shortener {short}, which hides the real destination",
            short, "suspicious_url",
        ))
    return signals


def has_action_channel(signals: Iterable[MessageSignal], urls: list[str]) -> bool:
    """A message can only be *confirmed* phishing if it gives the victim a way to act:
    a link, or a request to send credentials back."""
    return bool(urls) or any(s.name == "message.credential_request" for s in signals)
