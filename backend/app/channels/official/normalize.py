"""Bilingual (Arabic / English) normalization. Pure functions, no I/O."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import date

# --------------------------------------------------------------------- Arabic

_DIACRITICS = re.compile("[ؐ-ًؚ-ٰٟۖ-ۜ۟-۪ۨ-ۭ]")
_TATWEEL = "ـ"
_ALEF_FORMS = str.maketrans({"أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا"})
_YA_FORMS = str.maketrans({"ى": "ي", "ی": "ي"})
_TA_MARBUTA = str.maketrans({"ة": "ه"})
_DIGITS = str.maketrans(
    "٠١٢٣٤٥٦٧٨٩"
    "۰۱۲۳۴۵۶۷۸۹",
    "0123456789" * 2,
)
# Arabic decimal separator and thousands separator.
_SEPARATORS = str.maketrans({"٫": ".", "٬": ",", "،": ","})
_WS = re.compile(r"\s+")
_TOKEN = re.compile(r"[0-9a-zء-ي]+")


def strip_diacritics(text: str) -> str:
    return _DIACRITICS.sub("", text or "")


def strip_tatweel(text: str) -> str:
    return (text or "").replace(_TATWEEL, "")


def normalize_digits(text: str) -> str:
    return (text or "").translate(_DIGITS).translate(_SEPARATORS)


def normalize_arabic(text: str) -> str:
    """Diacritics + tatweel removal, Alef and Ya unification, digit normalization."""
    value = unicodedata.normalize("NFKC", text or "")
    value = strip_tatweel(strip_diacritics(value))
    value = value.translate(_ALEF_FORMS).translate(_YA_FORMS)
    return normalize_digits(value)


def normalize_text(text: str) -> str:
    """Canonical display-independent form used for claims and comparisons."""
    value = normalize_arabic(text).casefold()
    return _WS.sub(" ", value).strip()


def match_key(text: str) -> str:
    """Looser key for alias matching only (also folds Ta Marbuta → Ha)."""
    return normalize_text(text).translate(_TA_MARBUTA)


def tokens(text: str) -> list[str]:
    return _TOKEN.findall(match_key(text))


def contains_phrase(haystack_key: str, phrase: str) -> bool:
    """Whole-token phrase match on match_key() forms (works for Arabic and Latin)."""
    needle = " ".join(tokens(phrase))
    if not needle:
        return False
    hay = " " + " ".join(_TOKEN.findall(haystack_key)) + " "
    if f" {needle} " in hay:
        return True
    # Arabic proclitics: و (and), ب (by/with), ل (for), ال (the) glued to the word.
    if re.search(r"[ء-ي]", needle):
        for prefix in ("و", "ب", "ل", "ال", "وال", "بال", "لل", "ف"):
            if f" {prefix}{needle} " in hay:
                return True
    return False


# ---------------------------------------------------------------------- dates

_EN_MONTHS = {
    "january": 1, "jan": 1, "february": 2, "feb": 2, "march": 3, "mar": 3,
    "april": 4, "apr": 4, "may": 5, "june": 6, "jun": 6, "july": 7, "jul": 7,
    "august": 8, "aug": 8, "september": 9, "sep": 9, "sept": 9, "october": 10,
    "oct": 10, "november": 11, "nov": 11, "december": 12, "dec": 12,
}
_AR_MONTHS = {
    "يناير": 1, "فبراير": 2, "مارس": 3, "ابريل": 4, "مايو": 5, "يونيو": 6,
    "يوليو": 7, "اغسطس": 8, "سبتمبر": 9, "اكتوبر": 10, "نوفمبر": 11, "ديسمبر": 12,
    "كانون الثاني": 1, "شباط": 2, "اذار": 3, "نيسان": 4, "ايار": 5, "حزيران": 6,
    "تموز": 7, "اب": 8, "ايلول": 9, "تشرين الاول": 10, "تشرين الثاني": 11, "كانون الاول": 12,
}
_MONTH_ALT = "|".join(
    sorted((re.escape(name) for name in [*_EN_MONTHS, *_AR_MONTHS]), key=len, reverse=True)
)
_ISO_DATE = re.compile(r"\b(\d{4})-(\d{1,2})-(\d{1,2})\b")
_DMY_DATE = re.compile(r"\b(\d{1,2})[/.-](\d{1,2})[/.-](\d{4})\b")
_D_MONTH_Y = re.compile(rf"\b(\d{{1,2}})\s+({_MONTH_ALT})\.?,?\s+(\d{{4}})\b")
_MONTH_D_Y = re.compile(rf"\b({_MONTH_ALT})\.?\s+(\d{{1,2}}),?\s+(\d{{4}})\b")


def _month(name: str) -> int | None:
    key = name.strip(". ").casefold()
    return _EN_MONTHS.get(key) or _AR_MONTHS.get(key)


def _safe_date(year: int, month: int, day: int) -> str | None:
    try:
        return date(year, month, day).isoformat()
    except ValueError:
        return None


def extract_dates(text: str) -> list[str]:
    """ISO dates mentioned in EN/AR text. Day-first for numeric forms (UAE usage)."""
    value = normalize_text(text)
    found: list[str] = []

    def add(item: str | None) -> None:
        if item and item not in found:
            found.append(item)

    for y, m, d in _ISO_DATE.findall(value):
        add(_safe_date(int(y), int(m), int(d)))
    for d, m, y in _DMY_DATE.findall(value):
        add(_safe_date(int(y), int(m), int(d)))
    for d, mon, y in _D_MONTH_Y.findall(value):
        month = _month(mon)
        if month:
            add(_safe_date(int(y), month, int(d)))
    for mon, d, y in _MONTH_D_Y.findall(value):
        month = _month(mon)
        if month:
            add(_safe_date(int(y), month, int(d)))
    return found


# -------------------------------------------------------------------- amounts

USD_TO_AED = 3.6725  # fixed central-bank peg, stable since 1997

_NUM = r"\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?"
_MULT = r"million|mn|m|thousand|k|bn|billion|مليون|ملايين|الف|آلاف|الاف|مليار"
_AED = r"aed|dhs|dh|dirhams?|درهم|دراهم|د\.ا"
_USD = r"usd|us\$|\$|dollars?|دولار"
_AMOUNT_AFTER = re.compile(
    rf"(?<![\w.])({_NUM})\s*({_MULT})?\s*({_AED}|{_USD})(?![a-z])", re.I
)
_AMOUNT_BEFORE = re.compile(
    rf"({_AED}|{_USD})\s*({_NUM})\s*({_MULT})?(?![a-z])", re.I
)
_BARE_MULT_AED = re.compile(rf"(?<![\d\w])(مليون|million)\s*({_AED})", re.I)
_MULTIPLIERS = {
    "million": 1_000_000, "mn": 1_000_000, "m": 1_000_000, "مليون": 1_000_000, "ملايين": 1_000_000,
    "thousand": 1_000, "k": 1_000, "الف": 1_000, "آلاف": 1_000, "الاف": 1_000,
    "bn": 1_000_000_000, "billion": 1_000_000_000, "مليار": 1_000_000_000,
}


@dataclass(frozen=True)
class Amount:
    aed: float
    original: str
    currency: str
    converted: bool = False

    def as_dict(self) -> dict:
        return {"aed": self.aed, "original": self.original, "currency": self.currency, "converted": self.converted}


def _to_float(number: str) -> float:
    return float(number.replace(",", ""))


def _make(number: str, mult: str | None, currency: str, original: str) -> Amount:
    value = _to_float(number) * _MULTIPLIERS.get((mult or "").casefold(), 1)
    is_usd = bool(re.fullmatch(_USD, currency, re.I))
    if is_usd:
        return Amount(round(value * USD_TO_AED, 2), original.strip(), "USD", True)
    return Amount(round(value, 2), original.strip(), "AED", False)


def extract_amounts(text: str) -> list[Amount]:
    """Monetary amounts normalized to AED (USD converted at the fixed peg)."""
    value = normalize_text(text)
    found: dict[float, Amount] = {}
    for match in _AMOUNT_AFTER.finditer(value):
        amount = _make(match.group(1), match.group(2), match.group(3), match.group(0))
        found.setdefault(amount.aed, amount)
    for match in _AMOUNT_BEFORE.finditer(value):
        amount = _make(match.group(2), match.group(3), match.group(1), match.group(0))
        found.setdefault(amount.aed, amount)
    for match in _BARE_MULT_AED.finditer(value):
        amount = _make("1", match.group(1), match.group(2), match.group(0))
        found.setdefault(amount.aed, amount)
    return list(found.values())
