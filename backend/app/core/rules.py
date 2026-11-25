"""Loader for ``rules.yaml`` — the detection rules as DATA (lists of patterns, never verdicts)."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import yaml

RULES_FILE = Path(__file__).with_name("rules.yaml")
REQUIRED = ("risky_tlds", "giveaway_words", "generic_labels", "government_zones", "confusables",
            "fallback_multi_suffixes", "form_fields", "established_site")


@lru_cache(maxsize=1)
def rules() -> dict:
    data = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8")) or {}
    missing = [key for key in REQUIRED if key not in data]
    if missing:
        raise RuntimeError(f"{RULES_FILE}: missing sections {missing}")
    return data


def words_regex(phrases_en: list[str], words_ar: list[str]) -> re.Pattern:
    en = "|".join(re.escape(str(p)).replace(r"\ ", r"\s+") for p in phrases_en)
    ar = "|".join(re.escape(str(w)) for w in words_ar)
    return re.compile(rf"\b(?:{en})\b" + (f"|(?:{ar})" if ar else ""), re.I)


def any_regex(patterns: list[str]) -> re.Pattern:
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.I)
