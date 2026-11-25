"""Claim extraction and lexicon handling. Pure; no network, no clock."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from . import normalize
from .models import Claim
from .registry import Registry

DEFAULT_LEXICON_PATH = Path(__file__).resolve().with_name("lexicon.yaml")
_ARABIC = re.compile(r"[؀-ۿ]")
_LATIN = re.compile(r"[a-zA-Z]")
_SENTENCE = re.compile(r"(?<=[.!?؟。])\s+|\n+")
MAX_CLAIM_CHARS = 2000


@dataclass(frozen=True)
class Lexicon:
    version: int
    categories: dict[str, tuple[str, ...]]
    concepts: dict[str, tuple[str, ...]]
    government_terms: tuple[str, ...]
    denial_markers: tuple[str, ...]
    supersession_markers: tuple[str, ...]
    regulated_categories: frozenset[str]
    generic_concepts: frozenset[str] = frozenset()

    @classmethod
    def from_mapping(cls, data: dict) -> "Lexicon":
        def both(value: dict | None) -> tuple[str, ...]:
            value = value or {}
            terms = [*value.get("en", []), *value.get("ar", [])]
            return tuple(dict.fromkeys(str(term) for term in terms if str(term).strip()))

        categories = {str(name): both(terms) for name, terms in (data.get("categories") or {}).items()}
        concepts = {str(name): both(terms) for name, terms in (data.get("concepts") or {}).items()}
        if not categories or not concepts:
            raise ValueError("lexicon needs categories and concepts")
        for name, terms in [*categories.items(), *concepts.items()]:
            if not terms:
                raise ValueError(f"lexicon group '{name}' is empty")
        regulated = frozenset(str(item) for item in data.get("regulated_categories") or ())
        unknown = regulated - set(categories)
        if unknown:
            raise ValueError(f"regulated_categories not defined as categories: {sorted(unknown)}")
        generic = frozenset(str(item) for item in data.get("generic_concepts") or ())
        if generic - set(concepts):
            raise ValueError(f"generic_concepts not defined as concepts: {sorted(generic - set(concepts))}")
        return cls(
            generic_concepts=generic,
            version=int(data.get("version", 1)),
            categories=categories,
            concepts=concepts,
            government_terms=both(data.get("government_terms")),
            denial_markers=both(data.get("denial_markers")),
            supersession_markers=both(data.get("supersession_markers")),
            regulated_categories=regulated,
        )

    @classmethod
    def load(cls, path: Path | str | None = None) -> "Lexicon":
        target = Path(path) if path else DEFAULT_LEXICON_PATH
        return cls.from_mapping(yaml.safe_load(target.read_text(encoding="utf-8")) or {})

    # ---- matching

    @staticmethod
    def _hits(key: str, groups: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
        return tuple(name for name, terms in groups.items() if any(normalize.contains_phrase(key, t) for t in terms))

    def categories_in(self, text: str) -> tuple[str, ...]:
        return self._hits(normalize.match_key(text), self.categories)

    def concepts_in(self, text: str) -> tuple[str, ...]:
        return self._hits(normalize.match_key(text), self.concepts)

    def any_term(self, text: str, terms: tuple[str, ...]) -> bool:
        key = normalize.match_key(text)
        return any(normalize.contains_phrase(key, term) for term in terms)

    def mentions_government(self, text: str) -> bool:
        return self.any_term(text, self.government_terms)

    def is_denial(self, text: str) -> bool:
        return self.any_term(text, self.denial_markers)

    def is_supersession(self, text: str) -> bool:
        return self.any_term(text, self.supersession_markers)


def strip_entity_names(text: str, registry: Registry) -> str:
    """Remove organization names/aliases so 'Ministry of Social *Support*' is not read as a
    'support' concept. Returns a match_key()-normalized string."""
    key = " " + " ".join(normalize.tokens(text)) + " "
    for entry in registry.resolve_entities(text):
        for alias in sorted(entry.all_aliases, key=len, reverse=True):
            alias_key = " ".join(normalize.tokens(alias))
            if alias_key:
                key = key.replace(f" {alias_key} ", " ")
    return key.strip()


def detect_language(text: str) -> str:
    arabic = len(_ARABIC.findall(text or ""))
    latin = len(_LATIN.findall(text or ""))
    if arabic and latin:
        return "ar" if arabic >= latin else "en"
    return "ar" if arabic else "en"


def _focus(text: str, lexicon: Lexicon) -> str:
    """Pick the sentences that carry a category term; keeps claims short and specific."""
    sentences = [part.strip() for part in _SENTENCE.split(text or "") if part and part.strip()]
    keep = [s for s in sentences if lexicon.categories_in(s)]
    return " ".join(keep or sentences)[:MAX_CLAIM_CHARS]


def extract_claim(text: str, registry: Registry, lexicon: Lexicon) -> Claim:
    """Steps 1–4: extract the claim, identify the entity, resolve aliases, classify."""
    raw = (text or "")[:MAX_CLAIM_CHARS * 2]
    focused = _focus(raw, lexicon)
    canonical = normalize.normalize_text(focused)
    entities = registry.resolve_entities(raw)
    # Independent media mentioned in the text is a reporter, not the claimed entity.
    claimed = [entry for entry in entities if entry.source_class not in ("C", "P")]  # never government
    amounts = tuple(sorted({amount.aed for amount in normalize.extract_amounts(focused)}))
    topic_text = strip_entity_names(focused, registry)
    return Claim(
        raw=raw,
        canonical=canonical,
        entity_ids=tuple(entry.id for entry in claimed),
        entity_names=tuple(entry.organization for entry in claimed),
        generic_government=lexicon.mentions_government(raw),
        categories=lexicon.categories_in(topic_text),
        concepts=lexicon.concepts_in(topic_text),
        amounts_aed=amounts,
        dates=tuple(normalize.extract_dates(focused)),
        language=detect_language(raw),
    )
