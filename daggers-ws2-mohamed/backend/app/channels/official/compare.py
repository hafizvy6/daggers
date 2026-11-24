"""Deterministic claim ↔ official-record comparison. Pure; no network, no clock."""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import normalize
from .extract import Lexicon, strip_entity_names
from .models import Claim, OfficialRecord, RegistryEntry
from .registry import Registry

SUPPORTS = "supports"
CONTRADICTS = "contradicts"
RELATED = "related"
UNRELATED = "unrelated"

_NON_TOPICAL = frozenset({"fraud"})  # every denial mentions fraud; it is not a topic
_SENTENCES = re.compile(r"(?<=[.!?؟])\s+|\n+")
EXCERPT_CHARS = 280


@dataclass(frozen=True)
class Comparison:
    result: str
    detail: str
    excerpt: str
    record_concepts: tuple[str, ...]
    record_amounts_aed: tuple[float, ...]
    record_denies: bool


def _excerpt(record: OfficialRecord, lexicon: Lexicon, concepts: set[str]) -> str:
    """A verbatim sentence from the record containing an overlapping concept term."""
    sentences = [s.strip() for s in _SENTENCES.split(record.content) if s.strip()]
    for sentence in sentences:
        if set(lexicon.concepts_in(sentence)) & concepts:
            return sentence[:EXCERPT_CHARS]
    return (sentences[0] if sentences else record.content)[:EXCERPT_CHARS]


def _mentions_entity(record: OfficialRecord, claim: Claim, registry: Registry) -> bool:
    if not claim.entity_ids:
        return False
    named = {entry.id for entry in registry.resolve_entities(f"{record.title} {record.content}")}
    return bool(named & set(claim.entity_ids))


def compare(
    claim: Claim,
    record: OfficialRecord,
    entry: RegistryEntry,
    registry: Registry,
    lexicon: Lexicon,
) -> Comparison:
    text = f"{record.title}. {record.content}"
    topic_text = strip_entity_names(text, registry)
    record_concepts = set(lexicon.concepts_in(topic_text))
    record_categories = set(lexicon.categories_in(topic_text))
    record_amounts = tuple(sorted({a.aed for a in normalize.extract_amounts(text)}))
    record_denies = lexicon.is_denial(text)

    # --- relevance: right entity / authority AND same topic
    entity_ok = (
        entry.id in claim.entity_ids
        or _mentions_entity(record, claim, registry)
        or (entry.source_class == "A" and bool(set(entry.authority_scope) & set(claim.categories)))
        or (not claim.entity_ids and entry.source_class == "B")
    )
    claim_topics = set(claim.concepts) - _NON_TOPICAL
    record_topics = record_concepts - _NON_TOPICAL
    if claim_topics:
        shared = claim_topics & record_topics
        claim_specific = claim_topics - lexicon.generic_concepts
        record_specific = record_topics - lexicon.generic_concepts
        if claim_specific or record_specific:
            # When either side names a specific subject (amnesty, golden visa, housing …),
            # they must share one; a broad overlap such as 'visa' is not enough.
            topical = bool(shared - lexicon.generic_concepts) and (
                not claim_specific or bool(claim_specific & record_specific)
            )
        else:
            topical = bool(shared)
    else:
        shared = set()
        topical = bool(set(claim.categories) & record_categories)
    excerpt = _excerpt(record, lexicon, shared or record_topics)
    if not (entity_ok and topical):
        why = "different entity/authority" if not entity_ok else "different subject"
        return Comparison(UNRELATED, why, excerpt, tuple(sorted(record_concepts)), record_amounts, record_denies)

    # --- stance: does the record affirm or deny the same thing the claim asserts?
    claim_denies = lexicon.is_denial(claim.raw)
    if record_denies != claim_denies:
        detail = (
            "source denies or warns against this claim"
            if record_denies
            else "source affirms what the claim denies"
        )
        return Comparison(CONTRADICTS, detail, excerpt, tuple(sorted(record_concepts)), record_amounts, record_denies)

    if not record_denies and claim.amounts_aed and record_amounts:
        claimed = set(claim.amounts_aed)
        official = set(record_amounts)
        if claimed & official:
            detail = f"amount matches source figure (AED {sorted(claimed & official)[0]:,.2f})"
            return Comparison(SUPPORTS, detail, excerpt, tuple(sorted(record_concepts)), record_amounts, record_denies)
        detail = (
            "amount differs: claim AED "
            + ", ".join(f"{v:,.2f}" for v in sorted(claimed))
            + "; source AED "
            + ", ".join(f"{v:,.2f}" for v in sorted(official))
        )
        return Comparison(CONTRADICTS, detail, excerpt, tuple(sorted(record_concepts)), record_amounts, record_denies)

    if shared or not claim_topics:
        topics = ", ".join(sorted(shared)) or ", ".join(sorted(set(claim.categories) & record_categories))
        return Comparison(
            SUPPORTS,
            f"source states the same ({topics})",
            excerpt,
            tuple(sorted(record_concepts)),
            record_amounts,
            record_denies,
        )
    return Comparison(RELATED, "related but not decisive", excerpt, tuple(sorted(record_concepts)), record_amounts, record_denies)
