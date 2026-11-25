"""Deterministic claim ↔ official-record comparison. Pure; no network, no clock."""
from __future__ import annotations

import re
from pathlib import Path

import yaml
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
    # per-attribute outcome: match | differs | not_stated | not_compared
    attributes: dict | None = None


# Places named in a claim → registry jurisdiction ids (EN + AR) — data: lexicon.yaml "places".
PLACES = {str(name): str(juris) for juris, names in
          (yaml.safe_load(Path(__file__).with_name("lexicon.yaml").read_text(encoding="utf-8")).get("places") or {}).items()
          for name in names}


def claim_jurisdictions(claim: Claim, registry: Registry) -> set[str]:
    out = {registry.by_id[e].jurisdiction for e in claim.entity_ids if e in registry.by_id}
    key = normalize.match_key(claim.raw)
    for place, juris in PLACES.items():
        if normalize.contains_phrase(key, normalize.match_key(place)):
            out.add(juris)
    return {j for j in out if j}


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

    # --- relevance: right ISSUING AUTHORITY, right JURISDICTION, same topic
    named_by_claim = entry.id in claim.entity_ids
    mentions = _mentions_entity(record, claim, registry)
    if claim.entity_ids:
        # The claim names a specific authority. Its own records and records naming it are compared;
        # another Class A authority responsible for the same subject is compared too (it may
        # CONTRADICT the claim), but verify.py never lets it VERIFY a claim about a different
        # authority on its own (attributes.authority == "differs").
        entity_ok = (named_by_claim or mentions
                     or (entry.source_class == "A" and bool(set(entry.authority_scope) & set(claim.categories))))
    else:
        entity_ok = (
            (entry.source_class == "A" and bool(set(entry.authority_scope) & set(claim.categories)))
            or entry.source_class in ("B", "C")
        )
    claim_juris = claim_jurisdictions(claim, registry) - {"federal"}
    juris_ok = not claim_juris or entry.jurisdiction == "federal" or entry.jurisdiction in claim_juris
    attributes = {
        "authority": "match" if named_by_claim or mentions else ("not_stated" if not claim.entity_ids else "differs"),
        "jurisdiction": ("not_stated" if not claim_juris else "match" if juris_ok else "differs"),
        "service": "not_compared", "amount": "not_compared", "effective_date": "not_compared",
    }
    if not juris_ok:
        excerpt = _excerpt(record, lexicon, record_concepts)
        return Comparison(UNRELATED, f"different jurisdiction (claim: {', '.join(sorted(claim_juris))}; "
                          f"source: {entry.jurisdiction})", excerpt, tuple(sorted(record_concepts)),
                          record_amounts, record_denies, attributes)
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
        why = "different issuing authority" if not entity_ok else "different subject"
        attributes["service"] = "match" if topical else "differs"
        return Comparison(UNRELATED, why, excerpt, tuple(sorted(record_concepts)), record_amounts, record_denies,
                          attributes)
    attributes["service"] = "match"

    # --- effective date: when the claim states a date, the source must state the same one
    claim_dates = set(claim.dates)
    record_dates = set(normalize.extract_dates(text))
    if claim_dates and record_dates:
        attributes["effective_date"] = "match" if claim_dates & record_dates else "differs"
    elif claim_dates:
        attributes["effective_date"] = "not_stated"
    if claim.amounts_aed:
        attributes["amount"] = "not_stated" if not record_amounts else (
            "match" if set(claim.amounts_aed) & set(record_amounts) else "differs")

    # --- stance: does the record affirm or deny the same thing the claim asserts?
    claim_denies = lexicon.is_denial(claim.raw)
    if record_denies != claim_denies:
        detail = (
            "source denies or warns against this claim"
            if record_denies
            else "source affirms what the claim denies"
        )
        return Comparison(CONTRADICTS, detail, excerpt, tuple(sorted(record_concepts)), record_amounts, record_denies,
                          attributes)

    if attributes["effective_date"] == "differs" and not record_denies:
        detail = ("effective date not confirmed: claim " + ", ".join(sorted(claim_dates)) +
                  "; source " + ", ".join(sorted(record_dates)[:3]))
        return Comparison(RELATED, detail, excerpt, tuple(sorted(record_concepts)), record_amounts, record_denies,
                          attributes)

    if not record_denies and claim.amounts_aed and record_amounts:
        claimed = set(claim.amounts_aed)
        official = set(record_amounts)
        if claimed & official:
            detail = f"amount matches source figure (AED {sorted(claimed & official)[0]:,.2f})"
            return Comparison(SUPPORTS, detail, excerpt, tuple(sorted(record_concepts)), record_amounts, record_denies,
                              attributes)
        detail = (
            "amount differs: claim AED "
            + ", ".join(f"{v:,.2f}" for v in sorted(claimed))
            + "; source AED "
            + ", ".join(f"{v:,.2f}" for v in sorted(official))
        )
        return Comparison(CONTRADICTS, detail, excerpt, tuple(sorted(record_concepts)), record_amounts, record_denies,
                          attributes)

    if shared or not claim_topics:
        topics = ", ".join(sorted(shared)) or ", ".join(sorted(set(claim.categories) & record_categories))
        return Comparison(
            SUPPORTS,
            f"source states the same ({topics})",
            excerpt,
            tuple(sorted(record_concepts)),
            record_amounts,
            record_denies,
            attributes,
        )
    return Comparison(RELATED, "related but not decisive", excerpt, tuple(sorted(record_concepts)), record_amounts,
                      record_denies, attributes)
