"""Government-claim verification engine (pure).

It consumes PRE-FETCHED ``OfficialRecord`` objects and returns a verification
status plus evidence. It never fetches, never reads the clock (``now`` is a
parameter), and never produces a website verdict — that is the trust policy's
job (``channels.trust_policy``).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from . import POLICY_VERSION
from .compare import CONTRADICTS, RELATED, SUPPORTS, UNRELATED, compare
from .extract import Lexicon, extract_claim
from .models import (
    CLASS_A,
    CLASS_B,
    CLASS_C,
    CONFLICTING_SOURCES,
    CONTRADICTED,
    NOT_VERIFIABLE,
    SOURCE_EXPIRED,
    SOURCE_UNAVAILABLE,
    VERIFIED,
    Claim,
    EvidenceItem,
    GovVerification,
    OfficialRecord,
    RegistryEntry,
    iso,
    parse_ts,
    sha256_text,
)
from .registry import Registry, host_matches_entry, parse_target

EVIDENCE_MAX_AGE_DAYS = 30
_CLASS_RANK = {CLASS_A: 2, CLASS_B: 1, CLASS_C: 0}


@dataclass
class _Scored:
    record: OfficialRecord
    entry: RegistryEntry
    result: str
    detail: str
    excerpt: str
    role: str = "decisive"
    attributes: dict | None = None


# ---------------------------------------------------------------- selection


def _jurisdictions(claim: Claim, registry: Registry) -> set[str]:
    return {registry.by_id[eid].jurisdiction for eid in claim.entity_ids if eid in registry.by_id}


def _compatible(entry: RegistryEntry, claim_jurisdictions: set[str]) -> bool:
    if not claim_jurisdictions:
        return True
    return entry.jurisdiction == "federal" or entry.jurisdiction in claim_jurisdictions or bool(
        claim_jurisdictions & {"federal"}
    )


def select_sources(claim: Claim, registry: Registry, now: datetime) -> tuple[list[RegistryEntry], list[str]]:
    """Step 5: approved+fresh sources relevant by entity, jurisdiction and authority scope."""
    notes: list[str] = []
    juris = _jurisdictions(claim, registry)
    selected: dict[str, RegistryEntry] = {}
    for entity_id in claim.entity_ids:
        entry = registry.by_id[entity_id]
        if entry.is_trusted(now):
            selected[entry.id] = entry
        else:
            notes.append(
                f"{entry.organization} is named but its registry entry is {entry.status}"
                + ("" if entry.status != "approved" else " and stale")
                + "; it was not used as evidence"
            )
    for entry in registry.trusted(now):
        if entry.id in selected or not _compatible(entry, juris):
            continue
        if entry.source_class == CLASS_A and set(entry.authority_scope) & set(claim.categories):
            selected[entry.id] = entry
        elif entry.source_class in (CLASS_B, CLASS_C):
            selected[entry.id] = entry
    return list(selected.values()), notes


# ---------------------------------------------------------------- helpers


def _record_ok_for_entry(record: OfficialRecord, entry: RegistryEntry) -> bool:
    host, problem = parse_target(record.url)
    return bool(host) and problem is None and host_matches_entry(host, entry)


def _is_fresh(record: OfficialRecord, now: datetime, max_age_days: int) -> bool:
    retrieved = parse_ts(record.retrieved_at)
    if retrieved is None:
        return False
    age = (now - retrieved).total_seconds() / 86400
    return -0.01 <= age <= max_age_days


def _evidence(scored: _Scored, role: str | None = None) -> EvidenceItem:
    return EvidenceItem(
        role=role or scored.role,
        comparison=scored.result,
        source_class=scored.entry.source_class,
        entry_id=scored.entry.id,
        organization=scored.entry.organization,
        source_url=scored.record.url,
        published_at=scored.record.published_at,
        retrieved_at=scored.record.retrieved_at,
        excerpt=scored.excerpt,
        content_hash=scored.record.content_hash,
        detail=scored.detail,
        synthetic=scored.record.synthetic,
        attributes=scored.attributes,
    )


def evidence_id(canonical_claim: str, content_hashes: Iterable[str], registry_version: str, policy_version: str) -> str:
    material = "|".join([canonical_claim, *sorted(set(content_hashes)), registry_version, policy_version])
    return "gv_" + sha256_text(material)[:24]


def _resolve_supersession(decisive: list[_Scored]) -> tuple[list[_Scored], list[_Scored]]:
    """Newer equal-or-higher-class records supersede older ones that disagree."""
    dated = [s for s in decisive if parse_ts(s.record.published_at)]
    if len({s.result for s in decisive}) < 2 or not dated:
        return decisive, []
    newest = max(dated, key=lambda s: (parse_ts(s.record.published_at), _CLASS_RANK[s.entry.source_class]))
    newest_ts = parse_ts(newest.record.published_at)
    current: list[_Scored] = []
    superseded: list[_Scored] = []
    for item in decisive:
        ts = parse_ts(item.record.published_at)
        if (
            item.result != newest.result
            and ts is not None
            and ts < newest_ts  # type: ignore[operator]
            and _CLASS_RANK[newest.entry.source_class] >= _CLASS_RANK[item.entry.source_class]
        ):
            item.role = "superseded"
            superseded.append(item)
        else:
            current.append(item)
    return current, superseded


# ---------------------------------------------------------------- engine


def verify_claim(
    text_or_claim: str | Claim,
    *,
    registry: Registry,
    lexicon: Lexicon,
    records: Iterable[OfficialRecord],
    now: datetime,
    policy_version: str = POLICY_VERSION,
    evidence_max_age_days: int = EVIDENCE_MAX_AGE_DAYS,
) -> GovVerification:
    claim = text_or_claim if isinstance(text_or_claim, Claim) else extract_claim(text_or_claim, registry, lexicon)
    notes: list[str] = []

    def result(status: str, evidence: list[EvidenceItem], checked: list[str], unchecked: list[str],
               relevant: list[str], hashes: list[str]) -> GovVerification:
        return GovVerification(
            status=status,
            claim=claim,
            evidence=tuple(evidence),
            checked_sources=tuple(checked),
            unchecked_sources=tuple(unchecked),
            relevant_sources=tuple(relevant),
            notes=tuple(dict.fromkeys(notes)),
            evidence_id=evidence_id(claim.canonical, hashes, registry.version, policy_version),
            registry_version=registry.version,
            policy_version=policy_version,
            verified_at=iso(now) or "",
        )

    if not claim.is_government_claim:
        notes.append("no government claim (entity + claim category) was detected; nothing was checked")
        return result(NOT_VERIFIABLE, [], [], [], [], [])

    sources, selection_notes = select_sources(claim, registry, now)
    notes.extend(selection_notes)
    relevant_ids = [entry.id for entry in sources]
    if not sources:
        notes.append("no approved, current official source in the registry covers this claim; nothing was checked")
        return result(NOT_VERIFIABLE, [], [], [], [], [])

    by_entry: dict[str, list[OfficialRecord]] = {entry.id: [] for entry in sources}
    for record in records:
        if record.entry_id in by_entry:
            by_entry[record.entry_id].append(record)

    checked: list[str] = []
    unchecked: list[str] = []
    expired_only: list[str] = []
    scored: list[_Scored] = []
    hashes: list[str] = []
    evidence: list[EvidenceItem] = []

    for entry in sources:
        entry_records = by_entry[entry.id]
        good = [r for r in entry_records if r.fetch_status == "ok" and _record_ok_for_entry(r, entry)]
        for bad in entry_records:
            if bad.fetch_status == "ok" and bad not in good:
                notes.append(f"record {bad.record_id} ignored: URL is outside {entry.organization}'s approved domains")
        failed = [r for r in entry_records if r.fetch_status != "ok"]
        fresh = [r for r in good if _is_fresh(r, now, evidence_max_age_days)]
        if not fresh:
            unchecked.append(entry.id)
            if good:
                expired_only.append(entry.id)
                notes.append(f"{entry.organization}: evidence older than {evidence_max_age_days} days; not checked")
            elif failed:
                errors = ", ".join(sorted({str(r.fetch_error or "error") for r in failed}))
                notes.append(f"{entry.organization}: source could not be retrieved ({errors}); not checked")
            else:
                notes.append(f"{entry.organization}: no retrieved records available; not checked")
            continue
        checked.append(entry.id)
        for record in fresh:
            comparison = compare(claim, record, entry, registry, lexicon)
            if comparison.result == UNRELATED:
                continue
            hashes.append(record.content_hash)
            item = _Scored(record, entry, comparison.result, comparison.detail, comparison.excerpt,
                           attributes=comparison.attributes)
            if entry.source_class == CLASS_C:
                item.role = "supporting_context"
            elif comparison.result == RELATED:
                item.role = "related"
            scored.append(item)

    supporting = [s for s in scored if s.role == "supporting_context"]
    related = [s for s in scored if s.role == "related"]
    decisive = [s for s in scored if s.role == "decisive" and s.result in (SUPPORTS, CONTRADICTS)]
    current, superseded = _resolve_supersession(decisive)
    class_a = [s for s in current if s.entry.source_class == CLASS_A]
    class_b = [s for s in current if s.entry.source_class == CLASS_B]

    def finish(status: str, decisive_items: list[_Scored]) -> GovVerification:
        items = [_evidence(s) for s in decisive_items]
        items += [_evidence(s, "superseded") for s in superseded]
        items += [_evidence(s) for s in related]
        items += [_evidence(s, "supporting_context") for s in supporting]
        if supporting:
            notes.append("Class C (independent media) material is supporting context only and did not decide the status")
        return result(status, items, checked, unchecked, relevant_ids, hashes)

    if superseded:
        notes.append("older official statements were superseded by a newer official source")

    regulated = bool(set(claim.categories) & lexicon.regulated_categories)
    # The responsible authority is the named Class A entity; only when no entity is
    # named do we fall back to Class A sources whose authority scope covers the claim.
    named_a = [e for e in sources if e.source_class == CLASS_A and e.id in claim.entity_ids]
    responsible_a = named_a or [
        e for e in sources if e.source_class == CLASS_A and set(e.authority_scope) & set(claim.categories)
    ]

    # A claim about a NAMED authority is verified only by that authority (or a record naming it):
    # agreement from a different authority's record is not verification of someone else's claim.
    if claim.entity_ids and class_a and all(s.result == SUPPORTS for s in class_a) and all(
            (s.attributes or {}).get("authority") == "differs" for s in class_a):
        notes.append("only a different authority's record agreed with the claim; the named authority's own "
                     "statement was not found — not verified")
        return finish(NOT_VERIFIABLE, class_a)

    if class_a:
        stances = {s.result for s in class_a}
        if len(stances) > 1:
            notes.append("approved Class A sources disagree; manual review required")
            return finish(CONFLICTING_SOURCES, class_a + class_b)
        stance = stances.pop()
        if any(s.result != stance for s in class_b):
            notes.append("official media disagreed with the primary authority; the primary authority prevails")
        return finish(VERIFIED if stance == SUPPORTS else CONTRADICTED, class_a + class_b)

    if class_b:
        stances = {s.result for s in class_b}
        if len(stances) > 1:
            notes.append("approved official media sources disagree; manual review required")
            return finish(CONFLICTING_SOURCES, class_b)
        stance = stances.pop()
        if stance == CONTRADICTS:
            return finish(CONTRADICTED, class_b)
        if regulated and responsible_a:
            a_checked = [e for e in responsible_a if e.id in checked]
            notes.append(
                "an official media publication alone cannot establish the legal or current validity of this "
                "claim while the responsible primary authority is available"
            )
            if a_checked:
                return finish(NOT_VERIFIABLE, class_b)
            return finish(SOURCE_UNAVAILABLE, class_b)
        notes.append("verified through an official government media publication (Class B)")
        return finish(VERIFIED, class_b)

    # Nothing decisive.
    if not checked:
        responsible_stale = bool(responsible_a) and all(e.id in expired_only for e in responsible_a)
        all_stale = bool(expired_only) and len(expired_only) == len(unchecked)
        return finish(SOURCE_EXPIRED if (responsible_stale or all_stale) else SOURCE_UNAVAILABLE, [])
    responsible_unchecked = [e for e in responsible_a if e.id in unchecked]
    if responsible_unchecked:
        notes.append("the responsible authority could not be checked")
        status = SOURCE_EXPIRED if all(e.id in expired_only for e in responsible_unchecked) else SOURCE_UNAVAILABLE
        return finish(status, [])
    names = ", ".join(
        registry.by_id[i].organization for i in checked if registry.by_id[i].source_class != CLASS_C
    ) or "only independent media"
    notes.append(f"checked {names}: no matching official statement found")
    return finish(NOT_VERIFIABLE, [])
