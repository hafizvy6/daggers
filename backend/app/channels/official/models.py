"""Data model for the official UAE source registry and claim verification."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

# ----------------------------------------------------------------- vocabulary

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_REVOKED = "revoked"
ENTRY_STATUSES = (STATUS_PENDING, STATUS_APPROVED, STATUS_REVOKED)

CLASS_A = "A"  # primary authorities: ministries, police, departments, regulators
CLASS_B = "B"  # official government media: WAM, media offices
CLASS_C = "C"  # independent media: supporting context only
CLASS_P = "P"  # verified private / commercial organisation: legitimate site, NOT government
SOURCE_CLASSES = (CLASS_A, CLASS_B, CLASS_C, CLASS_P)
NON_GOVERNMENT_CLASSES = (CLASS_C, CLASS_P)

SUBDOMAIN_EXACT = "exact"      # only the listed hosts
SUBDOMAIN_LISTED = "listed"    # listed hosts + explicitly allowed subdomains
SUBDOMAIN_ANY = "any"          # any subdomain of a listed domain (needs reviewer intent)
SUBDOMAIN_POLICIES = (SUBDOMAIN_EXACT, SUBDOMAIN_LISTED, SUBDOMAIN_ANY)

JURISDICTIONS = (
    "federal", "abu_dhabi", "dubai", "sharjah", "ajman",
    "umm_al_quwain", "ras_al_khaimah", "fujairah", "synthetic",
)

# Domain-authentication statuses (separate from claim verification).
AUTH_AUTHENTICATED = "AUTHENTICATED"          # approved + fresh Class A/B
AUTH_INDEPENDENT_MEDIA = "INDEPENDENT_MEDIA"  # approved Class C: known outlet, NOT official
AUTH_VERIFIED_ORGANIZATION = "VERIFIED_ORGANIZATION"  # approved Class P: verified company, NOT official
AUTH_REPUTABLE_SITE = "REPUTABLE_SITE"      # NOT in the registry; widely used site (Tranco) — NOT official
AUTH_ESTABLISHED_SITE = "ESTABLISHED_SITE"  # NOT in the registry; old domain + live HTTPS page + no warning signs
LEGITIMATE_SITE_STATUSES = (AUTH_INDEPENDENT_MEDIA, AUTH_VERIFIED_ORGANIZATION, AUTH_REPUTABLE_SITE,
                            AUTH_ESTABLISHED_SITE)
AUTH_UNLISTED = "UNLISTED"
AUTH_PENDING = "PENDING"
AUTH_REVOKED = "REVOKED"
AUTH_EXPIRED = "EXPIRED"
AUTH_NOT_CHECKABLE = "NOT_CHECKABLE"

# Claim-verification statuses.
VERIFIED = "VERIFIED"
CONTRADICTED = "CONTRADICTED"
NOT_VERIFIABLE = "NOT_VERIFIABLE"
SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
SOURCE_EXPIRED = "SOURCE_EXPIRED"
CONFLICTING_SOURCES = "CONFLICTING_SOURCES"
VERIFICATION_STATUSES = (
    VERIFIED, CONTRADICTED, NOT_VERIFIABLE, SOURCE_UNAVAILABLE, SOURCE_EXPIRED, CONFLICTING_SOURCES,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_ts(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


# -------------------------------------------------------------------- registry


@dataclass(frozen=True)
class SourceURL:
    url: str
    kind: str = "html"            # rss | api | html
    terms_reviewed: bool = False  # reviewer confirmed robots/terms permit retrieval

    def as_dict(self) -> dict:
        return {"url": self.url, "kind": self.kind, "terms_reviewed": self.terms_reviewed}


@dataclass(frozen=True)
class RegistryEntry:
    id: str
    organization: str
    aliases_en: tuple[str, ...]
    aliases_ar: tuple[str, ...]
    aliases_translit: tuple[str, ...]
    domains: tuple[str, ...]
    subdomain_policy: str
    allowed_subdomains: tuple[str, ...]
    source_class: str
    jurisdiction: str
    authority_scope: tuple[str, ...]
    categories: tuple[str, ...]
    languages: tuple[str, ...]
    source_urls: tuple[SourceURL, ...]
    provenance: str
    status: str
    reviewer: str | None = None
    verified_at: str | None = None
    max_age_days: int = 180
    brand_token: str | None = None
    notes: str | None = None
    synthetic: bool = False
    revoked_reason: str | None = None

    @property
    def all_aliases(self) -> tuple[str, ...]:
        return (self.organization, *self.aliases_en, *self.aliases_ar, *self.aliases_translit)

    def is_fresh(self, now: datetime) -> bool:
        verified = parse_ts(self.verified_at)
        if verified is None:
            return False
        age_days = (now - verified).total_seconds() / 86400
        return 0 <= age_days <= self.max_age_days

    def expires_at(self) -> str | None:
        verified = parse_ts(self.verified_at)
        return iso(verified + timedelta(days=self.max_age_days)) if verified else None

    def is_trusted(self, now: datetime) -> bool:
        """Only approved AND fresh entries authenticate anything."""
        return self.status == STATUS_APPROVED and self.is_fresh(now)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "organization": self.organization,
            "aliases": {
                "en": list(self.aliases_en),
                "ar": list(self.aliases_ar),
                "translit": list(self.aliases_translit),
            },
            "domains": list(self.domains),
            "subdomain_policy": self.subdomain_policy,
            "allowed_subdomains": list(self.allowed_subdomains),
            "source_class": self.source_class,
            "jurisdiction": self.jurisdiction,
            "authority_scope": list(self.authority_scope),
            "categories": list(self.categories),
            "languages": list(self.languages),
            "source_urls": [item.as_dict() for item in self.source_urls],
            "provenance": self.provenance,
            "status": self.status,
            "reviewer": self.reviewer,
            "verified_at": self.verified_at,
            "max_age_days": self.max_age_days,
            "brand_token": self.brand_token,
            "notes": self.notes,
            "synthetic": self.synthetic,
            "revoked_reason": self.revoked_reason,
        }


@dataclass(frozen=True)
class DomainAuthentication:
    status: str
    host: str
    entry_id: str | None = None
    organization: str | None = None
    source_class: str | None = None
    reason: str = ""
    registry_version: str = ""
    reviewer: str | None = None
    verified_at: str | None = None
    expires_at: str | None = None
    reputation: dict | None = None     # independent reputation evidence (REPUTABLE_SITE only)
    established: dict | None = None    # established-website evidence / why not (ESTABLISHED_SITE)

    @property
    def authenticated(self) -> bool:
        """Approved, fresh GOVERNMENT domain (Class A/B) — the government SAFE path."""
        return self.status == AUTH_AUTHENTICATED

    @property
    def legitimate_site(self) -> bool:
        """Approved, fresh NON-government site (news / verified organisation) — the private SAFE path."""
        return self.status in LEGITIMATE_SITE_STATUSES

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "authenticated": self.authenticated,
            "legitimate_site": self.legitimate_site,
            "host": self.host,
            "entry_id": self.entry_id,
            "organization": self.organization,
            "source_class": self.source_class,
            "reason": self.reason,
            "registry_version": self.registry_version,
            "reviewer": self.reviewer,
            "verified_at": self.verified_at,
            "expires_at": self.expires_at,
            "reputation": self.reputation,
            "established": self.established,
        }


# ----------------------------------------------------------------- verification


@dataclass(frozen=True)
class OfficialRecord:
    """One pre-fetched official document. Produced only by the retrieval layer
    (or by a clearly labelled SYNTHETIC test fixture)."""

    record_id: str
    entry_id: str
    url: str
    content: str
    retrieved_at: str
    published_at: str | None = None
    title: str = ""
    fetch_status: str = "ok"          # ok | error
    fetch_error: str | None = None
    synthetic: bool = False

    @property
    def content_hash(self) -> str:
        return sha256_text(self.content)

    @classmethod
    def from_dict(cls, data: dict) -> "OfficialRecord":
        return cls(
            record_id=str(data["record_id"]),
            entry_id=str(data["entry_id"]),
            url=str(data["url"]),
            content=str(data.get("content") or ""),
            retrieved_at=str(data["retrieved_at"]),
            published_at=data.get("published_at"),
            title=str(data.get("title") or ""),
            fetch_status=str(data.get("fetch_status") or "ok"),
            fetch_error=data.get("fetch_error"),
            synthetic=bool(data.get("synthetic", False)),
        )


@dataclass(frozen=True)
class Claim:
    raw: str
    canonical: str
    entity_ids: tuple[str, ...]
    entity_names: tuple[str, ...]
    generic_government: bool
    categories: tuple[str, ...]
    concepts: tuple[str, ...]
    amounts_aed: tuple[float, ...]
    dates: tuple[str, ...]
    language: str

    @property
    def is_government_claim(self) -> bool:
        return bool(self.categories) and (bool(self.entity_ids) or self.generic_government)

    def as_dict(self) -> dict:
        return {
            "canonical": self.canonical,
            "entity_ids": list(self.entity_ids),
            "entity_names": list(self.entity_names),
            "generic_government": self.generic_government,
            "categories": list(self.categories),
            "concepts": list(self.concepts),
            "amounts_aed": list(self.amounts_aed),
            "dates": list(self.dates),
            "language": self.language,
        }


@dataclass(frozen=True)
class EvidenceItem:
    role: str                 # decisive | supporting_context | superseded | excluded
    comparison: str           # supports | contradicts | related | stale | unavailable
    source_class: str
    entry_id: str
    organization: str
    source_url: str
    published_at: str | None
    retrieved_at: str | None
    excerpt: str
    content_hash: str
    detail: str = ""
    synthetic: bool = False
    attributes: dict | None = None    # authority / jurisdiction / service / amount / effective_date outcome

    def as_dict(self) -> dict:
        return {
            "attributes": self.attributes,
            "role": self.role,
            "comparison": self.comparison,
            "source_class": self.source_class,
            "entry_id": self.entry_id,
            "organization": self.organization,
            "source_url": self.source_url,
            "published_at": self.published_at,
            "retrieved_at": self.retrieved_at,
            "excerpt": self.excerpt,
            "content_hash": self.content_hash,
            "detail": self.detail,
            "synthetic": self.synthetic,
        }


@dataclass(frozen=True)
class GovVerification:
    status: str
    claim: Claim
    evidence: tuple[EvidenceItem, ...]
    checked_sources: tuple[str, ...]
    unchecked_sources: tuple[str, ...]
    relevant_sources: tuple[str, ...]
    notes: tuple[str, ...]
    evidence_id: str
    registry_version: str
    policy_version: str
    verified_at: str

    @property
    def coverage(self) -> str:
        """'checked' when at least one relevant approved source was actually examined."""
        if self.checked_sources:
            return "checked"
        if self.relevant_sources:
            return "not_checked"
        return "no_relevant_source"

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "coverage": self.coverage,
            "claim": self.claim.as_dict(),
            "evidence": [item.as_dict() for item in self.evidence],
            "checked_sources": list(self.checked_sources),
            "unchecked_sources": list(self.unchecked_sources),
            "relevant_sources": list(self.relevant_sources),
            "notes": list(self.notes),
            "evidence_id": self.evidence_id,
            "registry_version": self.registry_version,
            "policy_version": self.policy_version,
            "verified_at": self.verified_at,
        }


@dataclass
class ValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors
