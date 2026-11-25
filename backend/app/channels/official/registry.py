"""Official UAE source registry: loading, validation, domain authentication.

Trust rules enforced here:

* Only ``approved`` entries whose ``verified_at`` (approval date) is within
  ``max_age_days`` authenticate anything ("trusted").
* Domains are matched exactly (punycode form) under an explicit subdomain
  policy. Nothing is trusted because it ends in ``.gov.ae`` — public suffixes
  are rejected as registry domains.
* Class C (independent media) never authenticates a government domain.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

import yaml

from . import normalize
from .models import (
    AUTH_AUTHENTICATED,
    AUTH_EXPIRED,
    AUTH_INDEPENDENT_MEDIA,
    AUTH_NOT_CHECKABLE,
    AUTH_PENDING,
    AUTH_REVOKED,
    AUTH_UNLISTED,
    CLASS_A,
    CLASS_B,
    CLASS_C,
    ENTRY_STATUSES,
    JURISDICTIONS,
    SOURCE_CLASSES,
    STATUS_APPROVED,
    STATUS_PENDING,
    STATUS_REVOKED,
    SUBDOMAIN_ANY,
    SUBDOMAIN_EXACT,
    SUBDOMAIN_LISTED,
    SUBDOMAIN_POLICIES,
    DomainAuthentication,
    RegistryEntry,
    SourceURL,
    ValidationReport,
    iso,
    parse_ts,
    sha256_text,
    CLASS_P,
    AUTH_VERIFIED_ORGANIZATION,
)

OFFICIAL_DIR = Path(__file__).resolve().parent
DEFAULT_REGISTRY_PATH = OFFICIAL_DIR / "registry.yaml"

# A registry domain must be a registrable name, never a bare public suffix.
PUBLIC_SUFFIXES = frozenset(
    {
        "ae", "gov.ae", "ac.ae", "co.ae", "net.ae", "org.ae", "sch.ae", "mil.ae",
        "abudhabi", "dubai", "com", "net", "org", "gov", "io", "example", "gov.example",
    }
)
_LDH_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}$")
DEFAULT_PORTS = {"https": 443, "http": 80}

HEADER = (
    "# Daggers — official UAE source registry + verified non-government sites.\n"
    "# Classes: A authority · B official media · C independent media · P verified organisation\n"
    "# (C and P are never official sources for government claims).\n"
    "# Every entry starts as `pending`. Approve one with (reviewer name optional):\n"
    "#   python -m backend.app.channels.official.cli approve <id>\n"
    "# Do not hand-edit `status`, `reviewer`, or `verified_at`.\n"
)


class RegistryError(ValueError):
    pass


# ------------------------------------------------------------------ host utils


def to_ascii_host(host: str) -> str | None:
    """Lower-case punycode form of a host, or None if it is not a valid DNS name."""
    value = (host or "").strip().rstrip(".").lower()
    if not value or len(value) > 253:
        return None
    labels: list[str] = []
    for label in value.split("."):
        if not label:
            return None
        if label.isascii():
            ascii_label = label
        else:
            try:
                ascii_label = "xn--" + label.encode("punycode").decode("ascii")
            except UnicodeError:
                return None
        if not _LDH_LABEL.match(ascii_label):
            return None
        labels.append(ascii_label)
    return ".".join(labels)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def parse_target(value: str) -> tuple[str | None, str | None]:
    """Return (ascii_host, problem). Problem is a human-readable NOT_CHECKABLE reason."""
    raw = (value or "").strip()
    if not raw:
        return None, "empty URL"
    candidate = raw if "://" in raw else f"https://{raw.lstrip('/')}"
    try:
        parts = urlsplit(candidate)
        port = parts.port
    except ValueError:
        return None, "malformed URL"
    scheme = (parts.scheme or "").lower()
    if scheme not in DEFAULT_PORTS:
        return None, f"unsupported scheme '{scheme}'"
    if "@" in (parts.netloc or ""):
        return None, "credentials ('user@host') in URL authority"
    host = parts.hostname or ""
    if is_ip_literal(host):
        return None, "IP-literal host cannot be authenticated"
    ascii_host = to_ascii_host(host)
    if not ascii_host:
        return None, "host is not a valid domain name"
    if port is not None and port != DEFAULT_PORTS[scheme]:
        return ascii_host, f"non-standard port {port}"
    if scheme != "https":
        return ascii_host, "plain HTTP cannot be authenticated"
    return ascii_host, None


# ------------------------------------------------------------------ parsing


def _tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)  # type: ignore[union-attr]


def _entry_from_dict(data: dict) -> RegistryEntry:
    aliases = data.get("aliases") or {}
    urls = []
    for item in data.get("source_urls") or []:
        if isinstance(item, str):
            urls.append(SourceURL(url=item))
        else:
            urls.append(
                SourceURL(
                    url=str(item.get("url", "")),
                    kind=str(item.get("kind", "html")),
                    terms_reviewed=bool(item.get("terms_reviewed", False)),
                )
            )
    return RegistryEntry(
        id=str(data.get("id", "")),
        organization=str(data.get("organization", "")),
        aliases_en=_tuple(aliases.get("en")),
        aliases_ar=_tuple(aliases.get("ar")),
        aliases_translit=_tuple(aliases.get("translit")),
        domains=tuple(str(d).strip().lower() for d in data.get("domains") or ()),
        subdomain_policy=str(data.get("subdomain_policy", SUBDOMAIN_EXACT)),
        allowed_subdomains=tuple(str(s).strip().lower() for s in data.get("allowed_subdomains") or ()),
        source_class=str(data.get("source_class", "")),
        jurisdiction=str(data.get("jurisdiction", "")),
        authority_scope=_tuple(data.get("authority_scope")),
        categories=_tuple(data.get("categories")),
        languages=_tuple(data.get("languages")),
        source_urls=tuple(urls),
        provenance=str(data.get("provenance", "")),
        status=str(data.get("status", STATUS_PENDING)),
        reviewer=data.get("reviewer") or None,
        verified_at=data.get("verified_at") or None,
        max_age_days=int(data.get("max_age_days", 180)),
        brand_token=data.get("brand_token") or None,
        notes=data.get("notes") or None,
        synthetic=bool(data.get("synthetic", False)),
        revoked_reason=data.get("revoked_reason") or None,
    )


def validate_entries(raw_entries: list[dict], *, allow_synthetic: bool = False) -> ValidationReport:
    report = ValidationReport()
    seen_ids: set[str] = set()
    domain_owner: dict[str, str] = {}
    for index, data in enumerate(raw_entries):
        where = f"entries[{index}]"
        if not isinstance(data, dict):
            report.errors.append(f"{where}: entry must be a mapping")
            continue
        entry = _entry_from_dict(data)
        where = f"{where} ({entry.id or '?'})"
        if not _ID.match(entry.id):
            report.errors.append(f"{where}: id must match {_ID.pattern}")
        if entry.id in seen_ids:
            report.errors.append(f"{where}: duplicate id")
        seen_ids.add(entry.id)
        if not entry.organization.strip():
            report.errors.append(f"{where}: organization is required")
        if entry.status not in ENTRY_STATUSES:
            report.errors.append(f"{where}: status must be one of {ENTRY_STATUSES}")
        if entry.source_class not in SOURCE_CLASSES:
            report.errors.append(f"{where}: source_class must be one of {SOURCE_CLASSES}")
        if entry.jurisdiction not in JURISDICTIONS:
            report.errors.append(f"{where}: jurisdiction must be one of {JURISDICTIONS}")
        if entry.jurisdiction == "synthetic" and not entry.synthetic:
            report.errors.append(f"{where}: synthetic jurisdiction requires synthetic: true")
        if entry.synthetic and not allow_synthetic:
            report.errors.append(f"{where}: synthetic entries are only allowed in test registries")
        if entry.subdomain_policy not in SUBDOMAIN_POLICIES:
            report.errors.append(f"{where}: subdomain_policy must be one of {SUBDOMAIN_POLICIES}")
        if entry.subdomain_policy == SUBDOMAIN_EXACT and entry.allowed_subdomains:
            report.errors.append(f"{where}: allowed_subdomains requires subdomain_policy 'listed'")
        for sub in entry.allowed_subdomains:
            if not all(_LDH_LABEL.match(label) for label in sub.split(".")):
                report.errors.append(f"{where}: invalid allowed subdomain '{sub}'")
        if not entry.domains:
            report.errors.append(f"{where}: at least one exact domain is required")
        for raw_domain in data.get("domains") or ():
            if str(raw_domain) != str(raw_domain).strip().lower():
                report.errors.append(f"{where}: domain '{raw_domain}' must be written in lower case")
        for domain in entry.domains:
            ascii_domain = to_ascii_host(domain)
            if ascii_domain != domain:
                report.errors.append(f"{where}: domain '{domain}' must be lower-case ASCII/punycode")
                continue
            if is_ip_literal(domain) or "*" in domain:
                report.errors.append(f"{where}: domain '{domain}' must be a DNS name without wildcards")
            if domain in PUBLIC_SUFFIXES or "." not in domain:
                report.errors.append(f"{where}: '{domain}' is a public suffix, not an authority domain")
            if domain.endswith(".example") and not entry.synthetic:
                report.errors.append(f"{where}: .example domains are reserved for synthetic fixtures")
            if domain in domain_owner and domain_owner[domain] != entry.id:
                report.errors.append(f"{where}: domain '{domain}' already claimed by {domain_owner[domain]}")
            domain_owner[domain] = entry.id
        if not entry.provenance.strip():
            report.errors.append(f"{where}: provenance is required")
        if entry.max_age_days <= 0 or entry.max_age_days > 730:
            report.errors.append(f"{where}: max_age_days must be within 1..730")
        if entry.status == STATUS_APPROVED:
            if parse_ts(entry.verified_at) is None:
                report.errors.append(f"{where}: approved entry needs a valid verified_at")
        if entry.status == STATUS_PENDING and (entry.reviewer or entry.verified_at):
            report.warnings.append(f"{where}: pending entry carries reviewer/verified_at; ignored until approved")
        if entry.status == STATUS_REVOKED and not entry.revoked_reason:
            report.warnings.append(f"{where}: revoked entry has no revoked_reason")
        if entry.source_class == CLASS_C and entry.authority_scope:
            report.errors.append(f"{where}: Class C (independent media) cannot hold authority_scope")
        if entry.source_class == CLASS_P and (entry.authority_scope or entry.source_urls):
            report.errors.append(f"{where}: Class P (verified organisation) cannot hold authority_scope or "
                                 "official source_urls — it is never a government source")
        for source in entry.source_urls:
            try:
                parts = urlsplit(source.url)
            except ValueError:
                report.errors.append(f"{where}: malformed source URL")
                continue
            if parts.scheme != "https":
                report.errors.append(f"{where}: source URL must be HTTPS: {source.url}")
            if parts.username or parts.password or parts.port not in (None, 443):
                report.errors.append(f"{where}: source URL must not carry credentials or ports: {source.url}")
            host = to_ascii_host(parts.hostname or "")
            if not host or not host_matches_entry(host, entry):
                report.errors.append(f"{where}: source URL host is outside the entry's approved domains: {source.url}")
            if source.kind not in {"rss", "api", "html"}:
                report.errors.append(f"{where}: source kind must be rss|api|html")
    return report


def host_matches_entry(ascii_host: str, entry: RegistryEntry) -> bool:
    for domain in entry.domains:
        if ascii_host == domain:
            return True
        if entry.subdomain_policy == SUBDOMAIN_LISTED:
            if any(ascii_host == f"{sub}.{domain}" for sub in entry.allowed_subdomains):
                return True
        elif entry.subdomain_policy == SUBDOMAIN_ANY and ascii_host.endswith("." + domain):
            return True
    return False


# ------------------------------------------------------------------ registry


class Registry:
    def __init__(
        self,
        entries: Iterable[RegistryEntry],
        *,
        version: str,
        path: Path | None = None,
        raw: dict | None = None,
    ) -> None:
        self.entries: tuple[RegistryEntry, ...] = tuple(entries)
        self.by_id = {entry.id: entry for entry in self.entries}
        self.version = version
        self.path = path
        self.raw = raw or {}

    # ---- construction

    @classmethod
    def from_mapping(
        cls, data: dict, *, path: Path | None = None, allow_synthetic: bool = False
    ) -> "Registry":
        if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
            raise RegistryError("registry must be a mapping with an 'entries' list")
        report = validate_entries(data["entries"], allow_synthetic=allow_synthetic)
        if not report.ok:
            raise RegistryError("invalid registry: " + "; ".join(report.errors))
        entries = [_entry_from_dict(item) for item in data["entries"]]
        canonical = json.dumps(data["entries"], sort_keys=True, ensure_ascii=False, default=str)
        version = "reg_" + sha256_text(canonical)[:16]
        return cls(entries, version=version, path=path, raw=data)

    @classmethod
    def load(cls, path: Path | str | None = None, *, allow_synthetic: bool = False) -> "Registry":
        target = Path(path) if path else DEFAULT_REGISTRY_PATH
        data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        return cls.from_mapping(data, path=target, allow_synthetic=allow_synthetic)

    # ---- lookups

    def trusted(self, now: datetime) -> list[RegistryEntry]:
        return [entry for entry in self.entries if entry.is_trusted(now)]

    def entries_for_host(self, ascii_host: str) -> list[RegistryEntry]:
        return [entry for entry in self.entries if host_matches_entry(ascii_host, entry)]

    def authenticate(self, url_or_host: str, now: datetime) -> DomainAuthentication:
        """Domain authentication only. Says nothing about the page's content."""
        host, problem = parse_target(url_or_host)
        display = host or (url_or_host or "")[:120]
        if problem:
            return DomainAuthentication(AUTH_NOT_CHECKABLE, display, reason=problem, registry_version=self.version)
        assert host is not None
        matches = self.entries_for_host(host)
        if not matches:
            return DomainAuthentication(
                AUTH_UNLISTED,
                host,
                reason="domain is not in the official source registry",
                registry_version=self.version,
            )
        # A trusted match wins; otherwise report the most informative non-trusted state.
        for entry in matches:
            if entry.is_trusted(now):
                approval = dict(reviewer=entry.reviewer, verified_at=entry.verified_at, expires_at=entry.expires_at())
                if entry.source_class == CLASS_C:
                    return DomainAuthentication(
                        AUTH_INDEPENDENT_MEDIA, host, entry.id, entry.organization, entry.source_class,
                        f"approved independent news outlet ({entry.organization}) — not an official government source",
                        self.version, **approval,
                    )
                if entry.source_class == CLASS_P:
                    return DomainAuthentication(
                        AUTH_VERIFIED_ORGANIZATION, host, entry.id, entry.organization, entry.source_class,
                        f"verified website of {entry.organization} — not a government source",
                        self.version, **approval,
                    )
                return DomainAuthentication(
                    AUTH_AUTHENTICATED, host, entry.id, entry.organization, entry.source_class,
                    f"approved official domain of {entry.organization}"
                    + (f" (reviewed by {entry.reviewer})" if entry.reviewer else ""),
                    self.version, **approval,
                )
        entry = matches[0]
        if entry.status == STATUS_REVOKED:
            status, reason = AUTH_REVOKED, f"registry approval revoked ({entry.revoked_reason or 'no reason recorded'})"
        elif entry.status == STATUS_APPROVED:
            status, reason = AUTH_EXPIRED, (f"registry approval expired on {entry.expires_at()} "
                                            f"(older than {entry.max_age_days} days); re-review required")
        else:
            status, reason = AUTH_PENDING, "registry entry is pending human review"
        return DomainAuthentication(
            status, host, entry.id, entry.organization, entry.source_class, reason, self.version
        )

    def resolve_entities(self, text: str) -> list[RegistryEntry]:
        """Entities named in text via EN/AR/transliterated aliases (identification, not trust)."""
        key = normalize.match_key(text)
        found: list[RegistryEntry] = []
        for entry in self.entries:
            for alias in entry.all_aliases:
                alias_tokens = normalize.tokens(alias)
                if not alias_tokens:
                    continue
                if len("".join(alias_tokens)) < 3:
                    continue
                if normalize.contains_phrase(key, alias):
                    found.append(entry)
                    break
        return found

    # ---- human review actions (return a new raw mapping; caller persists)

    def _replace_raw(self, entry_id: str, updater) -> dict:
        data = json.loads(json.dumps(self.raw, default=str))
        for item in data.get("entries", []):
            if item.get("id") == entry_id:
                updater(item)
                return data
        raise RegistryError(f"unknown entry id '{entry_id}'")

    def approved_mapping(self, entry_id: str, reviewer: str | None, now: datetime) -> dict:
        """Approve an entry. The reviewer name is optional; the approval date is always recorded
        (it drives the freshness expiry)."""
        reviewer = (reviewer or "").strip() or None
        entry = self.by_id.get(entry_id)
        if entry is None:
            raise RegistryError(f"unknown entry id '{entry_id}'")
        if entry.synthetic:
            raise RegistryError("synthetic entries cannot be approved through the CLI")

        def update(item: dict) -> None:
            item["status"] = STATUS_APPROVED
            item["reviewer"] = reviewer
            item["verified_at"] = iso(now)
            item.pop("revoked_reason", None)

        return self._replace_raw(entry_id, update)

    def revoked_mapping(self, entry_id: str, reviewer: str, reason: str, now: datetime) -> dict:
        if not (reason or "").strip():
            raise RegistryError("revocation needs a reason")

        def update(item: dict) -> None:
            item["status"] = STATUS_REVOKED
            who = f" — {reviewer.strip()}" if (reviewer or "").strip() else ""
            item["revoked_reason"] = f"{reason.strip()}{who} at {iso(now)}"

        return self._replace_raw(entry_id, update)


def dump_registry(data: dict) -> str:
    return HEADER + yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)


def write_registry_atomic(path: Path, data: dict, *, allow_synthetic: bool = False) -> Registry:
    """Validate first, then atomically replace the file. Never leaves a half-written registry."""
    registry = Registry.from_mapping(data, path=path, allow_synthetic=allow_synthetic)
    text = dump_registry(data)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".registry.", suffix=".yaml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return registry


__all__ = [
    "Registry", "RegistryError", "validate_entries", "host_matches_entry", "parse_target",
    "to_ascii_host", "write_registry_atomic", "dump_registry", "DEFAULT_REGISTRY_PATH",
]
