"""U.AE government-directory discovery → PENDING registry candidates.

The directory is a discovery index only. Every candidate is created with
``status: pending`` and must be approved by a human reviewer. A listing never
approves a domain, subdomain, or URL by itself.

The parser is structure-tolerant (anchors + nearest section heading). It is
tested against a SYNTHETIC fixture; it has NOT been validated against the live
U.AE page structure from this environment.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .models import iso
from .registry import is_ip_literal, to_ascii_host

NON_ENTITY_HOSTS = (
    "facebook.com", "twitter.com", "x.com", "instagram.com", "youtube.com", "linkedin.com",
    "apple.com", "google.com", "play.google.com", "tiktok.com", "snapchat.com", "whatsapp.com",
)
_JURISDICTION_HINTS = (
    ("abu dhabi", "abu_dhabi"), ("أبوظبي", "abu_dhabi"), ("ابوظبي", "abu_dhabi"),
    ("dubai", "dubai"), ("دبي", "dubai"), ("sharjah", "sharjah"), ("الشارقة", "sharjah"),
    ("ajman", "ajman"), ("عجمان", "ajman"), ("umm al quwain", "umm_al_quwain"),
    ("ras al khaimah", "ras_al_khaimah"), ("fujairah", "fujairah"), ("federal", "federal"),
    ("الاتحادية", "federal"),
)


@dataclass(frozen=True)
class Candidate:
    name: str
    url: str
    host: str
    section: str
    jurisdiction_hint: str | None


class _DirectoryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.section = ""
        self._heading_depth = 0
        self._heading_text: list[str] = []
        self._href: str | None = None
        self._anchor_text: list[str] = []
        self.links: list[tuple[str, str, str]] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript"}:
            self._skip += 1
        if tag in {"h1", "h2", "h3", "h4"}:
            self._heading_depth += 1
            self._heading_text = []
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._anchor_text = []

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript"} and self._skip:
            self._skip -= 1
        if tag in {"h1", "h2", "h3", "h4"} and self._heading_depth:
            self._heading_depth -= 1
            self.section = " ".join("".join(self._heading_text).split())
        if tag == "a" and self._href is not None:
            text = " ".join("".join(self._anchor_text).split())
            self.links.append((text, self._href, self.section))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        if self._heading_depth:
            self._heading_text.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


def _jurisdiction(section: str) -> str | None:
    lowered = section.casefold()
    for hint, value in _JURISDICTION_HINTS:
        if hint in lowered:
            return value
    return None


def parse_directory(html: str, directory_host: str = "u.ae") -> list[Candidate]:
    parser = _DirectoryParser()
    parser.feed(html or "")
    parser.close()
    seen: set[str] = set()
    found: list[Candidate] = []
    for text, href, section in parser.links:
        if not href or len(text) < 3:
            continue
        try:
            parts = urlsplit(href)
        except ValueError:
            continue
        if parts.scheme != "https" or parts.username or parts.password or parts.port not in (None, 443):
            continue
        host = to_ascii_host(parts.hostname or "")
        if not host or is_ip_literal(host) or "." not in host:
            continue
        if host == directory_host or host.endswith("." + directory_host):
            continue
        if any(host == bad or host.endswith("." + bad) for bad in NON_ENTITY_HOSTS):
            continue
        if host in seen:
            continue
        seen.add(host)
        found.append(Candidate(text[:200], f"https://{host}/", host, section[:200], _jurisdiction(section)))
    return found


def _slug(name: str, host: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", host.removeprefix("www.").lower()).strip("-")
    return f"cand-{base}"[:64]


def candidates_to_entries(candidates: list[Candidate], *, source_url: str, discovered_at) -> list[dict]:
    entries = []
    for cand in candidates:
        bare = cand.host.removeprefix("www.")
        entry = {
            "id": _slug(cand.name, cand.host),
            "organization": cand.name,
            "aliases": {"en": [cand.name] if cand.name.isascii() else [],
                        "ar": [] if cand.name.isascii() else [cand.name], "translit": []},
            "domains": [bare],
            "subdomain_policy": "listed" if cand.host.startswith("www.") else "exact",
            "source_class": "A",
            "jurisdiction": cand.jurisdiction_hint or "federal",
            "authority_scope": [],
            "categories": ["announcement"],
            "languages": ["en", "ar"],
            "source_urls": [],
            "provenance": (
                f"discovered in directory {source_url} at {iso(discovered_at)}"
                f" (section: {cand.section or 'n/a'}); class, jurisdiction and scope are UNREVIEWED guesses"
            ),
            "status": "pending",
            "reviewer": None,
            "verified_at": None,
            "max_age_days": 180,
            "notes": "auto-discovered candidate — verify the domain with the entity before approval",
        }
        if cand.host.startswith("www."):
            entry["allowed_subdomains"] = ["www"]
        entries.append(entry)
    return entries


def merge_candidates(registry_mapping: dict, new_entries: list[dict]) -> tuple[dict, list[str], list[str]]:
    """Add candidates whose domains/ids are not already present. Never touches existing entries."""
    data = json.loads(json.dumps(registry_mapping, default=str))
    existing_ids = {e["id"] for e in data.get("entries", [])}
    existing_domains = {d for e in data.get("entries", []) for d in e.get("domains", [])}
    added, skipped = [], []
    for entry in new_entries:
        if entry["id"] in existing_ids or set(entry["domains"]) & existing_domains:
            skipped.append(entry["id"])
            continue
        data.setdefault("entries", []).append(entry)
        existing_ids.add(entry["id"])
        existing_domains.update(entry["domains"])
        added.append(entry["id"])
    return data, added, skipped
