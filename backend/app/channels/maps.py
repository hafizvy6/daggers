"""Maps channel adapter (authorized Google Places only).

Each listing gets SEPARATE evidence for three checks:
  * identity — does the listing name claim a government entity / known brand, and
               does its website actually belong to it?
  * website  — the shared scorer + trust policy (same path as every other surface)
  * phone    — the deterministic number check (``core.numbers``)

Missing business information is reported as ``not_provided``; it is never
treated as evidence of fraud. Listing data is business data from a third-party
listing; no personal or victim information is accepted or stored.

Live Google Places is used only when MAPS_LIVE_ENABLED=1 and
GOOGLE_PLACES_API_KEY is set (server-side env only — never in the extension).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlencode

from ..core import numbers as ws1_numbers
from ..core import homograph
from . import privacy, trust_policy, urls
from .http_client import ProviderError
from .http_client import request as http_request
from .official.models import iso

PLACES_FIELDS = (
    "places.id,places.displayName,places.formattedAddress,places.websiteUri,"
    "places.internationalPhoneNumber,places.primaryType,places.businessStatus"
)
MAX_LISTINGS = 10

NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"


@dataclass
class Listing:
    provider: str
    place_id: str
    name: str
    address: str = ""
    website: str | None = None
    phone: str | None = None
    category: str = ""
    business_status: str = ""
    synthetic: bool = False
    source_kind: str = "live"


class GooglePlacesProvider:
    name, source_kind = "google_places", "live"

    def __init__(self, api_key: str, http: Callable = http_request) -> None:
        self.api_key = api_key
        self.http = http

    def search(self, query: str, lang: str, limit: int) -> list[Listing]:
        body = self.http(
            "https://places.googleapis.com/v1/places:searchText",
            method="POST",
            headers={"X-Goog-Api-Key": self.api_key, "X-Goog-FieldMask": PLACES_FIELDS},
            json_body={"textQuery": query, "languageCode": lang, "regionCode": "AE", "pageSize": limit},
        )
        data = json.loads(body)
        return [
            Listing(
                "google_places", str(p.get("id", "")), str((p.get("displayName") or {}).get("text", "")),
                str(p.get("formattedAddress", "")), p.get("websiteUri"), p.get("internationalPhoneNumber"),
                str(p.get("primaryType", "")), str(p.get("businessStatus", "")),
            )
            for p in data.get("places", [])[:limit]
        ]


def _first_tag(tags: dict, *keys: str) -> str | None:
    for key in keys:
        value = (tags or {}).get(key)
        if value:
            return str(value).strip()
    return None


def parse_nominatim(payload: list | dict, limit: int = MAX_LISTINGS) -> list[Listing]:
    """Map Nominatim jsonv2 results onto Listing. Pure; used by tests and the provider."""
    items = payload if isinstance(payload, list) else []
    listings: list[Listing] = []
    for item in items[:limit]:
        if not isinstance(item, dict):
            continue
        tags = item.get("extratags") or {}
        name = str(item.get("name") or "").strip()
        if not name:
            # Fall back to the first address segment; never invent a name.
            display = str(item.get("display_name") or "").strip()
            name = display.split(",", 1)[0].strip() if display else ""
        if not name:
            continue
        website = _first_tag(tags, "website", "contact:website", "url", "contact:url")
        if website and "://" not in website:
            website = "https://" + website
        phone = _first_tag(tags, "phone", "contact:phone", "contact:telephone", "phone:mobile", "contact:mobile", "mobile")
        osm_type = str(item.get("osm_type") or "")[:1] or "N"
        osm_id = str(item.get("osm_id") or item.get("place_id") or "")
        listings.append(Listing(
            provider="openstreetmap",
            place_id=f"{osm_type.upper()}/{osm_id}" if osm_id else f"nominatim:{item.get('place_id', '')}",
            name=name,
            address=str(item.get("display_name") or "").strip(),
            website=website,
            phone=phone,
            category=str(item.get("type") or item.get("class") or "").strip(),
            business_status="",
            source_kind="live",
        ))
    return listings


class NominatimProvider:
    """Keyless OpenStreetMap search. Usage policy: <=1 req/s, identifiable UA, attribution."""

    name, source_kind = "openstreetmap", "live"

    def __init__(self, http: Callable = http_request) -> None:
        self.http = http

    def search(self, query: str, lang: str, limit: int) -> list[Listing]:
        url = NOMINATIM_URL + "?" + urlencode({
            "q": query,
            "format": "jsonv2",
            "addressdetails": "1",
            "extratags": "1",
            "countrycodes": "ae",
            "limit": max(1, min(limit, MAX_LISTINGS)),
            "accept-language": "ar" if lang == "ar" else "en",
        })
        body = self.http(url, method="GET")
        return parse_nominatim(json.loads(body), limit)


def default_maps_providers(env: dict | None = None) -> list:
    env = dict(os.environ if env is None else env)
    providers: list = []
    if env.get("MAPS_LIVE_ENABLED", "0") == "1":
        if env.get("GOOGLE_PLACES_API_KEY"):
            providers.append(GooglePlacesProvider(env["GOOGLE_PLACES_API_KEY"]))
        # Keyless fallback: OpenStreetMap/Nominatim. Google is preferred when keyed;
        # OSM requires attribution ("© OpenStreetMap contributors") and low volume.
        providers.append(NominatimProvider())
    return providers


_PHONE_TAG = {"MALICIOUS": "FAKE", "MISLEADING": "MISLEADING", "SUSPICIOUS": "WARNING"}


class MapsChannel:
    def __init__(self, scorer, providers: list | None = None, clock=None) -> None:
        self.scorer = scorer
        self.providers = providers if providers is not None else default_maps_providers()
        self.clock = clock or scorer.clock

    def _listings(self, query: str, lang: str, limit: int) -> tuple[list[Listing], str, str, list[str]]:
        errors: list[str] = []
        if not self.providers:
            return [], "none", "unconfigured", ["maps: no live provider configured"]
        for provider in self.providers:
            try:
                found = provider.search(query, lang, limit)
            except (ProviderError, ValueError, KeyError, OSError) as exc:
                errors.append(f"{provider.name}: {type(exc).__name__}")
                continue
            if found:
                return found, provider.name, provider.source_kind, errors
            errors.append(f"{provider.name}: no results")
        return [], "none", "unavailable", errors

    def _identity(self, listing: Listing, website_result: dict | None) -> dict:
        named = [e for e in self.scorer.registry.resolve_entities(listing.name) if e.source_class != "C"]
        folded = homograph.confusable_fold(listing.name)
        brands = [
            b for b in self.scorer.catalog.brands
            if any(len(t) >= 4 and t in folded for t in [b["token"], *b.get("aliases", [])])
        ]
        if not named and not brands:
            return {"status": "no_official_claim", "detail": "listing name does not claim a government entity or catalogued brand"}
        claimed = ", ".join([e.organization for e in named] + [b["official_domain"] for b in brands])
        if website_result is None:
            return {"status": "not_assessable", "claimed": claimed,
                    "detail": "listing names an official entity/brand but provides no website to compare"}
        auth = website_result["domain_auth"]
        if auth["authenticated"] and (not named or auth["entry_id"] in {e.id for e in named}):
            return {"status": "consistent", "claimed": claimed, "detail": "website is the authenticated domain of the named entity"}
        host = urls.registrable_domain(website_result["url"], self.scorer.catalog.suffix_resolver)
        if brands and any(homograph.is_official_host(host, b["official_domain"]) for b in brands) and not named:
            return {"status": "consistent", "claimed": claimed, "detail": "website matches the brand's catalogued domain"}
        return {"status": "mismatch", "claimed": claimed,
                "detail": f"listing claims {claimed} but its website ({host}) is not that entity's authenticated domain"}

    def assess_listing(self, listing: Listing) -> dict:
        retrieved_at = iso(self.clock())
        website_check: dict
        website_result = None
        if listing.website:
            website_raw = listing.website if "://" in listing.website else "https://" + listing.website
            url, problem = urls.normalize_result_url(website_raw)
            if url:
                website_result = self.scorer.assess_url(url, text=listing.name)
                website_check = {"status": "checked", **{k: website_result[k] for k in (
                    "url", "verdict", "score", "reasons", "tag", "domain_auth", "trust_reasons", "blockable")}}
            else:
                website_check = {"status": "invalid", "detail": problem}
        else:
            website_check = {"status": "not_provided", "detail": "no website on the listing (not evidence of fraud)"}

        if listing.phone:
            number = ws1_numbers.check_number(listing.phone)
            phone_check = {"status": "checked", "verdict": number.verdict, "score": number.score,
                           "reasons": number.reasons, "scam_type": number.scam_type,
                           "tag": _PHONE_TAG.get(number.verdict)}
        else:
            phone_check = {"status": "not_provided", "detail": "no phone on the listing (not evidence of fraud)"}

        identity = self._identity(listing, website_result)
        tags = [website_result["tag"]] if website_result else [trust_policy.WARNING]
        if phone_check.get("tag"):
            tags.append(phone_check["tag"])
        if identity["status"] in ("mismatch", "not_assessable"):
            tags.append(trust_policy.WARNING)
        tag = trust_policy.worst(tags)
        reasons = []
        if not website_result:
            reasons.append("no verifiable website — listing cannot be authenticated")
        if identity["status"] == "mismatch":
            reasons.append(identity["detail"])
        return {
            "listing": {
                "provider": listing.provider,
                "provider_place_id": listing.place_id,
                "name": privacy.redact(listing.name, 200),
                "address": privacy.redact(listing.address, 200),
                "category": listing.category,
                "business_status": listing.business_status,
                "website": listing.website,
                "phone": listing.phone,
                "retrieved_at": retrieved_at,
                "is_synthetic": listing.synthetic,
                "source_kind": listing.source_kind,
                "evidence_type": "third_party_listing",
            },
            "checks": {"identity": identity, "website": website_check, "phone": phone_check},
            "tag": tag,
            "blockable": bool(website_result and website_result["blockable"]),
            "manual_review": tag != trust_policy.SAFE and identity["status"] == "mismatch",
            "reasons": reasons,
        }

    def run(self, query: str, lang: str = "en", limit: int = MAX_LISTINGS) -> dict:
        query = urls.normalize_query(query)
        listings, engine, kind, errors = self._listings(query, lang, max(1, min(limit, MAX_LISTINGS)))
        return {
            "query": query, "lang": lang, "engine": engine, "source_kind": kind, "cached": False,
            "errors": errors, "listings": [self.assess_listing(item) for item in listings],
        }
