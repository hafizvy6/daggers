from __future__ import annotations

import asyncio
import json
import socket
import ssl
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from io import BytesIO
from pathlib import Path
from typing import Any

import httpx

from ..catalog import Catalog
from ..config import Settings


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_age_hours(value: Any) -> float | None:
    if not value:
        return None
    text = str(value).strip()
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    delta = (datetime.now(timezone.utc) - parsed).total_seconds() / 3600
    return round(max(0.0, delta), 3)


def murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """Small pure-Python MurmurHash3 used for the 16×16 favicon digest."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded = length & ~0x3
    for index in range(0, rounded, 4):
        k1 = int.from_bytes(data[index : index + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[rounded:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if tail:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1


class Enricher:
    """Timeout-isolated S5 adapters. Every failure leaves the finding usable."""

    def __init__(self, settings: Settings, catalog: Catalog) -> None:
        self.settings = settings
        self.catalog = catalog

    async def _bounded(self, awaitable, timeout: float) -> dict:
        try:
            result = await asyncio.wait_for(awaitable, timeout=timeout)
            return result if isinstance(result, dict) else {}
        except Exception:
            return {}

    async def _rdap(self, domain: str) -> dict:
        headers = {"User-Agent": self.settings.http_user_agent, "Accept": "application/rdap+json"}
        async with httpx.AsyncClient(timeout=self.settings.http_timeout_s, headers=headers) as client:
            response = await client.get(f"https://rdap.org/domain/{domain}")
            response.raise_for_status()
            payload = response.json()
        created = next(
            (
                event.get("eventDate")
                for event in payload.get("events", [])
                if str(event.get("eventAction", "")).lower() == "registration"
            ),
            None,
        )
        registrar = None
        for entity in payload.get("entities", []):
            roles = {str(role).lower() for role in entity.get("roles", [])}
            if "registrar" in roles:
                vcard = entity.get("vcardArray") or []
                props = vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []
                registrar = next(
                    (prop[3] for prop in props if isinstance(prop, list) and len(prop) > 3 and prop[0] == "fn"),
                    None,
                )
                break
        return {"rdap_created": created, "rdap_registrar": registrar}

    async def _dns(self, domain: str) -> dict:
        loop = asyncio.get_running_loop()
        results = await loop.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        addresses = sorted({str(item[4][0]) for item in results})[:4]
        return {"dns_a": addresses}

    async def _tls(self, domain: str) -> dict:
        loop = asyncio.get_running_loop()
        context = ssl.create_default_context()
        transport, _ = await loop.create_connection(
            asyncio.Protocol,
            domain,
            443,
            ssl=context,
            server_hostname=domain,
        )
        try:
            ssl_object = transport.get_extra_info("ssl_object")
            certificate = ssl_object.getpeercert() if ssl_object else None
            if not certificate:
                return {}
            not_before = certificate.get("notBefore")
            issued = (
                datetime.fromtimestamp(ssl.cert_time_to_seconds(not_before), timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
                if not_before
                else None
            )
            issuer_parts = [
                value
                for rdn in certificate.get("issuer", ())
                for key, value in rdn  # type: ignore[misc]
                if key in {"organizationName", "commonName"}
            ]
            return {"tls_issued": issued, "tls_issuer": ", ".join(issuer_parts[:3]) or None}
        finally:
            transport.close()

    async def _favicon(self, domain: str) -> dict:
        try:
            from PIL import Image
        except ImportError:
            return {}
        headers = {"User-Agent": self.settings.http_user_agent}
        async with httpx.AsyncClient(timeout=self.settings.http_timeout_s, headers=headers) as client:
            response = await client.get(f"https://{domain}/favicon.ico")
            response.raise_for_status()
        with Image.open(BytesIO(response.content)) as image:
            pixels = image.convert("RGB").resize((16, 16)).tobytes()
        return {"favicon_hash": f"{murmur3_x86_32(pixels):08x}"}

    def demo_enrich(self, domain: str, cert_issued: str | None = None) -> dict:
        issued = cert_issued
        if not issued:
            path = self.settings.seed_dir / "fixtures" / "crt.json"
            if path.exists():
                for row in json.loads(path.read_text(encoding="utf-8")):
                    if str(row.get("domain")) == domain:
                        issued = row.get("cert_issued")
                        break
        issued = issued or _now()
        return {
            "rdap_created": issued,
            "rdap_registrar": "Daggers offline fixture",
            "dns_a": ["203.0.113.42"],
            "tls_issued": issued,
            "tls_issuer": "Daggers offline fixture",
            "favicon_hash": f"{murmur3_x86_32(domain.encode('utf-8')):08x}",
            "cert_age_hours": parse_age_hours(issued) or 0.7,
        }

    async def enrich(self, domain: str, *, cert_issued: str | None = None, mode: str = "live") -> dict:
        if mode == "demo":
            return self.demo_enrich(domain, cert_issued)
        if not self.settings.enrich_enabled:
            return {
                "tls_issued": cert_issued,
                "cert_age_hours": parse_age_hours(cert_issued),
                "dns_a": [],
                "favicon_hash": None,
                "rdap_created": None,
                "rdap_registrar": None,
                "tls_issuer": None,
            }
        timeout = self.settings.http_timeout_s
        results = await asyncio.gather(
            self._bounded(self._rdap(domain), timeout),
            self._bounded(self._dns(domain), timeout),
            self._bounded(self._tls(domain), timeout),
            self._bounded(self._favicon(domain), timeout),
        )
        merged: dict = {
            "rdap_created": None,
            "rdap_registrar": None,
            "dns_a": [],
            "tls_issued": cert_issued,
            "tls_issuer": None,
            "favicon_hash": None,
        }
        for result in results:
            merged.update(result)
        issued = merged.get("tls_issued") or cert_issued or merged.get("rdap_created")
        merged["cert_age_hours"] = parse_age_hours(issued)
        return merged
