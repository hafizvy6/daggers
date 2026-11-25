from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from io import BytesIO
from typing import Any

import httpx

from ..catalog import Catalog
from ..config import Settings


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
        self._rdap_client = None

    async def _bounded(self, awaitable, timeout: float) -> dict:
        try:
            result = await asyncio.wait_for(awaitable, timeout=timeout)
            return result if isinstance(result, dict) else {}
        except Exception:
            return {}

    async def _rdap(self, domain: str) -> dict:
        """Registration date ONLY (RDAP 'registration' event of the registrable domain, IANA bootstrap).
        Never certificate age, DNS age or 'last changed'. Unknown stays None."""
        if self._rdap_client is None:
            from ..intel.rdap import RDAPClient
            self._rdap_client = RDAPClient(cache_dir=self.settings.db_path.parent if self.settings.db_path else None,
                                           timeout_s=self.settings.http_timeout_s)
        age = await asyncio.to_thread(self._rdap_client.lookup, domain)
        return {"rdap_created": age.registered_at if age.known else None, "rdap_registrar": age.registrar,
                "rdap_status": age.status}

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

    async def enrich(self, domain: str, *, cert_issued: str | None = None) -> dict:
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
        # Certificate age comes from the CERTIFICATE only — never from the domain registration date.
        issued = merged.get("tls_issued") or cert_issued
        merged["cert_age_hours"] = parse_age_hours(issued)
        return merged
