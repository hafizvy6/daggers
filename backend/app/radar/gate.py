"""Cheap, SSRF-aware page gate for radar candidates.

This module reads only the first bytes of a public HTML page. It never fills
forms, executes scripts, accepts downloads, or follows a redirect onto private
address space.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass
from html import unescape
from typing import Any

import httpx

from ..config import Settings
from ..vision.diff import analyze_html_signals

MAX_HTML_BYTES = 256 * 1024
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


@dataclass(frozen=True)
class PageContext:
    final_url: str
    status_code: int
    title: str = ""
    form_action_mismatch: bool = False
    payment_harvest_fields: bool = False
    obfuscated_script: bool = False
    foreign_form_hosts: tuple[str, ...] = ()
    payment_field_names: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "final_url": self.final_url,
            "status_code": self.status_code,
            "title": self.title,
            "form_action_mismatch": self.form_action_mismatch,
            "payment_harvest_fields": self.payment_harvest_fields,
            "obfuscated_script": self.obfuscated_script,
            "foreign_form_hosts": list(self.foreign_form_hosts),
            "payment_field_names": list(self.payment_field_names),
        }


async def _resolved_ips(host: str) -> list[ipaddress.ip_address]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    addresses: list[ipaddress.ip_address] = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(str(info[4][0])))
        except ValueError:
            return []
    return addresses


async def is_public_host(host: str) -> bool:
    try:
        addresses = await _resolved_ips(host)
    except Exception:
        return False
    if not addresses:
        return False
    return all(address.is_global for address in addresses)


def _clean_title(html: str) -> str:
    match = TITLE_RE.search(html or "")
    if not match:
        return ""
    title = re.sub(r"\s+", " ", unescape(match.group(1))).strip()
    return title[:160]


async def _read_limited(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size >= MAX_HTML_BYTES:
            break
    return b"".join(chunks)[:MAX_HTML_BYTES]


async def fetch_page_context(domain: str, settings: Settings, *, max_redirects: int = 2) -> PageContext | None:
    clean = str(domain or "").strip().lower().rstrip(".")
    if not clean or "/" in clean or "://" in clean:
        return None

    url = f"https://{clean}/"
    headers = {
        "User-Agent": settings.http_user_agent,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
    }
    if not await is_public_host(clean):
        return None

    try:
        async with httpx.AsyncClient(
            timeout=settings.http_timeout_s,
            headers=headers,
            follow_redirects=False,
        ) as client:
            for _ in range(max_redirects + 1):
                async with client.stream("GET", url) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        if not location:
                            return None
                        redirected = httpx.URL(url).join(location)
                        host = (redirected.host or "").lower()
                        if redirected.scheme not in {"http", "https"} or not await is_public_host(host):
                            return None
                        url = str(redirected)
                        continue
                    content_type = (response.headers.get("content-type") or "").lower()
                    if "html" not in content_type and content_type:
                        return None
                    body = await _read_limited(response)
                    html = body.decode(response.encoding or "utf-8", errors="ignore")
                    host = (httpx.URL(url).host or clean).lower()
                    signals = analyze_html_signals(html, host)
                    return PageContext(
                        final_url=url,
                        status_code=response.status_code,
                        title=_clean_title(html),
                        form_action_mismatch=bool(signals.get("form_action_mismatch")),
                        payment_harvest_fields=bool(signals.get("payment_harvest_fields")),
                        obfuscated_script=bool(signals.get("obfuscated_script")),
                        foreign_form_hosts=tuple(signals.get("foreign_form_hosts") or ()),
                        payment_field_names=tuple(signals.get("payment_field_names") or ()),
                    )
    except Exception:
        return None
    return None


def actionable_from_context(*, score: float, verdict: str, context: dict[str, Any], min_score: float) -> bool:
    """Suppress CT-only noise before it becomes an operator-facing finding."""
    if verdict != "UNKNOWN" or score >= min_score:
        return True
    confirming = (
        bool(context.get("phishtank_confirmed"))
        or bool(context.get("payment_harvest_fields"))
        or bool(context.get("form_action_mismatch"))
        or bool(context.get("obfuscated_script"))
        or float(context.get("clone_score") or 0) >= 1
        or float(context.get("cert_age_hours") or 999_999) < 24
    )
    return confirming
