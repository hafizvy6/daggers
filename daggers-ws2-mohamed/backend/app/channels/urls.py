"""Result-URL normalization for channel adapters (search/maps). Pure.

Result URLs are only ever *scored*; they are never fetched by WS2.
"""
from __future__ import annotations

from typing import Callable
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from ..core import homograph
from .official.registry import is_ip_literal, to_ascii_host

TRACKING_PARAMS = frozenset({
    "gclid", "fbclid", "msclkid", "yclid", "dclid", "mc_eid", "mc_cid", "igshid", "ref_src", "_hsenc", "_hsmi",
})
MAX_URL_LEN = 2048


def unwrap_redirector(raw: str) -> str:
    """Unwrap Google `/url?q=` and DuckDuckGo `/l/?uddg=` result redirectors."""
    value = (raw or "").strip()
    if value.startswith("//"):
        value = "https:" + value
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    host = (parts.hostname or "").lower()
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    if (host.endswith("duckduckgo.com") and parts.path.startswith("/l")) and params.get("uddg"):
        return unquote(params["uddg"])
    if (host.startswith("www.google.") or host.startswith("google.")) and parts.path == "/url":
        target = params.get("q") or params.get("url")
        if target:
            return target
    return value


def normalize_result_url(raw: str) -> tuple[str | None, str | None]:
    """→ (normalized URL, None) or (None, rejection reason)."""
    value = unwrap_redirector(raw)
    if not value or len(value) > MAX_URL_LEN:
        return None, "empty or oversized URL"
    if "://" not in value:
        return None, "relative or schemeless URL"
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None, "malformed URL"
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None, f"scheme '{scheme}' not allowed"
    if parts.username or parts.password:
        return None, "credentials in URL"
    raw_host = parts.hostname or ""
    if is_ip_literal(raw_host):
        host = raw_host
    else:
        host = to_ascii_host(raw_host)
        if not host or "." not in host:
            return None, "invalid host"
    netloc = host if port in (None, 80 if scheme == "http" else 443) else f"{host}:{port}"
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if not k.lower().startswith("utm_") and k.lower() not in TRACKING_PARAMS]
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, urlencode(query, doseq=True), "")), None


def registrable_domain(url: str, suffix_resolver: Callable[[str], str | None] | None = None) -> str:
    host = urlsplit(url).hostname or ""
    if suffix_resolver:
        resolved = suffix_resolver(host)
        if resolved:
            return resolved
    return homograph.simple_registrable(host)


def dedupe_key(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").removeprefix("www.")
    return f"{host}{parts.path.rstrip('/') or '/'}?{parts.query}"


def normalize_query(query: str, max_len: int = 200) -> str:
    return " ".join((query or "").split())[:max_len]
