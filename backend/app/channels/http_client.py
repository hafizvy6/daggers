"""Minimal outbound HTTP for FIXED provider endpoints (Serper, DuckDuckGo, Places).

Only hosts in ``PROVIDER_HOSTS`` can be contacted, only over HTTPS, with a
timeout and a size cap. User- or website-supplied URLs never reach this module.
Stdlib only (httpx is not required here).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import urlsplit

PROVIDER_HOSTS = frozenset({"google.serper.dev", "html.duckduckgo.com", "places.googleapis.com"})
USER_AGENT = "Daggers-Research/1.0"


class ProviderError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # pragma: no cover - live only
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    json_body: dict | None = None,
    form: bytes | None = None,
    timeout: float = 8.0,
    max_bytes: int = 1_500_000,
) -> bytes:  # pragma: no cover - live network only; tests inject fakes
    parts = urlsplit(url)
    if parts.scheme != "https" or (parts.hostname or "") not in PROVIDER_HOSTS:
        raise ProviderError("endpoint not in the provider allowlist")
    data = json.dumps(json_body).encode() if json_body is not None else form
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", USER_AGENT)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    if json_body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise ProviderError(f"HTTP {resp.status}")
            body = resp.read(max_bytes + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ProviderError(type(exc).__name__) from exc
    if len(body) > max_bytes:
        raise ProviderError("response too large")
    return body
