"""Feed keys: exact URL vs host. Shared by the radar feed poller (writing) and the Checker (reading)."""
from __future__ import annotations

from urllib.parse import urlsplit

FEED_FRESH_HOURS = 48


def url_key(url: str) -> tuple[str, str] | None:
    """→ (key, host). Scheme-less, host lower-cased, fragment dropped, path/query kept exactly."""
    value = (url or "").strip().replace("hxxp://", "http://").replace("hxxps://", "https://")
    if not value:
        return None
    if "://" not in value:
        value = "http://" + value
    try:
        parts = urlsplit(value)
        host = (parts.hostname or "").rstrip(".").lower()
    except ValueError:
        return None
    if not host:
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    path = parts.path or "/"
    key = host + path + (f"?{parts.query}" if parts.query else "")
    return key, host
