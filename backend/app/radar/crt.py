from __future__ import annotations

import time
from datetime import datetime, timezone

import httpx

from ..catalog import Catalog
from ..config import Settings
from ..core import scorer
from .cursors import Cursors


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class CrtPoller:
    """crt.sh CT-log adapter. Disabled by default; live polling is rate-limited."""

    CRT_URL = "https://crt.sh/"

    def __init__(self, settings: Settings, catalog: Catalog, cursors: Cursors) -> None:
        self.settings = settings
        self.catalog = catalog
        self.cursors = cursors

    def _registrable(self, value: str) -> str | None:
        name = str(value).strip().lower().lstrip("*.")
        if not name or any(char.isspace() for char in name):
            return None
        try:
            normalized = scorer.normalize_url(name, self.catalog.suffix_resolver)
        except Exception:
            return None
        return normalized.registrable_domain or normalized.unicode_host or None

    async def poll_once(self) -> list[dict]:
        if not self.settings.crt_enabled:
            return []
        now = time.time()
        last = float(self.cursors.get("crt_last_query_ts", 0) or 0)
        if now - last < self.settings.crt_min_query_gap_s:
            return []
        tokens = [str(brand["token"]) for brand in self.catalog.brands[:36]]
        if not tokens:
            return []
        index = self.cursors.get_int("crt_query_index", 0)
        token = tokens[index % len(tokens)]
        self.cursors.set("crt_query_index", index + 1)
        self.cursors.set("crt_last_query_ts", now)

        params = {"q": f"%.{token}%", "output": "json"}
        headers = {"User-Agent": self.settings.http_user_agent, "Accept": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=self.settings.http_timeout_s, headers=headers) as client:
                response = await client.get(self.CRT_URL, params=params)
                response.raise_for_status()
                payload = response.json()
        except Exception:
            return []
        if not isinstance(payload, list):
            return []

        rows: list[dict] = []
        seen: set[str] = set()
        issued = _now()
        for entry in payload[:200]:
            names = str(entry.get("name_value") or entry.get("common_name") or "").splitlines()
            cert_names = [name.strip() for name in names if name.strip()]
            timestamp = str(entry.get("entry_timestamp") or entry.get("not_before") or issued)
            for name in cert_names:
                domain = self._registrable(name)
                if not domain or domain in seen:
                    continue
                seen.add(domain)
                rows.append(
                    {
                        "domain": domain,
                        "source": "crt.sh",
                        "cert_names": cert_names[:10],
                        "cert_issued": timestamp,
                        "first_seen": issued,
                        "is_case_file": False,
                        "brand_hit": True,
                    }
                )
                if len(rows) >= 25:
                    return rows
        return rows
