"""Optional, authorized police-intake adapter.

The portal is always the system of record. A live external submission happens
only when an operator explicitly configures it; otherwise reports remain
QUEUED. No user data is accepted by this boundary — evidence has already passed
validate_zero_pii() in the report queue.
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import httpx

from ..config import Settings

logger = logging.getLogger("daggers.intake")


class PoliceIntakeResult(dict):
    @property
    def submitted(self) -> bool:
        return bool(self.get("submitted"))


class PoliceIntakeClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def configured(self) -> bool:
        if not self.settings.police_intake_enabled:
            return False
        url = str(self.settings.police_intake_url or "").strip()
        if not url:
            return False
        parsed = urlparse(url)
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            return False
        return bool(parsed.hostname)

    async def submit_report(self, report: dict[str, Any]) -> PoliceIntakeResult:
        if not self.configured:
            return PoliceIntakeResult(submitted=False, status="QUEUED", reason="police intake not configured")

        # Deliberately flat, explicit payload — never forward request headers,
        # cookies, session IDs, user IPs, or arbitrary report metadata.
        payload = {
            "schema": "daggers.police.report.v1",
            "report_id": int(report["id"]),
            "finding_id": int(report["finding_id"]),
            "evidence": report.get("evidence") or {},
            "blocked_hits": int(report.get("blocked_hits") or 0),
            "auto": bool(report.get("auto")),
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": self.settings.http_user_agent}
        if self.settings.police_intake_token:
            headers["Authorization"] = f"Bearer {self.settings.police_intake_token}"
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.police_intake_timeout_s,
                headers=headers,
                follow_redirects=False,
            ) as client:
                response = await client.post(self.settings.police_intake_url, json=payload)
            if 200 <= response.status_code < 300:
                return PoliceIntakeResult(submitted=True, status="SUBMITTED", intake_status=response.status_code)
            return PoliceIntakeResult(
                submitted=False,
                status="QUEUED",
                reason=f"police intake rejected submission (HTTP {response.status_code})",
            )
        except Exception as exc:  # external intake must not break the radar
            logger.warning("police intake submission failed: %s", type(exc).__name__)
            return PoliceIntakeResult(submitted=False, status="QUEUED", reason="police intake unavailable")
