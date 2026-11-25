from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from ..config import Settings
from .diff import analyze_html_signals


@dataclass(frozen=True)
class RenderResult:
    enabled: bool
    screenshot_path: str | None = None
    html_length: int = 0
    dom_signals: dict | None = None
    error: str | None = None

    def as_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "screenshot_path": self.screenshot_path,
            "html_length": self.html_length,
            "dom_signals": self.dom_signals,
            "error": self.error,
        }


async def render_url(
    url: str,
    screenshot_path: Path,
    *,
    settings: Settings,
    timeout_ms: int | None = None,
) -> RenderResult:
    """Playwright capture with a hard timeout. Never submits forms or accepts downloads."""
    if not settings.render_enabled:
        return RenderResult(enabled=False, error="render disabled")
    try:
        from playwright.async_api import async_playwright  # type: ignore[import-not-found]
    except ImportError:
        return RenderResult(enabled=False, error="playwright unavailable")

    screenshot_path.parent.mkdir(parents=True, exist_ok=True)
    timeout = int(timeout_ms or settings.render_timeout_ms)
    host = (urlparse(url if "://" in url else f"https://{url}").hostname or "").lower()
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
            try:
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    accept_downloads=False,
                    user_agent=settings.http_user_agent,
                    java_script_enabled=True,
                )

                async def guard_requests(route) -> None:
                    # Defense in depth: our code never fills or submits a form,
                    # and non-read requests from a page are aborted too.
                    if route.request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
                        await route.abort()
                    else:
                        await route.continue_()

                page = await context.new_page()
                await page.route("**/*", guard_requests)
                page.set_default_navigation_timeout(timeout)
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
                await page.wait_for_timeout(2000)
                await page.screenshot(path=str(screenshot_path), full_page=True, timeout=timeout)
                html = await page.content()
                return RenderResult(
                    enabled=True,
                    screenshot_path=str(screenshot_path),
                    html_length=len(html),
                    dom_signals=analyze_html_signals(html, host),
                )
            finally:
                await browser.close()
    except Exception as exc:  # renderer failure must never break the brain
        return RenderResult(enabled=True, error=type(exc).__name__)


async def render_for_finding(finding: dict, settings: Settings) -> RenderResult:
    domain = str(finding.get("domain", ""))
    url = f"https://{domain}/"
    screenshot = settings.evidence_dir / f"shot_{int(finding.get('id') or 0)}.jpg"
    return await render_url(url, screenshot, settings=settings)


async def render_for_reference(official_domain: str, settings: Settings) -> RenderResult:
    """Capture the real official page used as the left side of an evidence pack."""
    host = str(official_domain).strip().lower().rstrip(".")
    if not host or "://" in host or "/" in host:
        return RenderResult(enabled=False, error="invalid official domain")
    safe = re.sub(r"[^a-z0-9.-]+", "-", host).strip("-") or "official"
    screenshot = settings.gallery_dir / f"reference_{safe}.jpg"
    return await render_url(f"https://{host}/", screenshot, settings=settings)
