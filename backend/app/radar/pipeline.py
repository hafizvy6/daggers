from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Callable, Mapping

from ..catalog import Catalog
from ..config import Heartbeats, Settings
from ..core import homograph, scorer, verdicts
from ..vision import diff, render
from .crt import CrtPoller
from .cursors import Cursors
from .enrich import Enricher, parse_age_hours
from .feeds import PhishFeeds

logger = logging.getLogger("daggers.radar")


class RadarPipeline:
    """One in-process asyncio pipeline: live ingest → score → evidence → report → SSE."""

    def __init__(
        self,
        *,
        repo,
        settings: Settings,
        catalog: Catalog,
        report_queue,
        publish: Callable[[str, dict], None],
        heartbeats: Heartbeats,
        status_getter: Callable[[], dict] | None = None,
    ) -> None:
        self.repo = repo
        self.settings = settings
        self.catalog = catalog
        self.report_queue = report_queue
        self.publish = publish
        self.heartbeats = heartbeats
        self.status_getter = status_getter
        self.cursors = Cursors(repo)
        self.crt = CrtPoller(settings, catalog, self.cursors)
        self.feeds = PhishFeeds(settings, catalog, repo, self.cursors)
        self.enricher = Enricher(settings, catalog)
        self.tasks: list[asyncio.Task] = []

    async def start(self) -> None:
        self.tasks = [
            asyncio.create_task(self._radar_loop(), name="daggers-radar"),
            asyncio.create_task(self._feed_loop(), name="daggers-feeds"),
            asyncio.create_task(self._enrich_loop(), name="daggers-enrich"),
            asyncio.create_task(self._heartbeat_loop(), name="daggers-heartbeat"),
        ]

    async def stop(self) -> None:
        for task in self.tasks:
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks = []

    def _confirmed(self, domain: str, confirmed: set[str]) -> bool:
        forms = homograph.host_forms(domain)
        candidates = {str(forms["unicode_host"]), str(forms["punycode_host"])}
        for value in confirmed:
            other = homograph.host_forms(value)
            if {str(other["unicode_host"]), str(other["punycode_host"])} & candidates:
                return True
        return False

    def _official_brand(self, domain: str, text: str) -> dict | None:
        """Resolve the catalogued official domain a real CT row appears to imitate."""
        needle = homograph.confusable_fold(f"{domain} {text}").casefold()
        for brand in self.catalog.brands:
            tokens = [str(brand["token"]), *[str(alias) for alias in brand.get("aliases", [])]]
            if any(len(token) >= 4 and token.casefold() in needle for token in tokens):
                return brand
        return None

    def _context_for_row(self, row: Mapping, confirmed: set[str]) -> dict:
        domain = str(row.get("domain", ""))
        age = row.get("cert_age_hours")
        if age is None:
            age = parse_age_hours(row.get("cert_issued"))
        return {
            "cert_age_hours": age,
            "phishtank_confirmed": bool(row.get("phishtank_confirmed")) or self._confirmed(domain, confirmed),
            "clone_score": float(row.get("clone_score") or row.get("clone") or 0),
            "gallery_match": row.get("gallery_match"),
            "form_action_mismatch": bool(row.get("form_action_mismatch")),
            "payment_harvest_fields": bool(row.get("payment_harvest_fields")),
            "obfuscated_script": bool(row.get("obfuscated_script")),
        }

    def _already_processed(self, row: Mapping) -> bool:
        domain = str(row.get("domain", ""))
        existing = self.repo.get_domain(domain)
        return bool(existing and existing.get("enqueued") and not row.get("force"))

    async def process_domain(self, row: Mapping, confirmed: set[str] | None = None) -> dict:
        confirmed = confirmed or set()
        domain = str(row.get("domain", ""))
        if not domain:
            raise ValueError("radar row needs a domain")
        text = str(row.get("text") or domain)
        context = self._context_for_row(row, confirmed)
        score_result = scorer.score_url(
            f"https://{domain}/",
            brands=list(self.catalog.brands),
            lures={key: list(value) for key, value in self.catalog.lures.items()},
            context=context,
            suffix_resolver=self.catalog.suffix_resolver,
            text=text,
            thresholds=self.settings.thresholds,
        )
        policy = verdicts.policy(
            score_result.verdict,
            score_result.score,
            context["clone_score"],
            thresholds=self.settings.thresholds,
            guard_block_misleading=self.settings.guard_block_misleading,
        )
        finding = self.repo.insert_finding(
            domain=domain,
            source=str(row.get("source") or "radar"),
            first_seen=str(row.get("first_seen") or ""),
            cert_issued=row.get("cert_issued"),
            score=score_result.score,
            verdict=score_result.verdict,
            reasons=score_result.reasons,
            l1_detail=score_result.l1_detail,
            rendered=False,
            evidence_path=row.get("evidence_url"),
            gallery_match=row.get("gallery_match"),
            clone_score=context["clone_score"],
            created_at=row.get("first_seen"),
            is_case_file=bool(row.get("is_case_file")),
            enqueued=True,
        )

        screenshot: Path | None = None
        reference: Path | None = None
        clone = context["clone_score"]
        dom_signals: dict = {}
        official_domain = row.get("gallery_match")

        if self.settings.render_enabled and policy["render"]:
            rendered = await render.render_for_finding(finding, self.settings)
            screenshot = Path(rendered.screenshot_path) if rendered.screenshot_path else None
            dom_signals = rendered.dom_signals or {}
            brand = self._official_brand(domain, text)
            if brand and screenshot and screenshot.exists() and str(brand["official_domain"]) != domain:
                reference_result = await render.render_for_reference(str(brand["official_domain"]), self.settings)
                reference = Path(reference_result.screenshot_path) if reference_result.screenshot_path else None
                official_domain = str(brand["official_domain"])
            if screenshot and reference and screenshot.exists() and reference.exists():
                clone = diff.clone_similarity(screenshot, reference, brand_hit=score_result.brand_hit)

        vision_context = {
            **context,
            "clone_score": clone,
            "gallery_match": official_domain,
            "form_action_mismatch": bool(dom_signals.get("form_action_mismatch")),
            "payment_harvest_fields": bool(dom_signals.get("payment_harvest_fields")),
            "obfuscated_script": bool(dom_signals.get("obfuscated_script")),
        }
        rescored = scorer.score_url(
            f"https://{domain}/",
            brands=list(self.catalog.brands),
            lures={key: list(value) for key, value in self.catalog.lures.items()},
            context=vision_context,
            suffix_resolver=self.catalog.suffix_resolver,
            text=text,
            thresholds=self.settings.thresholds,
        )

        evidence_path: str | None = None
        destination = self.settings.evidence_dir / f"{finding['id']}.jpg"
        if screenshot and reference and screenshot.exists() and reference.exists():
            composed = diff.create_comparison_evidence(
                screenshot,
                reference,
                finding,
                destination,
                clone,
            )
            if composed is not None:
                evidence_path = f"/evidence/{finding['id']}.jpg"

        finding = self.repo.update_finding_analysis(
            finding["id"],
            score=rescored.score,
            verdict=rescored.verdict,
            reasons=rescored.reasons,
            l1_detail=rescored.l1_detail,
            clone_score=clone,
            gallery_match=official_domain,
            evidence_path=evidence_path,
            rendered=bool(evidence_path),
        ) or finding

        self.report_queue.maybe_auto_file(finding)
        self.report_queue.submit_queued(limit=1)
        self.publish("finding", finding)
        self.heartbeats.mark("pipeline")
        return finding

    async def _live_tick(self) -> None:
        rows = await self.crt.poll_once()
        confirmed = await self.feeds.poll_once()
        for row in rows:
            if self._already_processed(row):
                continue
            await self.process_domain(row, confirmed)
        self.heartbeats.mark("crt")
        self.heartbeats.mark("phishtank")

    async def _radar_loop(self) -> None:
        while True:
            try:
                await self._live_tick()
                await asyncio.sleep(self.settings.crt_poll_interval_s)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("radar tick failed")
                await asyncio.sleep(self.settings.pipeline_poll_interval_s)

    async def _feed_loop(self) -> None:
        while True:
            await asyncio.sleep(self.settings.feed_poll_interval_s)
            try:
                await self.feeds.poll_once()
                self.heartbeats.mark("phishtank")
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("feed tick failed")

    async def _enrich_loop(self) -> None:
        while True:
            await asyncio.sleep(max(10, self.settings.pipeline_poll_interval_s * 5))
            if not self.settings.enrich_enabled:
                continue
            try:
                for row in self.repo.unprocessed_domains(limit=10):
                    enriched = await self.enricher.enrich(
                        str(row["domain"]),
                        cert_issued=row.get("tls_issued"),
                    )
                    self.repo.upsert_domain(
                        str(row["domain"]),
                        first_seen=row.get("first_seen"),
                        rdap_created=enriched.get("rdap_created"),
                        rdap_registrar=enriched.get("rdap_registrar"),
                        dns_a=enriched.get("dns_a") or [],
                        tls_issued=enriched.get("tls_issued"),
                        tls_issuer=enriched.get("tls_issuer"),
                        favicon_hash=enriched.get("favicon_hash"),
                        enqueued=True,
                    )
                    self.repo.mark_enqueued(str(row["domain"]))
                    self.heartbeats.mark("pipeline")
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("enrichment tick failed")

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(self.settings.heartbeat_interval_s)
            self.heartbeats.mark("pipeline")
            if self.status_getter:
                self.publish("heartbeat", self.status_getter())
