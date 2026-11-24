from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Callable, Mapping

from ..catalog import Catalog
from ..config import Heartbeats, Settings
from ..core import homograph, scorer, verdicts
from ..vision import diff, gallery, render
from .crt import CrtPoller
from .cursors import Cursors
from .enrich import Enricher, parse_age_hours
from .feeds import PhishFeeds

logger = logging.getLogger("daggers.radar")


class RadarPipeline:
    """One in-process asyncio pipeline: ingest → score → evidence → report → SSE."""

    def __init__(
        self,
        *,
        repo,
        settings: Settings,
        catalog: Catalog,
        report_queue,
        publish: Callable[[str, dict], None],
        heartbeats: Heartbeats,
        mode_getter: Callable[[], str],
        status_getter: Callable[[], dict] | None = None,
    ) -> None:
        self.repo = repo
        self.settings = settings
        self.catalog = catalog
        self.report_queue = report_queue
        self.publish = publish
        self.heartbeats = heartbeats
        self.mode_getter = mode_getter
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

    def _gallery_index(self) -> Path:
        return self.settings.seed_dir / "gallery_index.json"

    def _confirmed(self, domain: str, confirmed: set[str]) -> bool:
        forms = homograph.host_forms(domain)
        candidates = {str(forms["unicode_host"]), str(forms["punycode_host"])}
        for value in confirmed:
            other = homograph.host_forms(value)
            if {str(other["unicode_host"]), str(other["punycode_host"])} & candidates:
                return True
        return False

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
        context = self._context_for_row(row, confirmed)
        score_result = scorer.score_url(
            f"https://{domain}/",
            brands=list(self.catalog.brands),
            lures={key: list(value) for key, value in self.catalog.lures.items()},
            context=context,
            suffix_resolver=self.catalog.suffix_resolver,
            text=str(row.get("text") or domain),
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

        evidence_path = f"/evidence/{finding['id']}.jpg"
        destination = self.settings.evidence_dir / f"{finding['id']}.jpg"
        if self.settings.render_enabled and policy["render"]:
            rendered = await render.render_for_finding(finding, self.settings)
            screenshot = Path(rendered.screenshot_path) if rendered.screenshot_path else None
            index = gallery.load_gallery(self._gallery_index())
            match = gallery.best_match(screenshot, index) if screenshot else None
            reference = (
                self.settings.gallery_dir / Path(str(match["entry"].get("path", ""))).name
                if match
                else None
            )
            if screenshot and reference and reference.exists():
                clone = diff.clone_similarity(screenshot, reference, brand_hit=score_result.brand_hit)
                signals = rendered.dom_signals or {}
                vision_context = {
                    **context,
                    "clone_score": clone,
                    "gallery_match": match["entry"].get("url") if match else row.get("gallery_match"),
                    "form_action_mismatch": bool(signals.get("form_action_mismatch")),
                    "payment_harvest_fields": bool(signals.get("payment_harvest_fields")),
                    "obfuscated_script": bool(signals.get("obfuscated_script")),
                }
                rescored = scorer.score_url(
                    f"https://{domain}/",
                    brands=list(self.catalog.brands),
                    lures={key: list(value) for key, value in self.catalog.lures.items()},
                    context=vision_context,
                    suffix_resolver=self.catalog.suffix_resolver,
                    text=str(row.get("text") or domain),
                    thresholds=self.settings.thresholds,
                )
                diff.create_comparison_evidence(
                    screenshot,
                    reference,
                    finding,
                    destination,
                    clone,
                )
                finding = self.repo.update_finding_analysis(
                    finding["id"],
                    score=rescored.score,
                    verdict=rescored.verdict,
                    reasons=rescored.reasons,
                    l1_detail=rescored.l1_detail,
                    clone_score=clone,
                    gallery_match=vision_context["gallery_match"],
                    evidence_path=evidence_path,
                    rendered=True,
                ) or finding
            else:
                diff.ensure_evidence_image(finding, destination, self.settings.gallery_dir)
                if destination.exists():
                    finding = self.repo.set_finding_evidence(finding["id"], evidence_path) or finding
        elif policy["render"] or score_result.verdict in {"MALICIOUS", "MISLEADING"}:
            diff.ensure_evidence_image(finding, destination, self.settings.gallery_dir)
            if destination.exists():
                finding = self.repo.set_finding_evidence(finding["id"], evidence_path) or finding

        self.report_queue.maybe_auto_file(finding)
        self.report_queue.submit_queued(limit=1)
        self.publish("finding", finding)
        self.heartbeats.mark("pipeline")
        return finding

    async def _demo_tick(self) -> None:
        findings = self.repo.demo_findings()
        if findings:
            index = self.cursors.get_int("demo_feed", 0)
            self.publish("finding", findings[index % len(findings)])
            self.cursors.set_int("demo_feed", index + 1)
        self.heartbeats.mark("crt")
        self.heartbeats.mark("phishtank")
        self.heartbeats.mark("pipeline")

    async def _live_tick(self) -> None:
        rows = await self.crt.poll_once("live")
        confirmed = await self.feeds.poll_once("live")
        if confirmed:
            self.repo.upsert_feed_labels(confirmed, source="feeds")
        for row in rows:
            if self._already_processed(row):
                continue
            await self.process_domain(row, confirmed)
        self.heartbeats.mark("crt")
        self.heartbeats.mark("phishtank")

    async def _radar_loop(self) -> None:
        while True:
            try:
                if self.mode_getter() == "demo":
                    await self._demo_tick()
                    await asyncio.sleep(max(5, self.settings.heartbeat_interval_s * 2))
                else:
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
                await self.feeds.poll_once(self.mode_getter())
                self.heartbeats.mark("phishtank")
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("feed tick failed")

    async def _enrich_loop(self) -> None:
        while True:
            await asyncio.sleep(max(10, self.settings.pipeline_poll_interval_s * 5))
            if self.mode_getter() == "demo":
                continue
            try:
                for row in self.repo.unprocessed_domains(limit=10):
                    enriched = await self.enricher.enrich(
                        str(row["domain"]),
                        cert_issued=row.get("tls_issued"),
                        mode="live",
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
