"""Search, Maps, Sweep, Guard, privacy and URL handling. Synthetic doubles live only under tests."""
from __future__ import annotations

import json
import unittest
from datetime import timedelta

from backend.tests.ws2 import helpers
from backend.app.channels import privacy, urls
from backend.app.channels.guard import GuardSync, build_blocklist, render
from backend.app.channels.http_client import ProviderError
from backend.app.channels.maps import Listing, MapsChannel
from backend.app.channels.search import (
    DuckDuckGoProvider, SearchChannel, SerperProvider, TTLCache, default_providers, parse_ddg_html,
)
from backend.app.channels.sweep import RateLimiter, SweepError, SweepService, load_queries
from backend.app.channels.sweep_store import InMemorySweepStore, RepoSweepStore, make_store
from backend.app.channels.official.registry import Registry


def prod_scorer():
    """Production registry (all pending) — no synthetic record is auto-approved."""
    return helpers.scorer(records=[], registry=Registry.load())


class TestUrls(unittest.TestCase):
    def test_normalization_and_unwrapping(self):
        n = urls.normalize_result_url
        self.assertEqual(n("https://www.google.com/url?q=https://a.example/x%3Futm_source%3Dz%26id%3D1&sa=U")[0],
                         "https://a.example/x?id=1")
        self.assertEqual(n("//duckduckgo.com/l/?uddg=https%3A%2F%2Fb.example%2Fp&rut=1")[0], "https://b.example/p")
        self.assertEqual(n("HTTPS://Ex.Example:443/a#frag")[0], "https://ex.example/a")
        self.assertEqual(n("https://аmazon.example/")[0], "https://xn--mazon-3ve.example/")
        for bad in ("javascript:alert(1)", "data:text/html,x", "/relative", "https://u:p@x.example/", "ftp://x.example/", ""):
            self.assertIsNone(n(bad)[0], bad)

    def test_dedupe_key(self):
        self.assertEqual(urls.dedupe_key("https://www.a.example/x/"), urls.dedupe_key("http://a.example/x"))


class TestPrivacy(unittest.TestCase):
    def test_pii_detection_and_redaction(self):
        self.assertEqual(privacy.pii_kinds("pay abu dhabi police fines"), [])
        self.assertIn("email", privacy.pii_kinds("contact me@mail.example"))
        self.assertIn("emirates_id", privacy.pii_kinds("784-1990-1234567-1"))
        self.assertIn("phone", privacy.pii_kinds("call +971 50 123 4567"))
        self.assertIn("iban", privacy.pii_kinds("AE07 0331 2345 6789 0123 456"))
        red = privacy.redact("Call +971 50 123 4567 or mail a@b.example")
        self.assertNotIn("4567", red)
        self.assertNotIn("a@b.example", red)


class FailingProvider:
    name, source_kind = "serper", "live"

    def search(self, *_):
        raise ProviderError("timeout")


class CountingLive:
    name, source_kind = "duckduckgo", "live"

    def __init__(self):
        self.calls = 0

    def search(self, query, lang, limit):
        from backend.app.channels.search import RawResult
        self.calls += 1
        return [RawResult("https://live-result.example/", "Live", "snippet")]


class TestSearch(unittest.TestCase):
    def test_test_double_run_is_deduped_and_scored(self):
        run = SearchChannel(prod_scorer(), providers=[helpers.TestSearchProvider()]).run("pay abu dhabi police traffic fines online")
        self.assertEqual(run.source_kind, "fixture")
        self.assertEqual(run.engine, "unit_test")
        self.assertEqual(run.rejected, 1)  # javascript: URL
        found = [r["url"] for r in run.results]
        self.assertEqual(len(found), len(set(urls.dedupe_key(u) for u in found)))
        official = next(r for r in run.results if "adpolice.gov.ae" in r["url"])
        self.assertEqual(official["domain_auth"]["status"], "PENDING")
        self.assertEqual(official["tag"], "WARNING")  # real registry still pending → never SAFE
        self.assertFalse(any(r["tag"] == "SAFE" for r in run.results))
        self.assertTrue(any(r["tag"] == "FAKE" for r in run.results))
        self.assertTrue(all("4567" not in r["snippet"] for r in run.results))  # PII redacted

    def test_live_failure_never_falls_back_to_test_data(self):
        run = SearchChannel(prod_scorer(), providers=[FailingProvider()]).run("anything")
        self.assertEqual(run.source_kind, "unavailable")
        self.assertEqual(run.results, [])
        self.assertEqual(run.errors, ["serper: ProviderError"])

    def test_live_results_are_cached_and_marked(self):
        live = CountingLive()
        channel = SearchChannel(prod_scorer(), providers=[live], cache=TTLCache())
        self.assertEqual(channel.run("q").source_kind, "live")
        second = channel.run("q")
        self.assertEqual((second.source_kind, second.cached, live.calls), ("cached", True, 1))

    def test_serper_uses_organic_only(self):
        payload = {"organic": [{"link": "https://o.example/", "title": "t", "snippet": "s"}],
                   "ads": [{"link": "https://ad.example/"}], "places": [{"link": "https://maps.example/"}]}
        provider = SerperProvider("k", http=lambda *a, **k: json.dumps(payload).encode())
        self.assertEqual([r.url for r in provider.search("q", "en", 10)], ["https://o.example/"])

    def test_ddg_parser(self):
        html = ('<div class="result"><a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fr.example%2F">R'
                '</a><a class="result__snippet">snip</a></div>'
                '<a class="result__a" href="https://duckduckgo.com/y.js?ad=1">Ad</a>')
        results = parse_ddg_html(html)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].title, "R")
        provider = DuckDuckGoProvider(http=lambda *a, **k: html.encode())
        self.assertEqual(len(provider.search("q", "en", 5)), 1)

    def test_live_providers_are_opt_in_and_no_fixture_is_available(self):
        self.assertEqual(default_providers({}), [])
        names = [p.name for p in default_providers({"SEARCH_LIVE_ENABLED": "1", "SERPER_API_KEY": "x"})]
        self.assertEqual(names, ["serper", "duckduckgo"])
        unconfigured = SearchChannel(prod_scorer(), providers=default_providers({})).run("q")
        self.assertEqual(unconfigured.source_kind, "unconfigured")
        self.assertEqual(unconfigured.results, [])


class TestMaps(unittest.TestCase):
    def setUp(self):
        self.channel = MapsChannel(prod_scorer(), providers=[helpers.TestMapsProvider()])

    def test_separate_evidence_per_check(self):
        result = self.channel.run("police service centre abu dhabi")
        self.assertEqual(result["source_kind"], "fixture")
        by_id = {i["listing"]["provider_place_id"]: i for i in result["listings"]}
        fake_office = by_id["syn-place-2"]
        self.assertEqual(set(fake_office["checks"]), {"identity", "website", "phone"})
        self.assertEqual(fake_office["checks"]["phone"]["verdict"], "MALICIOUS")
        self.assertEqual(fake_office["checks"]["identity"]["status"], "mismatch")
        self.assertEqual(fake_office["tag"], "FAKE")
        bakery = by_id["syn-place-3"]
        self.assertEqual(bakery["checks"]["website"]["status"], "not_provided")
        self.assertEqual(bakery["checks"]["phone"]["status"], "not_provided")
        self.assertEqual(bakery["tag"], "WARNING")  # missing info is not fraud, but not SAFE either
        self.assertTrue(all(i["listing"]["is_synthetic"] for i in result["listings"]))

    def test_authenticated_website_with_consistent_identity_can_be_safe(self):
        channel = MapsChannel(helpers.scorer(), providers=[])
        item = channel.assess_listing(Listing("unit_test_maps", "p", "Synthetic Police Centre", website="https://police.gov.example/",
                                              phone="+971 2 555 1234", synthetic=True, source_kind="fixture"))
        self.assertEqual(item["checks"]["identity"]["status"], "consistent")
        self.assertEqual(item["tag"], "SAFE")


class TestSweep(unittest.TestCase):
    def make(self, **kw):
        scorer = prod_scorer()
        events = []
        service = SweepService(
            search_channel=SearchChannel(scorer, providers=[helpers.TestSearchProvider()]),
            maps_channel=MapsChannel(scorer, providers=[helpers.TestMapsProvider()]),
            store=InMemorySweepStore(), publish=lambda e, d: events.append((e, d)), **kw)
        return service, events

    def test_default_queries_are_valid(self):
        queries = load_queries()
        self.assertTrue({q["channel"] for q in queries} == {"web", "maps"})

    def test_web_and_maps_runs_round_trip(self):
        service, events = self.make(allow_arbitrary=False)
        run = service.run(channel="web", query_id="web-adpolice-fines", client="1.1.1.1")
        self.assertEqual(run["store"], "memory-temporary")
        self.assertTrue(run["synthetic"])  # the unit-test double declares itself synthetic
        self.assertEqual(sum(run["counts"].values()), len(run["results"]))
        self.assertEqual(service.get(run["id"])["results"], run["results"])
        self.assertEqual(events[0][0], "sweep")
        maps = service.run(channel="maps", client="1.1.1.1")
        self.assertTrue(all(r["maps"] for r in maps["results"]))
        self.assertIsNone(service.get(99999))

    def test_product_channels_are_empty_when_unconfigured(self):
        scorer = prod_scorer()
        service = SweepService(
            search_channel=SearchChannel(scorer, providers=[]),
            maps_channel=MapsChannel(scorer, providers=[]),
            store=InMemorySweepStore(),
        )
        web = service.run(channel="web", query_id="web-adpolice-fines")
        self.assertEqual(web["status"], "failed")   # honest failure, never sample results
        self.assertEqual(web["results"], [])
        self.assertIn("no live provider configured", web["error"])
        maps = service.run(channel="maps")
        self.assertEqual(maps["status"], "failed")
        self.assertEqual(maps["results"], [])

    def test_arbitrary_queries_need_opt_in_and_no_pii(self):
        service, _ = self.make(allow_arbitrary=False)
        with self.assertRaises(SweepError) as ctx:
            service.run(channel="web", query="some new query")
        self.assertEqual(ctx.exception.status, 403)
        # exact default text is always allowed
        service.run(channel="web", query="UAE visa amnesty registration")
        open_service, _ = self.make(allow_arbitrary=True)
        open_service.run(channel="web", query="some new query")
        with self.assertRaises(SweepError) as ctx:
            open_service.run(channel="web", query="scam call from +971 50 123 4567")
        self.assertEqual(ctx.exception.status, 422)
        with self.assertRaises(SweepError):
            open_service.run(channel="web", query="x" * 500)
        with self.assertRaises(SweepError):
            open_service.run(channel="sms")

    def test_rate_limit(self):
        t = [0.0]
        service, _ = self.make(allow_arbitrary=False, limiter=RateLimiter(per_minute=2, clock=lambda: t[0]))
        service.run(channel="web", client="9.9.9.9")
        service.run(channel="web", client="9.9.9.9")
        with self.assertRaises(SweepError) as ctx:
            service.run(channel="web", client="9.9.9.9")
        self.assertEqual(ctx.exception.status, 429)
        service.run(channel="web", client="8.8.8.8")
        t[0] = 61
        service.run(channel="web", client="9.9.9.9")

    def test_store_selection(self):
        self.assertIsInstance(make_store(object()), InMemorySweepStore)

        class Repo:
            def create_sweep_run(self, **kw): return {"id": 1, **kw, "created_at": "x"}
            def add_sweep_results(self, run_id, rows): pass
            def get_sweep_run(self, run_id): return None
            def update_sweep_run(self, run_id, **fields): pass
            def list_sweep_runs(self, limit=50): return []

        self.assertIsInstance(make_store(Repo()), RepoSweepStore)


class TestGuard(unittest.TestCase):
    def rows(self):
        recent = "2026-11-24T08:00:00Z"
        return [
            {"domain": "adcb-secure-login.xyz", "verdict": "MALICIOUS", "reason": "r", "flagged_at": recent},
            {"domain": "adcb-secure-login.xyz", "verdict": "MALICIOUS", "reason": "dup", "flagged_at": recent},
            {"domain": "xn--mazon-3ve.ae", "verdict": "MALICIOUS", "reason": "r", "flagged_at": recent},
            {"domain": "giveaway.top", "verdict": "MISLEADING", "reason": "claim", "flagged_at": recent},
            {"domain": "unknown.example", "verdict": "UNKNOWN", "reason": "", "flagged_at": recent},
            {"domain": "old-scam.xyz", "verdict": "MALICIOUS", "reason": "r", "flagged_at": "2026-01-01T00:00:00Z"},
            {"domain": "10.0.0.1", "verdict": "MALICIOUS", "reason": "r", "flagged_at": recent},
            {"domain": "bad domain!", "verdict": "MALICIOUS", "reason": "r", "flagged_at": recent},
            {"domain": "www.adpolice.gov.ae", "verdict": "MALICIOUS", "reason": "compromised?", "flagged_at": recent},
            {"domain": "adcb.ae", "verdict": "MALICIOUS", "reason": "?", "flagged_at": recent},
            {"domain": "nodate.xyz", "verdict": "MALICIOUS", "reason": "r"},
            {"domain": "future.xyz", "verdict": "MALICIOUS", "reason": "r", "flagged_at": "2099-01-01T00:00:00Z"},
        ]

    def test_only_confirmed_malicious_valid_recent_non_official(self):
        result = build_blocklist(self.rows(), registry=Registry.load(),
                                 official_domains=helpers.catalog().official_domains, now=helpers.NOW)
        self.assertEqual(result.domains, ["adcb-secure-login.xyz", "xn--mazon-3ve.ae"])
        self.assertEqual(result.excluded, {"not_malicious": 2, "invalid_domain": 2, "expired": 1, "undated": 2,
                                           "duplicate": 1, "official_or_registry": 2})
        hosts = render(result, "hosts")
        self.assertIn("0.0.0.0 adcb-secure-login.xyz", hosts)
        self.assertNotIn("giveaway.top", hosts)
        self.assertEqual([l for l in render(result, "domains").splitlines() if not l.startswith("#")],
                         ["adcb-secure-login.xyz", "xn--mazon-3ve.ae"])

    def test_sync_status_and_feed_failure_keeps_last_good(self):
        state = {"fail": False}

        def source():
            if state["fail"]:
                raise RuntimeError("down")
            return self.rows()

        now = [helpers.NOW]
        sync = GuardSync(Registry.load(), helpers.catalog().official_domains, source, clock=lambda: now[0], min_interval_s=0)
        self.assertEqual(sync.status()["status"], "never")
        self.assertEqual(len(sync.sync().domains), 2)
        self.assertEqual(sync.status()["status"], "ok")
        state["fail"] = True
        now[0] += timedelta(minutes=1)
        self.assertEqual(len(sync.sync().domains), 2)
        status = sync.status()
        self.assertEqual(status["status"], "stale")
        self.assertIn("unavailable", status["last_error"])
        self.assertFalse(status["nextdns"]["block_events_measured"])


if __name__ == "__main__":
    unittest.main()
