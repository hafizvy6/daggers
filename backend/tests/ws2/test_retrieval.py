"""Secure fetcher, snapshots, RSS and directory discovery. No live network is used:
DNS and HTTP are replaced by in-memory fakes. SYNTHETIC TEST FIXTUREs only."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from backend.tests.ws2 import helpers
from backend.app.channels.official.discover import candidates_to_entries, merge_candidates, parse_directory
from backend.app.channels.official.fetch import FetchBlocked, RawResponse, SecureFetcher, is_public_ip, parse_feed
from backend.app.channels.official.models import OfficialRecord
from backend.app.channels.official.registry import validate_entries
from backend.app.channels.official.snapshots import SnapshotStore

PUBLIC_IP = "93.184.216.34"


class FakeTransport:
    """routes: {(host, path): (status, headers, body)}"""

    def __init__(self, routes):
        self.routes = routes
        self.calls: list[tuple[str, str, str, dict]] = []

    def get(self, *, ip, host, path, headers, timeout):
        self.calls.append((ip, host, path, headers))
        status, hdrs, body = self.routes.get((host, path), (404, {}, b""))
        return RawResponse(status, {k.lower(): v for k, v in hdrs.items()}, iter([body[i:i + 7] for i in range(0, len(body), 7)] or [b""]))


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def make_fetcher(routes, resolver=None, **kw):
    transport = FakeTransport(routes)
    clock = Clock()
    fetcher = SecureFetcher(
        helpers.synthetic_registry(),
        transport=transport,
        resolver=resolver or (lambda host: [PUBLIC_IP]),
        clock=lambda: helpers.NOW,
        monotonic=clock,
        **kw,
    )
    return fetcher, transport, clock


ROBOTS = ("police.gov.example", "/robots.txt")
HTML = b"<html><head><title>Fraud alert</title><script>alert(1)</script></head><body><p>SYNTHETIC TEST FIXTURE. Police warns.</p></body></html>"


class TestFetcher(unittest.TestCase):
    def test_ip_classification(self):
        for ip in ("127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
                   "0.0.0.0", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "224.0.0.1", "198.18.0.1"):
            self.assertFalse(is_public_ip(ip), ip)
        self.assertTrue(is_public_ip(PUBLIC_IP))
        self.assertFalse(is_public_ip("not-an-ip"))

    def test_successful_fetch_strips_scripts_and_records_provenance(self):
        f, t, _ = make_fetcher({ROBOTS: (200, {"Content-Type": "text/plain"}, b"User-agent: *\nAllow: /\n"),
                                ("police.gov.example", "/news"): (200, {"Content-Type": "text/html; charset=utf-8"}, HTML)})
        result = f.fetch("syn-police", "https://police.gov.example/news")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(t.calls[-1][0], PUBLIC_IP)  # connection pinned to the validated IP
        self.assertEqual(t.calls[-1][3]["User-Agent"], "Daggers-Research/1.0")
        records = f.to_records(f.registry.by_id["syn-police"], "html", result)
        self.assertEqual(records[0].title, "Fraud alert")
        self.assertNotIn("alert(1)", records[0].content)
        self.assertIsNone(records[0].published_at)  # never invented
        self.assertEqual(records[0].retrieved_at, "2026-11-24T12:00:00Z")

    def test_only_registry_approved_urls(self):
        f, t, _ = make_fetcher({})
        for entry, url, code in (
            ("syn-police", "https://police.gov.example/other", "url_not_approved"),
            ("syn-pending", "https://pending.gov.example/news", "entry_not_approved"),
            ("syn-revoked", "https://revoked.gov.example/news", "entry_not_approved"),
            ("syn-expired", "https://expired.gov.example/news", "entry_not_approved"),
            ("nope", "https://police.gov.example/news", "unknown_entry"),
            ("syn-police", "https://scanned-site.example/evidence", "url_not_approved"),
        ):
            with self.subTest(url=url):
                result = f.fetch(entry, url)
                self.assertFalse(result.ok)
                self.assertEqual(result.error_code, code)
        self.assertEqual(t.calls, [])

    def test_private_dns_answer_blocked(self):
        f, t, _ = make_fetcher({}, resolver=lambda host: ["10.0.0.5"])
        result = f.fetch("syn-police", "https://police.gov.example/news")
        self.assertEqual(result.error_code, "private_address")
        self.assertEqual(t.calls, [])

    def test_mixed_dns_answer_blocked(self):
        f, _, _ = make_fetcher({}, resolver=lambda host: [PUBLIC_IP, "127.0.0.1"])
        self.assertEqual(f.fetch("syn-police", "https://police.gov.example/news").error_code, "private_address")

    def test_redirect_checks_every_hop(self):
        routes = {ROBOTS: (404, {}, b""),
                  ("police.gov.example", "/news"): (302, {"Location": "https://www.police.gov.example/news2"}, b""),
                  ("www.police.gov.example", "/news2"): (200, {"Content-Type": "text/html"}, HTML)}
        seen = []

        def resolver(host):
            seen.append(host)
            return [PUBLIC_IP]

        f, _, _ = make_fetcher(routes, resolver=resolver)
        result = f.fetch("syn-police", "https://police.gov.example/news")
        self.assertTrue(result.ok, result.error)
        self.assertIn("www.police.gov.example", seen)
        self.assertEqual(len(result.hops), 2)

    def test_redirect_off_registry_or_to_private_ip_blocked(self):
        off = {ROBOTS: (404, {}, b""),
               ("police.gov.example", "/news"): (302, {"Location": "https://evil.example/x"}, b"")}
        f, _, _ = make_fetcher(off)
        self.assertEqual(f.fetch("syn-police", "https://police.gov.example/news").error_code, "host_not_approved")
        http = {ROBOTS: (404, {}, b""),
                ("police.gov.example", "/news"): (301, {"Location": "http://police.gov.example/news"}, b"")}
        f, _, _ = make_fetcher(http)
        self.assertEqual(f.fetch("syn-police", "https://police.gov.example/news").error_code, "https_required")
        rebind = {ROBOTS: (404, {}, b""),
                  ("police.gov.example", "/news"): (302, {"Location": "https://www.police.gov.example/a"}, b"")}
        f, _, _ = make_fetcher(rebind, resolver=lambda h: ["127.0.0.1"] if h.startswith("www.") else [PUBLIC_IP])
        self.assertEqual(f.fetch("syn-police", "https://police.gov.example/news").error_code, "private_address")
        loop = {ROBOTS: (404, {}, b""),
                ("police.gov.example", "/news"): (302, {"Location": "/news"}, b"")}
        f, _, _ = make_fetcher(loop)
        self.assertEqual(f.fetch("syn-police", "https://police.gov.example/news").error_code, "too_many_redirects")

    def test_size_limit_and_content_type(self):
        big = {ROBOTS: (404, {}, b""), ("police.gov.example", "/news"): (200, {"Content-Type": "text/html"}, b"x" * 500)}
        f, _, _ = make_fetcher(big, max_bytes=100)
        self.assertEqual(f.fetch("syn-police", "https://police.gov.example/news").error_code, "too_large")
        declared = {ROBOTS: (404, {}, b""),
                    ("police.gov.example", "/news"): (200, {"Content-Type": "text/html", "Content-Length": "999999"}, b"x")}
        f, _, _ = make_fetcher(declared, max_bytes=100)
        self.assertEqual(f.fetch("syn-police", "https://police.gov.example/news").error_code, "too_large")
        binary = {ROBOTS: (404, {}, b""), ("police.gov.example", "/news"): (200, {"Content-Type": "application/x-msdownload"}, b"MZ")}
        f, _, _ = make_fetcher(binary)
        self.assertEqual(f.fetch("syn-police", "https://police.gov.example/news").error_code, "content_type_rejected")

    def test_robots_disallow_and_unavailable(self):
        deny = {ROBOTS: (200, {"Content-Type": "text/plain"}, b"User-agent: *\nDisallow: /news\n")}
        f, t, _ = make_fetcher(deny)
        self.assertEqual(f.fetch("syn-police", "https://police.gov.example/news").error_code, "robots_disallowed")
        self.assertEqual([c[2] for c in t.calls], ["/robots.txt"])
        down = {ROBOTS: (503, {}, b"")}
        f, _, _ = make_fetcher(down)
        self.assertEqual(f.fetch("syn-police", "https://police.gov.example/news").error_code, "robots_unavailable")

    def test_per_host_rate_limit(self):
        routes = {ROBOTS: (404, {}, b""), ("police.gov.example", "/news"): (200, {"Content-Type": "text/html"}, HTML)}
        f, _, clock = make_fetcher(routes, min_host_interval_s=10)
        self.assertTrue(f.fetch("syn-police", "https://police.gov.example/news").ok)
        self.assertEqual(f.fetch("syn-police", "https://police.gov.example/news").error_code, "rate_limited")
        clock.t += 11
        self.assertTrue(f.fetch("syn-police", "https://police.gov.example/news").ok)

    def test_xml_with_dtd_or_entity_rejected(self):
        evil = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss><channel><item><title>&x;</title></item></channel></rss>'
        with self.assertRaises(FetchBlocked):
            parse_feed(evil)
        routes = {ROBOTS: (404, {}, b""), ("police.gov.example", "/news"): (200, {"Content-Type": "application/rss+xml"}, evil)}
        f, _, _ = make_fetcher(routes)
        self.assertEqual(f.fetch("syn-police", "https://police.gov.example/news").error_code, "xml_dtd_rejected")

    def test_rss_items_off_registry_are_dropped(self):
        rss = (b'<?xml version="1.0"?><rss><channel>'
               b'<item><title>SYNTHETIC alert</title><link>https://police.gov.example/a/1</link>'
               b'<pubDate>Tue, 18 Nov 2026 06:00:00 GMT</pubDate><description>&lt;b&gt;fake&lt;/b&gt; messages</description></item>'
               b'<item><title>elsewhere</title><link>https://evil.example/x</link></item>'
               b'</channel></rss>')
        routes = {ROBOTS: (404, {}, b""), ("police.gov.example", "/news"): (200, {"Content-Type": "application/rss+xml"}, rss)}
        f, _, _ = make_fetcher(routes)
        result = f.fetch("syn-police", "https://police.gov.example/news")
        records = f.to_records(f.registry.by_id["syn-police"], "rss", result)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].published_at, "2026-11-18T06:00:00Z")
        self.assertNotIn("<b>", records[0].content)

    def test_failure_becomes_error_record_never_verified(self):
        f, _, _ = make_fetcher({ROBOTS: (404, {}, b"")}, resolver=lambda h: (_ for _ in ()).throw(OSError("nxdomain")))
        records = f.fetch_records("syn-police")
        self.assertTrue(records)
        self.assertTrue(all(r.fetch_status == "error" and r.content == "" for r in records))


class TestSnapshots(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.store = SnapshotStore(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_content_addressed_and_append_only(self):
        rec = helpers.synthetic_records()[0]
        row1 = self.store.record(rec)
        row2 = self.store.record(rec)
        self.assertEqual(row1["content_sha256"], rec.content_hash)
        self.assertEqual(len(self.store.rows()), 2)  # index appended, not rewritten
        objects = list((self.tmp / "objects").rglob("*.txt"))
        self.assertEqual(len(objects), 1)  # same content stored once
        self.assertEqual(self.store.get_content(row2["content_sha256"]), rec.content)

    def test_errors_are_recorded_without_content(self):
        failed = OfficialRecord("e1", "syn-police", "https://police.gov.example/news", "", "2026-11-24T00:00:00Z",
                                fetch_status="error", fetch_error="timeout")
        row = self.store.record(failed)
        self.assertIsNone(row["content_sha256"])
        latest = self.store.latest_records(["syn-police"])
        self.assertEqual(latest[0].fetch_status, "error")

    def test_tampered_object_detected(self):
        rec = helpers.synthetic_records()[0]
        row = self.store.record(rec)
        path = next((self.tmp / "objects").rglob("*.txt"))
        path.write_text("tampered", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.store.get_content(row["content_sha256"])

    def test_provider_feeds_scorer(self):
        for rec in helpers.synthetic_records():
            self.store.record(rec)
        scorer = helpers.scorer()
        scorer.record_provider = self.store.provider()
        r = scorer.assess_url("https://sira.gov.example/", text="Synthetic Residency Authority announces the golden visa renewal fee of AED 1,150.")
        self.assertEqual(r["gov_verification"]["status"], "VERIFIED")


class TestDiscovery(unittest.TestCase):
    def test_directory_double_creates_pending_candidates_only(self):
        html = (helpers.DATA_DIR / "uae_directory_sample.html").read_text(encoding="utf-8")
        candidates = parse_directory(html)
        hosts = [c.host for c in candidates]
        self.assertIn("www.harbour-authority.example", hosts)
        self.assertNotIn("u.ae", hosts)
        self.assertFalse(any("facebook" in h or h[0].isdigit() for h in hosts))
        self.assertFalse(any(c.url.startswith("http://") for c in candidates))
        entries = candidates_to_entries(candidates, source_url="https://u.ae/en/Help/The-Government", discovered_at=helpers.NOW)
        self.assertTrue(all(e["status"] == "pending" and e["reviewer"] is None for e in entries))
        juris = {e["domains"][0]: e["jurisdiction"] for e in entries}
        self.assertEqual(juris["harbour-authority.example"], "abu_dhabi")
        for e in entries:
            e["synthetic"] = True
        report = validate_entries(entries, allow_synthetic=True)
        self.assertTrue(report.ok, report.errors)

    def test_merge_never_overwrites_existing_entries(self):
        reg = helpers.synthetic_registry()
        existing = {"id": "cand-police-gov-example", "domains": ["police.gov.example"]}
        merged, added, skipped = merge_candidates(reg.raw, [existing])
        self.assertEqual(added, [])
        self.assertEqual(skipped, ["cand-police-gov-example"])
        self.assertEqual(merged["entries"], reg.raw["entries"])


if __name__ == "__main__":
    unittest.main()
