"""Live Guard: eligibility, the Checker/Radar → Guard loop, the O(1) index, every Guard endpoint,
DNS-over-HTTPS wire format, the NextDNS provider and the AdGuard Home sidecar — all offline, with
test doubles for the external services (no real network, no real API keys)."""
from __future__ import annotations

import base64
import importlib.util
import json
import struct
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.guard import eligibility
from backend.app.guard.doh import DoHResolver, build_query, parse_query
from backend.app.guard.index import GuardIndex
from backend.app.guard.nextdns import NextDNSProvider
from backend.app.main import create_app
from backend.tests.test_integration import make_settings
from backend.tests.ws2 import helpers

ROOT = Path(__file__).resolve().parents[2]
NOW = "2026-11-25T08:00:00Z"


def _app(tmp_path, monkeypatch, **overrides):
    monkeypatch.setenv("AI_PROVIDER", "template")
    app = create_app(make_settings(tmp_path, **overrides))
    app.state.runtime.trust_policy = helpers.scorer()
    return app


@pytest.fixture
def guard_app(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch, guard_sync_debounce_s=60.0)
    with TestClient(app) as client:
        yield client, app


def radar(rt, domain, verdict="MALICIOUS", source="crt.sh"):
    rt.publish("finding", {"id": 900 + len(domain), "domain": domain, "verdict": verdict, "score": 0.93,
                           "reasons": ["lookalike of a bank with a login form"], "source": source,
                           "first_seen": NOW, "created_at": NOW})


# ------------------------------------------------------------------ eligibility (strict)


class _Rep:
    def __init__(self, shared=(), trusted=()):
        self.shared, self.trusted = set(shared), set(trusted)

    def shared_platform(self, host):
        return host in self.shared

    def lookup(self, host):
        return type("L", (), {"trusted": host in self.trusted})()


def _ev(item, source="radar", **kw):
    base = dict(source=source, registry=helpers.synthetic_registry(), official_domains=["adcb.com"],
                reputation=_Rep(shared={"github.io"}, trusted={"youtube.com"}))
    base.update(kw)
    return eligibility.evaluate(item, **base)


FAKE = {"tag": "FAKE", "verdict": "MALICIOUS", "domain": "adcb-secure-login.xyz", "input_type": "url"}


def test_only_confirmed_fakes_are_eligible():
    assert _ev(FAKE).eligible and _ev(FAKE).scope == "site"
    assert not _ev({**FAKE, "tag": "WARNING", "verdict": "SUSPICIOUS"}).eligible
    assert not _ev({**FAKE, "tag": "WARNING", "verdict": "UNKNOWN"}).eligible
    assert not _ev({**FAKE, "tag": "SAFE"}).eligible
    assert not _ev({**FAKE, "verdict": "SUSPICIOUS"}).eligible          # FAKE needs MALICIOUS
    mis = {**FAKE, "tag": "MISLEADING", "verdict": "MISLEADING", "gov_verification": {"status": "CONTRADICTED"}}
    assert not _ev(mis).eligible and _ev(mis, include_misleading=True).eligible
    assert not _ev({**mis, "gov_verification": {"status": "UNVERIFIED"}}, include_misleading=True).eligible


def test_protected_and_invalid_hosts_are_never_eligible():
    for domain in ("192.0.2.10", "*.evil.xyz", "not a host", "", "xyz"):
        assert not _ev({**FAKE, "domain": domain}).eligible, domain
    for domain in ("police.gov.example", "www.police.gov.example", "adcb.com", "login.adcb.com",
                   "youtube.com", "github.io", "portal.gov.ae", "moe.gov.ae"):
        d = _ev({**FAKE, "domain": domain})
        assert not d.eligible and d.protected, domain
    assert not _ev({**FAKE, "blockable": False}).eligible
    assert not _ev({**FAKE, "domain_auth": {"legitimate_site": True}}).eligible
    # a Checker analysis of message TEXT never blocks, even if it is FAKE
    assert not _ev({**FAKE, "input_type": "text"}, source="checker").eligible
    assert _ev(FAKE, source="checker").eligible
    # www.site lists the site itself
    assert _ev({**FAKE, "domain": "www.adcb-secure-login.xyz"}).domain == "adcb-secure-login.xyz"
    # a sub-site of a shared platform is listed exactly, never the platform
    d = _ev({**FAKE, "domain": "adcb-login.github.io"})
    assert d.eligible and d.scope == "exact" and d.domain == "adcb-login.github.io"


def test_index_matches_exact_and_parent_site_only():
    idx = GuardIndex()
    idx.replace([{"domain": "adcb-secure-login.xyz", "source": "radar"},
                 {"domain": "adcb-login.github.io", "source": "radar"}])
    assert idx.match("adcb-secure-login.xyz")["domain"] == "adcb-secure-login.xyz"
    assert idx.match("pay.www.adcb-secure-login.xyz")["domain"] == "adcb-secure-login.xyz"
    assert idx.match("adcb-login.github.io")
    assert idx.match("other.github.io") is None and idx.match("github.io") is None
    assert idx.match("xyz") is None and idx.match("example.com") is None


# ------------------------------------------------------------------ live loop + endpoints


def test_radar_finding_lists_live_with_sse_and_lists(guard_app):
    client, app = guard_app
    rt = app.state.runtime
    queue = rt.events.subscribe()
    radar(rt, "adcb-secure-login.xyz")
    events = []
    while not queue.empty():
        events.append(queue.get_nowait())
    rt.events.unsubscribe(queue)
    guard = [e for e in events if e["event"] == "guard"]
    assert guard and guard[0]["data"]["type"] == "listed" and guard[0]["data"]["source"] == "radar"

    hosts = client.get("/api/guard/blocklist.txt")
    assert hosts.status_code == 200 and "0.0.0.0 adcb-secure-login.xyz" in hosts.text
    assert "max-age" in hosts.headers["cache-control"] and hosts.headers["etag"].startswith('W/"')
    assert client.get("/api/guard/blocklist.txt", headers={"If-None-Match": hosts.headers["etag"]}).status_code == 304
    assert "adcb-secure-login.xyz" in client.get("/api/guard/blocklist.txt?format=domains").text.splitlines()
    assert "adcb-secure-login.xyz" in client.get("/api/guard/domains.txt").text.splitlines()
    assert "||adcb-secure-login.xyz^" in client.get("/api/guard/adguard-rules.txt").text.splitlines()
    feed = [json.loads(line) for line in client.get("/api/guard/feed").text.splitlines() if line]
    assert feed[0]["domain"] == "adcb-secure-login.xyz" and set(feed[0]) == {"domain", "verdict", "reason", "flagged_at"}

    stats = client.get("/api/guard/stats").json()
    for key in ("status", "enabled", "mode", "dot_hostname", "doh_url", "blocklist_url", "blocklist_count",
                "blocked_today", "blocked_total", "newest_fakes", "last_sync_at", "sync_health",
                "nextdns_configured", "honest_limits_key", "blocked_domains", "feed_size", "blocked_hits"):
        assert key in stats, key
    assert stats["blocklist_count"] == 1 and stats["newest_fakes"][0]["source"] == "radar"
    assert stats["dot_hostname"] in ("", None)                    # no fake hostname when not configured
    assert "daggers-guard.nextdns.io" not in json.dumps(stats)
    assert stats["honest_limits_key"] == "guard.limits_list_only" and stats["nextdns_configured"] is False

    check = client.get("/api/guard/check?domain=https://login.adcb-secure-login.xyz/pay").json()["guard"]
    assert check["blocked"] and check["matched"] == "adcb-secure-login.xyz"


def test_warning_unknown_registry_and_ip_findings_are_never_listed(guard_app):
    client, app = guard_app
    rt = app.state.runtime
    radar(rt, "maybe-odd.xyz", verdict="SUSPICIOUS")
    radar(rt, "nothing-known.xyz", verdict="UNKNOWN")
    radar(rt, "police.gov.example")
    radar(rt, "203.0.113.7")
    assert rt.guard.index.domains() == []
    assert not [l for l in client.get("/api/guard/domains.txt").text.splitlines() if not l.startswith("#")]


def test_checker_link_check_feeds_guard_without_publishing_the_submission(guard_app):
    client, app = guard_app
    r = client.post("/api/check", json={"input": "https://adcb-secure-login.xyz/login",
                                         "request_id": "guard-live-1"}).json()
    assert "guard" in r and r["guard"]["valid"]
    assert r["tag"] == "FAKE"                      # bank lookalike + login path, deterministic offline
    if r["tag"] == "FAKE":
        assert r["guard"]["blocked"] and r["guard"]["source"] == "checker"
        stats = client.get("/api/guard/stats").json()
        row = next(x for x in stats["newest_fakes"] if x["domain"] == "adcb-secure-login.xyz")
        assert row["source"] == "checker" and row["finding_id"] is None       # portal-only id
        assert "/login" not in client.get("/api/guard/blocklist.txt").text
    else:
        assert not r["guard"]["blocked"]


def test_checker_message_text_never_lists(guard_app):
    client, app = guard_app
    text = "URGENT your ADCB account is locked, verify now at https://adcb-secure-login.xyz/login"
    client.post("/api/check", json={"input": text, "request_id": "guard-live-2"})
    assert "adcb-secure-login.xyz" not in app.state.runtime.guard.index.domains()


def test_scan_reports_guard_but_never_lists(guard_app):
    client, app = guard_app
    rt = app.state.runtime
    radar(rt, "adcb-secure-login.xyz")
    r = client.post("/api/scan?guard=1", json={"kind": "url", "input": "https://adcb-secure-login.xyz/x"}).json()
    assert r["guard"]["blocked"] is True
    assert "guard" not in client.post("/api/scan", json={"kind": "url", "input": "https://adcb-secure-login.xyz/x"}).json()
    client.post("/api/scan?guard=1", json={"kind": "url", "input": "https://other-fake-login.xyz/x"})
    assert "other-fake-login.xyz" not in rt.guard.index.domains()


def test_protected_domain_is_delisted_when_reanalysed(guard_app):
    client, app = guard_app
    rt = app.state.runtime
    radar(rt, "adcb-secure-login.xyz")
    assert rt.guard.check("adcb-secure-login.xyz")["blocked"]
    rt.guard.offer({"tag": "SAFE", "verdict": "UNKNOWN", "domain": "adcb-secure-login.xyz",
                    "domain_auth": {"legitimate_site": True}}, "radar")
    assert not rt.guard.check("adcb-secure-login.xyz")["blocked"]
    assert "adcb-secure-login.xyz" not in client.get("/api/guard/domains.txt").text


def test_list_survives_restart(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch, guard_sync_debounce_s=60.0)
    with TestClient(app):
        radar(app.state.runtime, "adcb-secure-login.xyz")
    app2 = _app(tmp_path, monkeypatch, guard_sync_debounce_s=60.0)
    with TestClient(app2) as client:
        assert "adcb-secure-login.xyz" in client.get("/api/guard/domains.txt").text


def test_verdict_endpoint_and_page_count_hits_once_and_store_no_pii(guard_app):
    client, app = guard_app
    rt = app.state.runtime
    radar(rt, "adcb-secure-login.xyz")
    v = client.get("/api/guard/verdict?domain=adcb-secure-login.xyz&hit=1").json()
    assert v["blocked"] and v["counted"] and v["source"] == "radar" and v["reason"]
    again = client.get("/api/guard/verdict?domain=adcb-secure-login.xyz&hit=1").json()
    assert again["counted"] is False                                  # one device, one count per window
    clean = client.get("/api/guard/verdict?domain=example.org&hit=1").json()
    assert clean["blocked"] is False and clean["counted"] is False
    stats = client.get("/api/guard/stats").json()
    assert stats["blocked_today"] == 1 and stats["blocked_total"] == 1
    page = client.get("/verdict?domain=adcb-secure-login.xyz")
    assert page.status_code == 200 and "text/html" in page.headers["content-type"]
    dump = json.dumps(rt.repo.guard_list_rows())
    assert "testclient" not in dump and "127.0.0.1" not in dump


def test_manual_sync_has_cooldown_and_reports_status(guard_app):
    client, app = guard_app
    first = client.post("/api/guard/sync")
    assert first.status_code == 200 and first.json()["ok"] is True
    second = client.post("/api/guard/sync")
    assert second.status_code == 429 and int(second.headers["retry-after"]) >= 1
    status = client.get("/api/guard/sync-status").json()
    assert status["source"] == "guard_feed" and status["nextdns"]["block_events_measured"] is False


def test_live_check_runs_engine_and_respects_rate_limit(guard_app):
    client, app = guard_app
    r = client.get("/api/guard/check?domain=adcb-secure-login.xyz&live=1").json()
    assert r["scan"]["tag"] in ("FAKE", "WARNING", "MISLEADING", "SAFE")
    assert r["guard"]["blocked"] == (r["scan"]["tag"] == "FAKE")
    assert client.get("/api/guard/check?domain=192.0.2.1&live=1").json()["guard"]["valid"] is False


def test_adguard_rules_use_verdict_ip_when_set(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch, guard_verdict_ip="198.51.100.20", guard_sync_debounce_s=60.0)
    with TestClient(app) as client:
        radar(app.state.runtime, "adcb-secure-login.xyz")
        rules = client.get("/api/guard/adguard-rules.txt").text
        assert "||adcb-secure-login.xyz^$dnsrewrite=NOERROR;A;198.51.100.20" in rules


def test_stats_show_real_nextdns_hostname_only_when_configured(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch, nextdns_profile="abc123", nextdns_api_key="k-test",
               guard_dns_hostname="abc123.dns.nextdns.io", guard_sync_debounce_s=60.0)
    app.state.runtime.guard.provider.http = lambda *a, **k: _Resp(200, {"data": []})
    with TestClient(app) as client:
        stats = client.get("/api/guard/stats").json()
        assert stats["dot_hostname"] == "abc123.dns.nextdns.io" and stats["nextdns_configured"] is True
        assert stats["honest_limits_key"] == "guard.limits_nextdns"


# ------------------------------------------------------------------ DNS-over-HTTPS


def test_doh_disabled_by_default(guard_app):
    client, _ = guard_app
    q = base64.urlsafe_b64encode(build_query("example.org")).rstrip(b"=").decode()
    assert client.get(f"/dns-query?dns={q}").status_code == 404


@pytest.fixture
def doh_app(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch, guard_doh_enabled=True, guard_sync_debounce_s=60.0)
    with TestClient(app) as client:
        from backend.app.api.guard import _resolver

        resolver = _resolver(type("R", (), {"app": app})())
        calls = []

        def upstream(url, body, timeout):
            calls.append(body)
            q = parse_query(body)
            answer = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([93, 184, 215, 14]))
            return 200, struct.pack("!6H", q.txid, 0x8180, 1, 1, 0, 0) + q.question + answer

        resolver.http = upstream
        yield client, app, calls


def _rcode(msg: bytes) -> int:
    return msg[3] & 0xF


def test_doh_blocks_listed_names_and_counts_without_pii(doh_app):
    client, app, calls = doh_app
    radar(app.state.runtime, "adcb-secure-login.xyz")
    q = build_query("www.adcb-secure-login.xyz", txid=0xBEEF)
    r = client.post("/dns-query", content=q, headers={"Content-Type": "application/dns-message"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/dns-message"
    assert r.content[:2] == b"\xbe\xef" and _rcode(r.content) == 3            # NXDOMAIN
    assert calls == []                                                          # never forwarded
    get = client.get("/dns-query?dns=" + base64.urlsafe_b64encode(q).rstrip(b"=").decode())
    assert _rcode(get.content) == 3
    stats = client.get("/api/guard/stats").json()
    assert stats["blocked_today"] == 2 and stats["doh_url"].endswith("/dns-query")
    assert stats["honest_limits_key"] == "guard.limits_doh"


def test_doh_forwards_clean_names_and_rejects_bad_input(doh_app):
    client, app, calls = doh_app
    r = client.post("/dns-query", content=build_query("example.org", txid=7),
                    headers={"Content-Type": "application/dns-message"})
    assert _rcode(r.content) == 0 and r.content[:2] == b"\x00\x07" and len(calls) == 1
    # cached: second identical query is answered locally with the new transaction id
    r2 = client.post("/dns-query", content=build_query("example.org", txid=9),
                     headers={"Content-Type": "application/dns-message"})
    assert r2.content[:2] == b"\x00\x09" and len(calls) == 1
    bad = client.post("/dns-query", content=b"\x00\x01garbage", headers={"Content-Type": "application/dns-message"})
    assert _rcode(bad.content) == 1                                             # FORMERR
    assert client.post("/dns-query", content=build_query("example.org"),
                       headers={"Content-Type": "text/plain"}).status_code == 415
    assert client.post("/dns-query", content=b"\x00" * 5000,
                       headers={"Content-Type": "application/dns-message"}).status_code == 413


def test_doh_zero_and_verdict_ip_modes():
    q = build_query("evil-login.xyz")
    hit = {"domain": "evil-login.xyz"}
    blocked = []
    zero = DoHResolver(lookup=lambda n: hit, on_block=blocked.append, upstream="x", mode="zero")
    out = zero.resolve(q)
    assert _rcode(out) == 0 and out.endswith(bytes([0, 0, 0, 0])) and blocked == ["evil-login.xyz"]
    vip = DoHResolver(lookup=lambda n: hit, on_block=blocked.append, upstream="x", verdict_ip="198.51.100.20")
    assert vip.resolve(q).endswith(bytes([198, 51, 100, 20]))
    down = DoHResolver(lookup=lambda n: None, on_block=blocked.append, upstream="x",
                       http=lambda *a: (_ for _ in ()).throw(OSError("offline")))
    assert _rcode(down.resolve(q)) == 2                                          # SERVFAIL, honest


# ------------------------------------------------------------------ NextDNS provider (mocked API)


class _Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}

    def json(self):
        return self._body


def test_nextdns_push_adds_removes_and_never_touches_hand_added_entries():
    seen = []

    def http(method, url, *, headers, json, timeout):
        seen.append((method.upper(), url.rsplit("/profiles/abc123", 1)[1], json))
        assert headers["X-Api-Key"] == "k-test"
        if json and json["id"] == "mine-by-hand.xyz":
            return _Resp(200, {"errors": [{"code": "duplicate"}]})
        return _Resp(200, {"data": {}})

    p = NextDNSProvider("abc123", "k-test", http=http)
    res = p.push({"new-fake.xyz", "mine-by-hand.xyz"}, {"old-fake.xyz"})
    assert res.added == ["new-fake.xyz"] and res.removed == ["old-fake.xyz"]
    assert res.already_present == ["mine-by-hand.xyz"] and not res.errors
    assert ("DELETE", "/denylist/old-fake.xyz", None) in seen
    assert ("POST", "/denylist", {"id": "new-fake.xyz", "active": True}) in seen
    seen.clear()
    p.push({"new-fake.xyz", "mine-by-hand.xyz"}, {"new-fake.xyz"})
    assert seen == []                                                            # nothing to do, no retries


def test_nextdns_rate_limit_errors_and_analytics():
    p = NextDNSProvider("abc123", "k", http=lambda *a, **k: _Resp(429, {}, {"retry-after": "12"}))
    res = p.push({"a-fake.xyz"}, set())
    assert res.rate_limited and res.retry_after_s == 12.0 and not res.added
    p = NextDNSProvider("abc123", "k", http=lambda *a, **k: _Resp(200, {"errors": [{"code": "invalid"}]}))
    assert p.push({"a-fake.xyz"}, set()).errors
    p = NextDNSProvider("abc123", "k", http=lambda *a, **k: _Resp(
        200, {"data": [{"id": "blocklists", "queries": 9}, {"id": "denylist", "queries": 4}]}))
    assert p.blocked_last_24h() == (4, None)
    p = NextDNSProvider("abc123", "k", http=lambda *a, **k: _Resp(403, {}))
    assert p.blocked_last_24h() == (None, "HTTP 403")
    assert NextDNSProvider("", "").blocked_last_24h() == (None, "not configured")


def test_manager_sync_pushes_to_nextdns(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch, nextdns_profile="abc123", nextdns_api_key="k-test",
               guard_sync_debounce_s=60.0)
    posted = []

    def http(method, url, *, headers, json, timeout):
        if json:
            posted.append(json["id"])
        return _Resp(200, {"data": []})

    app.state.runtime.guard.provider.http = http
    with TestClient(app) as client:
        radar(app.state.runtime, "adcb-secure-login.xyz")
        status = client.post("/api/guard/sync").json()
        assert status["ok"] is True and posted == ["adcb-secure-login.xyz"]
        assert client.get("/api/guard/stats").json()["sync_health"] == "ok"


# ------------------------------------------------------------------ AdGuard Home sidecar (mocked)


def _load_sidecar():
    spec = importlib.util.spec_from_file_location("guard_sync", ROOT / "guard" / "sync.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeAdGuard:
    def __init__(self, domains, user_rules=(), rewrites=(), filters=()):
        self.domains, self.user_rules = list(domains), list(user_rules)
        self.rewrites, self.filters, self.calls = list(rewrites), list(filters), []

    def __call__(self, req, timeout):
        url, method = req.full_url, req.get_method()
        body = json.loads(req.data) if req.data else None
        self.calls.append((method, url.split("://", 1)[1].split("/", 1)[1], body))
        if url.endswith("/api/guard/domains.txt"):
            out = "# header\n" + "\n".join(self.domains) + "\n"
        elif url.endswith("/control/filtering/status"):
            out = json.dumps({"user_rules": self.user_rules, "filters": self.filters})
        elif url.endswith("/control/rewrite/list"):
            out = json.dumps(self.rewrites)
        else:
            out = ""
        return _UrlResp(out.encode())


class _UrlResp:
    status = 200

    def __init__(self, raw):
        self.raw = raw

    def read(self):
        return self.raw

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_adguard_sync_rules_mode_keeps_user_rules():
    mod = _load_sidecar()
    fake = _FakeAdGuard(["bad-one.xyz"], user_rules=["@@||mybank.example^", mod.BEGIN, "||stale.xyz^", mod.END])
    s = mod.AdGuardSync("http://daggers", "http://agh", "admin", "pw", mode="hosts", opener=fake)
    plan = s.plan()
    assert plan["changed"] and plan["rules"] == ["@@||mybank.example^", mod.BEGIN, "||bad-one.xyz^", mod.END]
    s.apply(plan)
    assert ("POST", "control/filtering/set_rules", {"rules": plan["rules"]}) in fake.calls


def test_adguard_sync_rewrites_and_filter_url_modes():
    mod = _load_sidecar()
    fake = _FakeAdGuard(["bad-one.xyz"], rewrites=[{"domain": "gone.xyz", "answer": "198.51.100.20"},
                                                   {"domain": "nas.home", "answer": "192.168.1.5"}])
    s = mod.AdGuardSync("http://daggers", "http://agh", mode="rewrites", verdict_ip="198.51.100.20", opener=fake)
    plan = s.plan()
    assert plan["add"] == [("bad-one.xyz", "198.51.100.20")] and plan["remove"] == [("gone.xyz", "198.51.100.20")]
    s.apply(plan)
    assert not any(c[2] and c[2].get("domain") == "nas.home" for c in fake.calls)   # not ours: untouched
    with pytest.raises(mod.SyncError):
        mod.AdGuardSync("http://d", "http://a", mode="rewrites", opener=fake)
    fake = _FakeAdGuard(["bad-one.xyz"])
    s = mod.AdGuardSync("http://daggers", "http://agh", mode="filter-url", opener=fake)
    plan = s.plan()
    assert plan["add"] is True
    s.apply(plan)
    assert ("POST", "control/filtering/add_url", {"name": "Daggers Guard", "url": "http://daggers/api/guard/adguard-rules.txt",
                                                   "whitelist": False}) in fake.calls


def test_private_paths_never_reach_the_access_log():
    import logging

    from backend.app.main import _PrivateAccessLogFilter

    f = _PrivateAccessLogFilter()

    def rec(path):
        return logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d',
                                 ("203.0.113.9:5000", "GET", path, "1.1", 200), None)

    assert not f.filter(rec("/dns-query?dns=AAABAAAB"))
    assert not f.filter(rec("/api/guard/verdict?domain=x.xyz&hit=1"))
    assert not f.filter(rec("/verdict?domain=x.xyz"))
    assert f.filter(rec("/api/guard/stats"))


def test_doh_servfail_echoes_question():
    down = DoHResolver(lookup=lambda n: None, on_block=lambda d: None, upstream="x",
                       http=lambda *a: (_ for _ in ()).throw(OSError("offline")))
    q = build_query("example.org", txid=5)
    out = down.resolve(q)
    assert _rcode(out) == 2 and out[:2] == b"\x00\x05" and out.endswith(q[12:])
