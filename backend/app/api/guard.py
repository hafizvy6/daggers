"""Guard API (live). The feed (C6 JSONL) and stats are served by findings.py from the same Guard list.

GET  /api/guard/config
GET  /api/guard/blocklist.txt?format=hosts|domains     hosts file (0.0.0.0 domain) — NextDNS / hosts
GET  /api/guard/domains.txt                            one domain per line — routers / AdGuard / NextDNS
GET  /api/guard/adguard-rules.txt                      AdGuard Home rules (||domain^ or $dnsrewrite)
GET  /api/guard/sync-status                            provider + sync diagnostics
POST /api/guard/sync                                   manual sync (cooldown)
GET  /api/guard/check?domain=…&live=0|1                O(1) Guard lookup (+ optional engine evaluation)
GET  /api/guard/verdict?domain=…&hit=0|1               data for the verdict page (no personal data)
GET  /verdict?domain=…                                 the bilingual verdict page (web app)
GET|POST /dns-query                                    RFC 8484 DNS-over-HTTPS (GUARD_DOH_ENABLED=1)
"""
from __future__ import annotations

import base64
import hashlib
import threading
import time
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from starlette.concurrency import run_in_threadpool

from .. import security
from ..guard.doh import MAX_MESSAGE, DoHResolver
from ..guard.manager import SyncCooldown, client_key

router = APIRouter()
_lock = threading.Lock()
_verdict_hits: dict[tuple[str, str], float] = {}
VERDICT_HIT_WINDOW_S = 600.0


def _rt(request: Request):
    return request.app.state.runtime


def _origin(request: Request) -> str:
    rt = _rt(request)
    return rt.settings.guard_public_origin or str(request.base_url).rstrip("/")


# ------------------------------------------------------------------ lists


def _render(domains: list[str], fmt: str, origin: str, generated_at: str) -> str:
    head = [
        f"# Daggers Guard — confirmed-malicious domains only ({fmt})",
        f"# generated_at: {generated_at}",
        f"# entries: {len(domains)}",
        f"# source: {origin}/api/guard/{'blocklist.txt' if fmt in ('hosts', 'domains') else 'adguard-rules.txt'}",
        "# policy: central verdict FAKE (engine MALICIOUS); official, registry, shared and widely used domains are never listed",
    ]
    if fmt == "domains":
        body = domains
    else:
        body = [f"0.0.0.0 {d}" for d in domains]
    return "\n".join(head + body) + "\n"


def _list_response(request: Request, fmt: str) -> Response:
    rt = _rt(request)
    rt.maybe_reload_registry()
    domains = rt.guard.index.domains()
    etag = 'W/"' + hashlib.sha256(("\n".join(domains) + fmt).encode()).hexdigest()[:24] + '"'
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    generated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    origin = _origin(request)
    if fmt == "adguard":
        verdict_ip = rt.settings.guard_verdict_ip
        head = [
            "! Daggers Guard — confirmed-malicious domains only (AdGuard Home rules)",
            f"! generated_at: {generated}", f"! entries: {len(domains)}",
            f"! source: {origin}/api/guard/adguard-rules.txt",
            "! policy: central verdict FAKE (engine MALICIOUS); official, registry, shared and widely used "
            "domains are never listed",
        ]
        body = ([f"||{d}^$dnsrewrite=NOERROR;A;{verdict_ip}" for d in domains] if verdict_ip
                else [f"||{d}^" for d in domains])
        text = "\n".join(head + body) + "\n"
    else:
        text = _render(domains, fmt, origin, generated)
    return PlainTextResponse(text, headers={"Cache-Control": "public, max-age=60", "ETag": etag,
                                            "X-Guard-Entries": str(len(domains))})


@router.get("/api/guard/config")
async def guard_config(request: Request):
    s = _rt(request).settings
    return {"hostname": s.guard_dns_hostname or None,
            "configured": bool(s.nextdns_api_key and s.nextdns_profile),
            "doh_enabled": bool(s.guard_doh_enabled)}


@router.get("/api/guard/blocklist.txt")
async def blocklist(request: Request, format: Literal["hosts", "domains"] = Query("hosts")):
    return _list_response(request, format)


@router.get("/api/guard/domains.txt")
async def domains_txt(request: Request):
    return _list_response(request, "domains")


@router.get("/api/guard/adguard-rules.txt")
async def adguard_rules(request: Request):
    return _list_response(request, "adguard")


# ------------------------------------------------------------------ sync


@router.get("/api/guard/sync-status")
async def sync_status(request: Request):
    return _rt(request).guard.sync_status()


@router.post("/api/guard/sync")
async def sync_now(request: Request):
    rt = _rt(request)
    try:
        return await run_in_threadpool(rt.guard.manual_sync)
    except SyncCooldown as exc:
        return JSONResponse(status_code=429, headers={"Retry-After": str(exc.retry_after_s)},
                            content={"detail": {"code": "cooldown", "retry_after_s": exc.retry_after_s,
                                                "message": f"sync was just run — try again in {exc.retry_after_s} s"}})


# ------------------------------------------------------------------ check / verdict


@router.get("/api/guard/check")
async def guard_check(request: Request, domain: str = Query(..., min_length=1, max_length=300),
                      live: int = Query(0, ge=0, le=1)):
    rt = _rt(request)
    rt.maybe_reload_registry()
    result = {"guard": rt.guard.check(domain)}
    if live and result["guard"].get("valid"):
        ip = security.client_ip(request, rt.settings.trust_proxy_headers)
        if not rt.scan_limiter.hit(ip):
            raise HTTPException(status_code=429, detail={"code": "rate_limited", "message": "too many checks"})
        url = f"https://{result['guard']['domain']}/"
        scan = await run_in_threadpool(rt.scan, "url", url, "en")
        offer = rt.guard_offer({**scan, "input_type": "url", "domain": result["guard"]["domain"]}, "checker")
        result["scan"] = {k: scan.get(k) for k in ("tag", "verdict", "score", "trust_reasons", "reason_codes",
                                                    "domain_auth", "blockable")}
        result["listed_now"] = bool(offer.get("new"))
        result["guard"] = rt.guard.check(domain)
    return result


@router.get("/api/guard/verdict")
async def guard_verdict(request: Request, domain: str = Query(..., min_length=1, max_length=300),
                        hit: int = Query(0, ge=0, le=1)):
    """What the verdict page shows. No personal data: the visitor's address is used only as an
    in-memory hashed key to stop one device inflating the counter."""
    rt = _rt(request)
    check = rt.guard.check(domain)
    row = rt.repo.guard_get(check.get("matched") or "") if check.get("blocked") else None
    counted = False
    # In DoH + verdict-IP mode this server's DNS answer already counted the block: don't count twice.
    dns_counted = bool(rt.settings.guard_doh_enabled and rt.settings.guard_verdict_ip)
    if hit and check.get("blocked") and not dns_counted:
        key = (client_key(security.client_ip(request, rt.settings.trust_proxy_headers)), check["matched"])
        now = time.monotonic()
        with _lock:
            last = _verdict_hits.get(key)
            if last is None or now - last > VERDICT_HIT_WINDOW_S:
                _verdict_hits[key] = now
                counted = True
            if len(_verdict_hits) > 20000:
                _verdict_hits.clear()
        if counted:
            rt.guard.record_block(check["matched"])
    out = {"domain": check.get("domain"), "valid": check.get("valid"), "blocked": check.get("blocked"),
           "matched": check.get("matched"), "counted": counted}
    if row:
        out.update({"tag": row["tag"], "verdict": row["verdict"], "score": row["score"], "reason": row["reason"],
                    "source": row["source"], "listed_at": row["listed_at"]})
        finding = rt.repo.get_finding(int(row["finding_id"])) if row.get("finding_id") else None
        if finding and str(finding.get("source") or "") not in rt.repo.RESTRICTED_SOURCES:
            out["finding_id"] = finding["id"]
            if finding.get("evidence_url"):
                out["evidence_url"] = f"/api/evidence/{finding['id']}.jpg"
    return out


@router.get("/verdict")
async def verdict_page(request: Request):
    index = _rt(request).settings.web_dir / "index.html"
    if not index.exists():
        raise HTTPException(status_code=404, detail="web app not installed")
    return FileResponse(str(index), media_type="text/html", headers={"Cache-Control": "no-store"})


# ------------------------------------------------------------------ DNS-over-HTTPS


def _resolver(request: Request) -> DoHResolver:
    state = request.app.state
    with _lock:
        resolver = getattr(state, "guard_doh", None)
        if resolver is None:
            rt = state.runtime
            s = rt.settings
            resolver = DoHResolver(lookup=rt.guard.index.match, on_block=rt.guard.record_block,
                                   upstream=s.guard_upstream_doh, mode=s.guard_doh_block_mode,
                                   verdict_ip=s.guard_verdict_ip or None)
            state.guard_doh = resolver
            state.guard_doh_limiter = security.SlidingWindow(s.guard_doh_rate_per_min, 60)
    return resolver


async def _answer(request: Request, message: bytes) -> Response:
    rt = _rt(request)
    if not rt.settings.guard_doh_enabled:
        raise HTTPException(status_code=404, detail="DNS-over-HTTPS is not enabled on this server")
    resolver = _resolver(request)
    key = client_key(security.client_ip(request, rt.settings.trust_proxy_headers))
    if not request.app.state.guard_doh_limiter.hit(key):
        return Response(status_code=429, headers={"Retry-After": "30"})
    answer = await run_in_threadpool(resolver.resolve, message)
    return Response(content=answer, media_type="application/dns-message",
                    headers={"Cache-Control": "max-age=30"})


@router.get("/dns-query")
async def doh_get(request: Request, dns: str = Query(..., min_length=16, max_length=6000)):
    try:
        message = base64.urlsafe_b64decode(dns + "=" * (-len(dns) % 4))
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="invalid dns parameter") from None
    if len(message) > MAX_MESSAGE:
        raise HTTPException(status_code=413, detail="DNS message too large")
    return await _answer(request, message)


@router.post("/dns-query")
async def doh_post(request: Request):
    if (request.headers.get("content-type") or "").split(";")[0].strip() != "application/dns-message":
        raise HTTPException(status_code=415, detail="Content-Type must be application/dns-message")
    body = await request.body()
    if len(body) > MAX_MESSAGE:
        raise HTTPException(status_code=413, detail="DNS message too large")
    return await _answer(request, body)
