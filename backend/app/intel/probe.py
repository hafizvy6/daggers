"""Secure, read-only page inspection for the Checker.

Reuses the controls of the official-source fetcher (``channels.official.fetch``):

* DNS resolved by us; EVERY address of EVERY hop must be public (private, loopback, link-local,
  CGNAT, multicast, reserved … are blocked); the TCP connection is pinned to the checked IP
  (TLS verified for the real host name) → no DNS-rebinding between check and connect.
* http/https only, default ports only, no credentials in URLs, at most 5 redirects, each hop
  re-checked; connect timeout, total deadline, size cap, HTML content types only.
* One GET per hop with a generic User-Agent; no cookies, no Referer, no request body.
* Markup is PARSED, never executed: no JavaScript, no form submission, no sub-resources fetched.
* The raw HTML is not stored; only derived facts (hosts, form shapes, title, short text) are kept.

``meta refresh`` targets are reported (and followed once, through the same checks); JavaScript
redirects are not executed, only noted.
"""
from __future__ import annotations

import http.client
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urljoin, urlsplit

from ..core.rules import any_regex, rules as _rules
from ..channels.official.fetch import RawResponse, StdlibTransport, default_resolver, html_to_text, is_public_ip

USER_AGENT = "Mozilla/5.0 (compatible; Daggers-Checker/1.0; +read-only safety check)"
HTML_TYPES = ("text/html", "application/xhtml+xml")
MAX_REDIRECTS = 5


class ProbeBlocked(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, ip: str, timeout: float) -> None:
        super().__init__(host, 80, timeout=timeout)
        self._pinned_ip = ip

    def connect(self) -> None:  # pragma: no cover - live network only
        self.sock = socket.create_connection((self._pinned_ip, 80), self.timeout)


class PinnedTransport(StdlibTransport):
    """https via the official fetcher's pinned connection; plain http pinned the same way."""

    def get_url(self, *, scheme: str, ip: str, host: str, path: str, headers: dict[str, str],
                timeout: float) -> RawResponse:  # pragma: no cover - live network only
        if scheme == "https":
            return self.get(ip=ip, host=host, path=path, headers=headers, timeout=timeout)
        conn = _PinnedHTTPConnection(host, ip, timeout)
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()

        def chunks():
            while True:
                block = response.read(16384)
                if not block:
                    break
                yield block

        return RawResponse(status=response.status, headers={k.lower(): v for k, v in response.getheaders()},
                           chunks=chunks(), close=conn.close)


# ---------------------------------------------------------------- markup facts


@dataclass
class FormFacts:
    action: str
    action_host: str | None
    method: str
    password: bool = False
    otp: bool = False
    card: bool = False
    iban: bool = False
    identity: bool = False          # Emirates ID / passport / national id fields
    inputs: int = 0

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in ("action_host", "method", "password", "otp", "card", "iban",
                                              "identity", "inputs")}


_OTP = any_regex(_rules()["form_fields"]["otp"])   # data: core/rules.yaml
_CARD = any_regex(_rules()["form_fields"]["card"])   # data: core/rules.yaml
_IBAN = any_regex(_rules()["form_fields"]["iban"])   # data: core/rules.yaml
_IDENT = any_regex(_rules()["form_fields"]["identity"])   # data: core/rules.yaml
_OBFUSCATION = re.compile(r"eval\s*\(\s*(atob|unescape|function\s*\(p,a,c,k,e)|String\.fromCharCode\((\d+,\s*){20,}"
                          r"|document\.write\s*\(\s*unescape|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){40,}", re.I)
_JS_REDIRECT = re.compile(r"(window\.)?location(\.href)?\s*=\s*['\"]https?://|location\.replace\(\s*['\"]https?://", re.I)


class _MarkupParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.forms: list[FormFacts] = []
        self._form: FormFacts | None = None
        self.meta_refresh: str | None = None
        self.iframes = 0
        self.script_hosts: set[str] = set()
        self.inline_scripts: list[str] = []
        self._in_script = False
        self.loose_inputs: list[dict] = []

    def _abs_host(self, url: str) -> str | None:
        try:
            return (urlsplit(urljoin(self.base, url)).hostname or "").lower() or None
        except ValueError:
            return None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            action = a.get("action", "")
            self._form = FormFacts(action=action[:300], action_host=self._abs_host(action or self.base),
                                   method=(a.get("method") or "get").lower())
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea"):
            descr = " ".join(a.get(k, "") for k in ("name", "id", "placeholder", "autocomplete", "aria-label"))
            kind = a.get("type", "text").lower()
            target = self._form
            if target is None:
                self.loose_inputs.append({"type": kind, "descr": descr})
                return
            target.inputs += 1
            if kind == "password":
                target.password = True
            if _OTP.search(descr) or a.get("autocomplete") == "one-time-code":
                target.otp = True
            if _CARD.search(descr) or a.get("autocomplete", "").startswith("cc-"):
                target.card = True
            if _IBAN.search(descr):
                target.iban = True
            if _IDENT.search(descr):
                target.identity = True
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            match = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.I)
            if match:
                self.meta_refresh = urljoin(self.base, match.group(1).strip())
        elif tag == "iframe":
            self.iframes += 1
        elif tag == "script":
            src = a.get("src")
            if src:
                host = self._abs_host(src)
                if host:
                    self.script_hosts.add(host)
            else:
                self._in_script = True

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script and sum(len(s) for s in self.inline_scripts) < 400_000:
            self.inline_scripts.append(data)


@dataclass
class PageFacts:
    title: str
    text_excerpt: str
    forms: list[FormFacts]
    meta_refresh: str | None
    js_redirect: bool
    obfuscated_script: bool
    iframes: int
    script_hosts: list[str]

    def as_dict(self) -> dict:
        return {"title": self.title[:200], "forms": [f.as_dict() for f in self.forms][:10],
                "meta_refresh_host": (urlsplit(self.meta_refresh).hostname if self.meta_refresh else None),
                "js_redirect": self.js_redirect, "obfuscated_script": self.obfuscated_script,
                "iframes": self.iframes, "script_hosts": self.script_hosts[:15]}


def parse_markup(html: str, base_url: str) -> PageFacts:
    parser = _MarkupParser(base_url)
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 — malformed markup: keep what was parsed
        pass
    if parser.loose_inputs and not parser.forms:
        # inputs outside a <form> (JS-submitted): treat as one form posting to an unknown destination
        form = FormFacts(action="", action_host=None, method="js")
        for item in parser.loose_inputs:
            form.inputs += 1
            form.password |= item["type"] == "password"
            form.otp |= bool(_OTP.search(item["descr"]))
            form.card |= bool(_CARD.search(item["descr"]))
            form.iban |= bool(_IBAN.search(item["descr"]))
            form.identity |= bool(_IDENT.search(item["descr"]))
        parser.forms.append(form)
    scripts = "\n".join(parser.inline_scripts)
    title, text = html_to_text(html)
    return PageFacts(title=title, text_excerpt=text[:4000], forms=parser.forms, meta_refresh=parser.meta_refresh,
                     js_redirect=bool(_JS_REDIRECT.search(scripts)), obfuscated_script=bool(_OBFUSCATION.search(scripts)),
                     iframes=parser.iframes, script_hosts=sorted(parser.script_hosts))


# ---------------------------------------------------------------- probe


@dataclass
class Hop:
    url_host: str
    status: int | None
    scheme: str

    def as_dict(self) -> dict:
        return {"host": self.url_host, "status": self.status, "scheme": self.scheme}


@dataclass
class ProbeResult:
    status: str                                   # ok | blocked | unavailable | not_html | disabled
    original_host: str
    final_url: str | None = None
    final_host: str | None = None
    hops: list[Hop] = field(default_factory=list)
    facts: PageFacts | None = None
    retrieved_at: str | None = None
    error_code: str | None = None
    reason: str = ""

    @property
    def redirected_off_host(self) -> bool:
        return bool(self.final_host and self.final_host != self.original_host)

    def as_dict(self) -> dict:
        return {"status": self.status, "original_host": self.original_host, "final_host": self.final_host,
                "redirected": self.redirected_off_host, "hops": [h.as_dict() for h in self.hops],
                "retrieved_at": self.retrieved_at, "error_code": self.error_code, "reason": self.reason,
                "page": self.facts.as_dict() if self.facts else None}


def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class PageProbe:
    def __init__(
        self,
        *,
        enabled: bool = True,
        transport=None,
        resolver: Callable[[str], list[str]] = default_resolver,
        connect_timeout_s: float = 4.0,
        total_timeout_s: float = 8.0,
        max_bytes: int = 1_500_000,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.enabled = enabled
        self.transport = transport or PinnedTransport()
        self.resolver = resolver
        self.connect_timeout_s = connect_timeout_s
        self.total_timeout_s = total_timeout_s
        self.max_bytes = max_bytes
        self.monotonic = monotonic

    def _check(self, url: str) -> tuple[str, str, str]:
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as exc:
            raise ProbeBlocked("bad_url", "malformed URL") from exc
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise ProbeBlocked("scheme_not_allowed", f"{scheme}: links are not retrieved")
        if parts.username or parts.password or "@" in parts.netloc:
            raise ProbeBlocked("credentials_in_url", "URLs with user-info are not retrieved")
        if port not in (None, 80 if scheme == "http" else 443):
            raise ProbeBlocked("port_not_allowed", "only default ports are retrieved")
        host = (parts.hostname or "").rstrip(".").lower()
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ProbeBlocked("bad_host", "invalid host name") from exc
        if not host or "%" in host:
            raise ProbeBlocked("bad_host", "invalid host name")
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        return scheme, host, path

    def _public_ip(self, host: str) -> str:
        if is_public_ip(host):
            return host
        try:
            addresses = self.resolver(host)
        except OSError as exc:
            raise ProbeBlocked("dns_error", "the domain does not resolve") from exc
        if not addresses:
            raise ProbeBlocked("dns_error", "the domain does not resolve")
        if any(not is_public_ip(a) for a in addresses):
            raise ProbeBlocked("private_address", "the host resolves to a private / internal network address")
        return addresses[0]

    def probe(self, url: str) -> ProbeResult:
        try:
            _, original_host, _ = self._check(url)
        except ProbeBlocked as exc:
            return ProbeResult("blocked", "", error_code=exc.code, reason=str(exc), retrieved_at=_iso_now())
        result = ProbeResult("unavailable", original_host)
        if not self.enabled:
            result.status, result.reason = "disabled", "page retrieval is switched off"
            return result
        deadline = self.monotonic() + self.total_timeout_s
        current = url
        refreshed = False
        try:
            for _ in range(MAX_REDIRECTS + 1):
                scheme, host, path = self._check(current)
                ip = self._public_ip(host)
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    raise ProbeBlocked("timeout", "time limit reached")
                headers = {"Host": host, "User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml",
                           "Accept-Encoding": "identity", "Connection": "close"}
                try:
                    response = self.transport.get_url(scheme=scheme, ip=ip, host=host, path=path, headers=headers,
                                                      timeout=min(self.connect_timeout_s, remaining))
                except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                    raise ProbeBlocked("network_error", f"the site could not be reached ({type(exc).__name__})") from exc
                hop = Hop(host, response.status, scheme)
                result.hops.append(hop)
                try:
                    if response.status in (301, 302, 303, 307, 308):
                        location = response.headers.get("location")
                        if not location:
                            raise ProbeBlocked("bad_redirect", "redirect without a target")
                        current = urljoin(current, location)
                        continue
                    ctype = (response.headers.get("content-type") or "").split(";")[0].strip().lower()
                    body = bytearray()
                    if response.status == 200 and (not ctype or ctype in HTML_TYPES):
                        for chunk in response.chunks:
                            body.extend(chunk)
                            if len(body) > self.max_bytes:
                                break                 # keep the first part; enough for markup facts
                            if self.monotonic() > deadline:
                                raise ProbeBlocked("timeout", "time limit reached")
                finally:
                    response.close()
                result.final_url, result.final_host = current, host
                result.retrieved_at = _iso_now()
                if response.status != 200:
                    result.status, result.error_code = "unavailable", f"http_{response.status}"
                    result.reason = f"the site answered HTTP {response.status}"
                    return result
                if ctype and ctype not in HTML_TYPES:
                    result.status, result.reason = "not_html", f"content type {ctype} (not a web page)"
                    return result
                match = re.search(r"charset=([\w-]+)", response.headers.get("content-type") or "", re.I)
                try:
                    html = bytes(body).decode(match.group(1) if match else "utf-8", errors="replace")
                except LookupError:
                    html = bytes(body).decode("utf-8", errors="replace")
                facts = parse_markup(html, current)
                if facts.meta_refresh and not refreshed and urlsplit(facts.meta_refresh).hostname:
                    refreshed = True
                    current = facts.meta_refresh
                    continue
                result.status, result.facts = "ok", facts
                result.reason = "page retrieved and inspected (markup only; no scripts run, no forms submitted)"
                return result
            raise ProbeBlocked("too_many_redirects", f"more than {MAX_REDIRECTS} redirects")
        except ProbeBlocked as exc:
            result.status = "blocked" if exc.code in ("private_address", "credentials_in_url", "port_not_allowed",
                                                      "scheme_not_allowed", "bad_host") else "unavailable"
            result.error_code, result.reason = exc.code, str(exc)
            result.retrieved_at = result.retrieved_at or _iso_now()
            if not result.final_host and current != url:
                # where the redirect chain was heading when it was stopped
                result.final_url = current
                result.final_host = (urlsplit(current).hostname or "").lower() or None
            return result
