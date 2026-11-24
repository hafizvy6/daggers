"""Secure retrieval layer for registry-approved official sources.

Separate from the pure verification engine. Guarantees:

* Only URLs listed in an approved+fresh registry entry (``source_urls``, exact or
  path-prefix, ``terms_reviewed: true``) are fetched. URLs supplied by scanned
  websites are never fetched by this module.
* HTTPS only, no credentials, default port only.
* DNS is resolved by us and EVERY address is checked on EVERY redirect hop;
  private, loopback, link-local, multicast, reserved, CGNAT and other
  non-global ranges are blocked. The TCP connection is pinned to the checked IP
  (with SNI + certificate verification for the hostname), defeating DNS
  rebinding between check and connect.
* Redirect targets must stay inside the same registry entry's domains.
* Connect timeout, total deadline, and response-size cap.
* Per-host minimum interval (rate limit) and robots.txt (RFC 9309) respected.
* XML containing DOCTYPE or ENTITY declarations is rejected before parsing.
* No JavaScript is executed; HTML is reduced to text with the stdlib parser.
* Every failure returns ``ok=False`` with an error code — never a record that
  looks like a successful retrieval.
"""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from typing import Callable, Iterator, Protocol
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser
from xml.etree import ElementTree

from .models import OfficialRecord, RegistryEntry, iso, sha256_text, utc_now
from .registry import Registry, host_matches_entry, to_ascii_host

USER_AGENT = "Daggers-Research/1.0"
ALLOWED_CONTENT_TYPES = (
    "text/html", "application/xhtml+xml", "application/rss+xml", "application/atom+xml",
    "application/xml", "text/xml", "application/json", "text/plain",
)
_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
        "255.255.255.255/32", "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64",
        "2001::/32", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
    )
)
_SECURITY_CODES = frozenset({
    "private_address", "host_not_approved", "https_required", "credentials_in_url",
    "port_not_allowed", "bad_host", "bad_url", "xml_dtd_rejected",
})
_DTD = re.compile(rb"<!\s*(doctype|entity)", re.I)


class FetchBlocked(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return False
    if any(ip in net for net in _BLOCKED_NETWORKS):
        return False
    return ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local)


def default_resolver(host: str, port: int = 443) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))


# --------------------------------------------------------------- transport


@dataclass
class RawResponse:
    status: int
    headers: dict[str, str]
    chunks: Iterator[bytes]
    close: Callable[[], None] = lambda: None


class Transport(Protocol):
    def get(self, *, ip: str, host: str, path: str, headers: dict[str, str], timeout: float) -> RawResponse: ...


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to a pre-validated IP but verifies TLS for the real hostname."""

    def __init__(self, host: str, ip: str, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(host, 443, timeout=timeout, context=context)
        self._pinned_ip = ip
        self._ctx = context

    def connect(self) -> None:  # pragma: no cover - exercised only against live hosts
        sock = socket.create_connection((self._pinned_ip, 443), self.timeout)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self.host)


class StdlibTransport:
    def __init__(self) -> None:
        self.context = ssl.create_default_context()
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def get(self, *, ip: str, host: str, path: str, headers: dict[str, str], timeout: float) -> RawResponse:  # pragma: no cover
        conn = _PinnedHTTPSConnection(host, ip, timeout, self.context)
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()

        def chunks() -> Iterator[bytes]:
            while True:
                block = response.read(16384)
                if not block:
                    break
                yield block

        return RawResponse(
            status=response.status,
            headers={k.lower(): v for k, v in response.getheaders()},
            chunks=chunks(),
            close=conn.close,
        )


# --------------------------------------------------------------- results


@dataclass
class FetchResult:
    ok: bool
    url: str
    final_url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    text: str = ""
    retrieved_at: str | None = None
    error_code: str | None = None
    error: str | None = None
    hops: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in (
            "ok", "url", "final_url", "status_code", "content_type", "retrieved_at", "error_code", "error", "hops"
        )} | {"content_sha256": sha256_text(self.text) if self.ok else None}


class _TextExtractor(HTMLParser):
    SKIP = {"script", "style", "noscript", "template", "svg", "iframe", "object"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
        if tag == "title":
            self._in_title = True
        if tag in {"p", "br", "div", "li", "h1", "h2", "h3", "h4", "tr", "section", "article"}:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._skip:
            return
        if self._in_title:
            self.title += data
        self.parts.append(data)


def html_to_text(html: str) -> tuple[str, str]:
    parser = _TextExtractor()
    parser.feed(html)
    parser.close()
    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(parser.parts))
    text = re.sub(r"\n\s*\n+", "\n", text).strip()
    return parser.title.strip(), text


def reject_dtd(data: bytes) -> None:
    if _DTD.search(data):
        raise FetchBlocked("xml_dtd_rejected", "XML with DOCTYPE/ENTITY declarations is rejected")


def parse_feed(xml_bytes: bytes) -> list[dict]:
    """RSS 2.0 / Atom items → [{title, link, published_at, summary}]. DTDs rejected."""
    reject_dtd(xml_bytes)
    root = ElementTree.fromstring(xml_bytes)
    items: list[dict] = []
    atom = "{http://www.w3.org/2005/Atom}"
    for item in root.iter("item"):
        pub = item.findtext("pubDate")
        published = None
        if pub:
            try:
                published = iso(parsedate_to_datetime(pub))
            except (TypeError, ValueError):
                published = None
        summary = html_to_text(item.findtext("description") or "")[1]
        items.append({
            "title": (item.findtext("title") or "").strip(),
            "link": (item.findtext("link") or "").strip(),
            "published_at": published,
            "summary": summary,
        })
    for entry in root.iter(f"{atom}entry"):
        link_el = entry.find(f"{atom}link")
        link = (link_el.get("href") if link_el is not None else "") or ""
        updated = entry.findtext(f"{atom}updated") or entry.findtext(f"{atom}published")
        items.append({
            "title": (entry.findtext(f"{atom}title") or "").strip(),
            "link": link.strip(),
            "published_at": iso(datetime.fromisoformat(updated.replace("Z", "+00:00"))) if updated else None,
            "summary": html_to_text(entry.findtext(f"{atom}summary") or "")[1],
        })
    return items


# --------------------------------------------------------------- fetcher


class SecureFetcher:
    def __init__(
        self,
        registry: Registry,
        *,
        transport: Transport | None = None,
        resolver: Callable[[str], list[str]] = default_resolver,
        clock: Callable[[], datetime] = utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        connect_timeout_s: float = 5.0,
        total_timeout_s: float = 15.0,
        max_bytes: int = 2_000_000,
        max_redirects: int = 3,
        min_host_interval_s: float = 10.0,
        respect_robots: bool = True,
        user_agent: str = USER_AGENT,
    ) -> None:
        self.registry = registry
        self.transport = transport or StdlibTransport()
        self.resolver = resolver
        self.clock = clock
        self.monotonic = monotonic
        self.connect_timeout_s = connect_timeout_s
        self.total_timeout_s = total_timeout_s
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.min_host_interval_s = min_host_interval_s
        self.respect_robots = respect_robots
        self.user_agent = user_agent
        self._last_request: dict[str, float] = {}
        self._robots: dict[str, RobotFileParser | None] = {}
        self._lock = threading.Lock()

    # ---- policy checks

    def approved_source(self, entry_id: str, url: str) -> RegistryEntry:
        entry = self.registry.by_id.get(entry_id)
        if entry is None:
            raise FetchBlocked("unknown_entry", f"unknown registry entry '{entry_id}'")
        if not entry.is_trusted(self.clock()):
            raise FetchBlocked("entry_not_approved", "registry entry is not approved and fresh")
        for source in entry.source_urls:
            if url == source.url or (source.url.endswith("/") and url.startswith(source.url)):
                if not source.terms_reviewed:
                    raise FetchBlocked("terms_not_reviewed", "source terms/robots have not been reviewed")
                return entry
        raise FetchBlocked("url_not_approved", "URL is not an approved source URL for this entry")

    def _check_url(self, url: str, entry: RegistryEntry) -> tuple[str, str]:
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as exc:
            raise FetchBlocked("bad_url", "malformed URL") from exc
        if parts.scheme != "https":
            raise FetchBlocked("https_required", "only HTTPS is allowed")
        if parts.username or parts.password or "@" in parts.netloc:
            raise FetchBlocked("credentials_in_url", "credentials in URL are not allowed")
        if port not in (None, 443):
            raise FetchBlocked("port_not_allowed", "only the default HTTPS port is allowed")
        host = to_ascii_host(parts.hostname or "")
        if not host:
            raise FetchBlocked("bad_host", "invalid host")
        if not host_matches_entry(host, entry):
            raise FetchBlocked("host_not_approved", f"host {host} is outside the entry's approved domains")
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        return host, path

    def _resolve_public(self, host: str) -> str:
        try:
            addresses = self.resolver(host)
        except OSError as exc:
            raise FetchBlocked("dns_error", f"DNS resolution failed: {type(exc).__name__}") from exc
        if not addresses:
            raise FetchBlocked("dns_error", "no addresses")
        bad = [a for a in addresses if not is_public_ip(a)]
        if bad:
            raise FetchBlocked("private_address", "host resolves to a non-public address")
        return addresses[0]

    def _rate_limit(self, host: str) -> None:
        with self._lock:
            now = self.monotonic()
            last = self._last_request.get(host)
            if last is not None and now - last < self.min_host_interval_s:
                raise FetchBlocked("rate_limited", f"per-host interval {self.min_host_interval_s}s not elapsed")
            self._last_request[host] = now

    # ---- one GET with all checks; follows redirects within the entry

    def _get(self, url: str, entry: RegistryEntry, *, check_robots: bool) -> FetchResult:
        deadline = self.monotonic() + self.total_timeout_s
        result = FetchResult(ok=False, url=url)
        current = url
        for _hop in range(self.max_redirects + 1):
            host, path = self._check_url(current, entry)
            result.hops.append(current)
            if check_robots and self.respect_robots and not self._robots_allowed(host, path, entry):
                raise FetchBlocked("robots_disallowed", "robots.txt disallows this path")
            ip = self._resolve_public(host)
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                raise FetchBlocked("timeout", "total deadline exceeded")
            try:
                response = self.transport.get(
                    ip=ip,
                    host=host,
                    path=path,
                    headers={
                        "Host": host,
                        "User-Agent": self.user_agent,
                        "Accept": "text/html,application/rss+xml,application/xml;q=0.9,*/*;q=0.1",
                        "Accept-Encoding": "identity",
                        "Connection": "close",
                    },
                    timeout=min(self.connect_timeout_s, remaining),
                )
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                raise FetchBlocked("network_error", f"{type(exc).__name__}") from exc
            try:
                if response.status in (301, 302, 303, 307, 308):
                    location = response.headers.get("location")
                    if not location:
                        raise FetchBlocked("bad_redirect", "redirect without Location")
                    current = urljoin(current, location)
                    continue
                result.status_code = response.status
                if response.status != 200:
                    raise FetchBlocked(f"http_{response.status}", f"HTTP {response.status}")
                declared = response.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > self.max_bytes:
                    raise FetchBlocked("too_large", "declared size exceeds limit")
                content_type = (response.headers.get("content-type") or "").split(";")[0].strip().lower()
                if content_type and not any(content_type == allowed for allowed in ALLOWED_CONTENT_TYPES):
                    raise FetchBlocked("content_type_rejected", f"content type {content_type} not allowed")
                body = bytearray()
                for chunk in response.chunks:
                    body.extend(chunk)
                    if len(body) > self.max_bytes:
                        raise FetchBlocked("too_large", "response exceeds size limit")
                    if self.monotonic() > deadline:
                        raise FetchBlocked("timeout", "total deadline exceeded")
            finally:
                response.close()
            charset = "utf-8"
            match = re.search(r"charset=([\w-]+)", response.headers.get("content-type") or "", re.I)
            if match:
                charset = match.group(1)
            raw = bytes(body)
            if "xml" in content_type or raw.lstrip()[:5].lower() == b"<?xml":
                reject_dtd(raw)
            try:
                text = raw.decode(charset, errors="replace")
            except LookupError:
                text = raw.decode("utf-8", errors="replace")
            result.ok = True
            result.final_url = current
            result.content_type = content_type
            result.text = text
            result.retrieved_at = iso(self.clock())
            return result
        raise FetchBlocked("too_many_redirects", "redirect limit exceeded")

    def _robots_allowed(self, host: str, path: str, entry: RegistryEntry) -> bool:
        if host not in self._robots:
            robots_url = f"https://{host}/robots.txt"
            try:
                res = self._get(robots_url, entry, check_robots=False)
                parser = RobotFileParser()
                parser.parse(res.text.splitlines())
                self._robots[host] = parser
            except FetchBlocked as exc:
                if exc.code.startswith("http_4"):
                    self._robots[host] = None  # RFC 9309: 4xx → no restrictions
                elif exc.code in _SECURITY_CODES:
                    raise  # a security block is reported as itself, never masked
                else:
                    raise FetchBlocked("robots_unavailable", "robots.txt unreachable; treated as disallow") from exc
        parser = self._robots[host]
        return True if parser is None else parser.can_fetch(self.user_agent, path)

    # ---- public

    def fetch(self, entry_id: str, url: str) -> FetchResult:
        try:
            entry = self.approved_source(entry_id, url)
            host, _ = self._check_url(url, entry)
            self._rate_limit(host)  # once per logical fetch; robots + redirect hops ride along
            return self._get(url, entry, check_robots=True)
        except FetchBlocked as exc:
            return FetchResult(ok=False, url=url, error_code=exc.code, error=str(exc), retrieved_at=iso(self.clock()))

    def fetch_records(self, entry_id: str) -> list[OfficialRecord]:
        """Fetch every approved source URL of one entry into OfficialRecords (errors included)."""
        entry = self.registry.by_id.get(entry_id)
        if entry is None:
            return []
        records: list[OfficialRecord] = []
        for source in entry.source_urls:
            result = self.fetch(entry_id, source.url)
            records.extend(self.to_records(entry, source.kind, result))
        return records

    def to_records(self, entry: RegistryEntry, kind: str, result: FetchResult) -> list[OfficialRecord]:
        rid = "rec_" + sha256_text(f"{entry.id}|{result.url}|{result.retrieved_at}")[:16]
        if not result.ok:
            return [OfficialRecord(rid, entry.id, result.url, "", result.retrieved_at or "", None, "",
                                   "error", result.error_code)]
        if kind == "rss" or "xml" in (result.content_type or ""):
            try:
                items = parse_feed(result.text.encode("utf-8"))
            except (FetchBlocked, ElementTree.ParseError) as exc:
                code = exc.code if isinstance(exc, FetchBlocked) else "xml_parse_error"
                return [OfficialRecord(rid, entry.id, result.url, "", result.retrieved_at or "", None, "", "error", code)]
            out = []
            for item in items:
                link = item["link"]
                host = to_ascii_host(urlsplit(link).hostname or "") if link else None
                if not host or not host_matches_entry(host, entry) or not link.startswith("https://"):
                    continue  # feed items pointing off-registry are not official records
                out.append(OfficialRecord(
                    "rec_" + sha256_text(f"{entry.id}|{link}|{item['title']}")[:16], entry.id, link,
                    f"{item['title']}. {item['summary']}".strip(), result.retrieved_at or "",
                    item["published_at"], item["title"],
                ))
            return out
        title, text = html_to_text(result.text) if "html" in (result.content_type or "html") else ("", result.text)
        return [OfficialRecord(rid, entry.id, result.final_url or result.url, text, result.retrieved_at or "",
                               None, title)]
