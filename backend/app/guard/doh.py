"""RFC 8484 DNS-over-HTTPS resolver for the Guard (``/dns-query``, GUARD_DOH_ENABLED=1).

Works on hosts that only expose HTTPS (Hugging Face Spaces, Render): phones / browsers use
``https://<your-host>/dns-query`` as their secure-DNS server.

* Strict parsing: one question, standard QUERY opcode, QR=0, label/name length limits, no
  compression pointers in the question; anything else → FORMERR.
* Blocked name (exact host or a listed registrable site above it) → answered locally:
  ``GUARD_DOH_BLOCK_MODE=nxdomain`` (default) or ``zero`` (A 0.0.0.0 / AAAA ::), or — when
  ``GUARD_VERDICT_IP`` is set — an A record pointing at your verdict server (VPS mode).
  The block is counted (daily counter); no client address, no query log is stored.
* Not blocked → forwarded over HTTPS to ``GUARD_UPSTREAM_DOH`` (bounded timeout); answers are cached
  briefly (30 s) with the transaction id rewritten. Upstream failure → SERVFAIL (never a fake answer).
"""
from __future__ import annotations

import ipaddress
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable

import httpx

MAX_MESSAGE = 4096
TYPE_A, TYPE_AAAA, CLASS_IN = 1, 28, 1
RCODE_OK, RCODE_FORMERR, RCODE_SERVFAIL, RCODE_NXDOMAIN, RCODE_REFUSED = 0, 1, 2, 3, 5
BLOCK_TTL = 60
CACHE_TTL = 30.0


class DNSFormatError(ValueError):
    pass


@dataclass(frozen=True)
class Query:
    raw: bytes
    txid: int
    flags: int
    qname: str
    qtype: int
    qclass: int
    question: bytes          # wire bytes of the question section

    @property
    def rd(self) -> bool:
        return bool(self.flags & 0x0100)


def parse_query(data: bytes) -> Query:
    if not isinstance(data, (bytes, bytearray)) or len(data) < 12 or len(data) > MAX_MESSAGE:
        raise DNSFormatError("bad message size")
    txid, flags, qd, an, ns, ar = struct.unpack("!6H", data[:12])
    if flags & 0x8000:
        raise DNSFormatError("not a query")
    if (flags >> 11) & 0xF != 0:
        raise DNSFormatError("only standard QUERY is supported")
    if qd != 1 or an or ns:
        raise DNSFormatError("exactly one question is required")
    pos, labels, total = 12, [], 0
    while True:
        if pos >= len(data):
            raise DNSFormatError("truncated name")
        length = data[pos]
        if length & 0xC0:
            raise DNSFormatError("compression in question")
        pos += 1
        if length == 0:
            break
        if length > 63 or pos + length > len(data):
            raise DNSFormatError("bad label")
        label = bytes(data[pos:pos + length])
        if not all(32 < b < 127 for b in label):
            raise DNSFormatError("bad label characters")
        labels.append(label.decode("ascii").lower())
        total += length + 1
        if total > 255:
            raise DNSFormatError("name too long")
        pos += length
    if pos + 4 > len(data):
        raise DNSFormatError("truncated question")
    qtype, qclass = struct.unpack("!HH", data[pos:pos + 4])
    question = bytes(data[12:pos + 4])
    return Query(bytes(data), txid, flags, ".".join(labels), qtype, qclass, question)


def _header(txid: int, query_flags: int, rcode: int, ancount: int) -> bytes:
    flags = 0x8000 | (query_flags & 0x0100) | 0x0080 | (rcode & 0xF)   # QR, copy RD, RA
    return struct.pack("!6H", txid, flags, 1, ancount, 0, 0)


def error_response(data: bytes, rcode: int) -> bytes:
    txid = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else 0
    flags = struct.unpack("!H", data[2:4])[0] if len(data) >= 4 else 0
    return struct.pack("!6H", txid, 0x8000 | (flags & 0x0100) | 0x0080 | rcode, 0, 0, 0, 0)


def query_error(q: Query, rcode: int) -> bytes:
    """Error answer that echoes the question (RFC 1035 §4.1.1) — used once the query parsed."""
    return _header(q.txid, q.flags, rcode, 0) + q.question


def block_response(q: Query, mode: str = "nxdomain", verdict_ip: str | None = None) -> bytes:
    answers = b""
    count = 0
    rcode = RCODE_OK
    rdata = None
    if verdict_ip:
        ip = ipaddress.ip_address(verdict_ip)
        if q.qtype == TYPE_A and ip.version == 4:
            rdata = ip.packed
        elif q.qtype == TYPE_AAAA and ip.version == 6:
            rdata = ip.packed
    elif mode == "zero":
        if q.qtype == TYPE_A:
            rdata = bytes(4)
        elif q.qtype == TYPE_AAAA:
            rdata = bytes(16)
    else:
        rcode = RCODE_NXDOMAIN
    if rdata is not None:
        answers = struct.pack("!HHHIH", 0xC00C, q.qtype, CLASS_IN, BLOCK_TTL, len(rdata)) + rdata
        count = 1
    return _header(q.txid, q.flags, rcode, count) + q.question + answers


class DoHResolver:
    def __init__(self, *, lookup: Callable[[str], dict | None], on_block: Callable[[str], None],
                 upstream: str, mode: str = "nxdomain", verdict_ip: str | None = None,
                 timeout_s: float = 3.0, http: Callable | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.lookup = lookup
        self.on_block = on_block
        self.upstream = upstream
        self.mode = mode if mode in ("nxdomain", "zero") else "nxdomain"
        self.verdict_ip = verdict_ip or None
        self.timeout_s = timeout_s
        self.http = http or self._post
        self.clock = clock
        self._cache: dict[tuple[str, int, int], tuple[float, bytes]] = {}
        self._lock = threading.Lock()
        self.forwarded = 0
        self.blocked = 0
        self.upstream_errors = 0

    def _post(self, url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, content=body, headers={"Content-Type": "application/dns-message",
                                                           "Accept": "application/dns-message"})
            return resp.status_code, resp.content

    def resolve(self, data: bytes) -> bytes:
        try:
            q = parse_query(data)
        except DNSFormatError:
            return error_response(data, RCODE_FORMERR)
        if q.qclass != CLASS_IN:
            return query_error(q, RCODE_REFUSED)
        hit = self.lookup(q.qname)
        if hit is not None:
            self.blocked += 1
            try:
                self.on_block(hit.get("domain") or q.qname)
            except Exception:  # noqa: BLE001 — counting must never break resolution
                pass
            return block_response(q, self.mode, self.verdict_ip)
        key = (q.qname, q.qtype, q.flags & 0x0010)        # CD bit separates DNSSEC-checking-disabled answers
        now = self.clock()
        with self._lock:
            cached = self._cache.get(key)
        if cached and now - cached[0] < CACHE_TTL:
            return struct.pack("!H", q.txid) + cached[1][2:]
        try:
            status, body = self.http(self.upstream, q.raw, self.timeout_s)
        except Exception:  # noqa: BLE001
            self.upstream_errors += 1
            return query_error(q, RCODE_SERVFAIL)
        if status != 200 or len(body) < 12:
            self.upstream_errors += 1
            return query_error(q, RCODE_SERVFAIL)
        self.forwarded += 1
        rcode = body[3] & 0xF
        if rcode in (RCODE_OK, RCODE_NXDOMAIN):
            with self._lock:
                if len(self._cache) > 5000:
                    self._cache.clear()
                self._cache[key] = (now, body)
        return struct.pack("!H", q.txid) + body[2:]


def build_query(name: str, qtype: int = TYPE_A, txid: int = 0x1234) -> bytes:
    """Helper (tests / smoke checks): a standard recursive query."""
    q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.rstrip(".").split(".")) + b"\x00"
    return struct.pack("!6H", txid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, CLASS_IN)
