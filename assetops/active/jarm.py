"""Controlled JARM 1.0 probes; no CLI, proxy, or unguarded network fallback.

Protocol construction and fuzzy hash adapted from Salesforce JARM:
https://github.com/salesforce/jarm/blob/master/jarm.py
Created by John Althouse, Andrew Smart, RJ Nunaly, Mike Brady;
converted to Python by Caleb Yu.

Copyright (c) 2020, Salesforce.com, Inc.
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
* Neither the name of Salesforce.com nor the names of its contributors may
  be used to endorse or promote products derived from this software without
  specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import secrets
import struct
import time
from urllib.parse import urlsplit

from assetops.active.transport import BudgetExceeded, connect_address, consume_budget, resolve_addresses
from assetops.core.scope_guard import ScopeGuard

_CIPHERS = "0016 0033 0067 c09e c0a2 009e 0039 006b c09f c0a3 009f 0045 00be 0088 00c4 009a c008 c009 c023 c0ac c0ae c02b c00a c024 c0ad c0af c02c c072 c073 cca9 1302 1301 cc14 c007 c012 c013 c027 c02f c014 c028 c030 c060 c061 c076 c077 cca8 1305 1304 1303 cc13 c011 000a 002f 003c c09c c0a0 009c 0035 003d c09d c0a1 009d 0041 00ba 0084 00c0 0007 0004 0005".split()
_HASH_CIPHERS = sorted((c for c in _CIPHERS if not c.startswith("13"))) + sorted(c for c in _CIPHERS if c.startswith("13"))
# version, cipher list, cipher order, grease, rare ALPN, supported versions, extension order
_PROBES = (
    ("1.2", "ALL", "FORWARD", False, False, "1.2", "REVERSE"),
    ("1.2", "ALL", "REVERSE", False, False, "1.2", "FORWARD"),
    ("1.2", "ALL", "TOP_HALF", False, False, "NONE", "FORWARD"),
    ("1.2", "ALL", "BOTTOM_HALF", False, True, "NONE", "FORWARD"),
    ("1.2", "ALL", "MIDDLE_OUT", True, True, "NONE", "REVERSE"),
    ("1.1", "ALL", "FORWARD", False, False, "NONE", "FORWARD"),
    ("1.3", "ALL", "FORWARD", False, False, "1.3", "REVERSE"),
    ("1.3", "ALL", "REVERSE", False, False, "1.3", "FORWARD"),
    ("1.3", "NO1.3", "FORWARD", False, False, "1.3", "FORWARD"),
    ("1.3", "ALL", "MIDDLE_OUT", True, False, "1.3", "REVERSE"),
)
_MAX_RECORD_BYTES = 16384


def _u16(value):
    return struct.pack(">H", value)


def _extension(kind, data):
    return _u16(kind) + _u16(len(data)) + data


def _grease():
    return bytes([0x0a + 0x10 * secrets.randbelow(16)]) * 2


def _reorder(values, order):
    middle = len(values) // 2
    if order == "REVERSE":
        return values[::-1]
    if order == "BOTTOM_HALF":
        return values[middle + len(values) % 2:]
    if order == "TOP_HALF":
        return (values[middle:middle + 1] if len(values) % 2 else []) + _reorder(values[::-1], "BOTTOM_HALF")
    if order == "MIDDLE_OUT":
        result = values[middle:middle + 1] if len(values) % 2 else []
        for index in range(1, middle + 1):
            result.extend([values[middle + index] if len(values) % 2 else values[middle - 1 + index], values[middle - index]])
        return result
    return values[:]


def build_probe(host: str, index: int) -> bytes:
    version, cipher_list, order, grease, rare, support, ext_order = _PROBES[index]
    ciphers = [bytes.fromhex(c) for c in _CIPHERS if cipher_list == "ALL" or not c.startswith("13")]
    ciphers = _reorder(ciphers, order)
    if grease:
        ciphers.insert(0, _grease())
    cipher_bytes = b"".join(ciphers)
    hostname = host.encode("ascii")
    sni = b"\x00" + _u16(len(hostname)) + hostname
    extensions = _grease() + b"\x00\x00" if grease else b""
    extensions += _extension(0, _u16(len(sni)) + sni)
    extensions += bytes.fromhex("00170000 0001000101 ff01000100 000a000a0008001d001700180019 000b00020100 00230000")
    alpns = [b"http/0.9", b"http/1.0", b"http/1.1", b"spdy/1", b"spdy/2", b"spdy/3", b"h2", b"h2c", b"hq"]
    if rare:
        alpns = [a for a in alpns if a not in (b"h2", b"http/1.1")]
    alpn = b"".join(bytes([len(a)]) + a for a in _reorder(alpns, ext_order))
    extensions += _extension(16, _u16(len(alpn)) + alpn)
    extensions += bytes.fromhex("000d00140012040308040401050308050501080606010201")
    share = (_grease() + b"\x00\x01\x00" if grease else b"") + bytes.fromhex("001d0020") + os.urandom(32)
    extensions += _extension(51, _u16(len(share)) + share)
    extensions += bytes.fromhex("002d00020101")
    if support != "NONE":
        versions = [bytes.fromhex(v) for v in ("0301", "0302", "0303", "0304") if support == "1.3" or v != "0304"]
        versions = (_grease() if grease else b"") + b"".join(_reorder(versions, ext_order))
        extensions += _extension(43, bytes([len(versions)]) + versions)
    hello_version = bytes.fromhex("0302" if version == "1.1" else "0303")
    hello = hello_version + os.urandom(32) + b"\x20" + os.urandom(32)
    hello += _u16(len(cipher_bytes)) + cipher_bytes + b"\x01\x00" + _u16(len(extensions)) + extensions
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    record_version = bytes.fromhex("0301" if version == "1.3" else "0302" if version == "1.1" else "0303")
    return b"\x16" + record_version + _u16(len(handshake)) + handshake


def parse_server_hello(record: bytes) -> str:
    """Parse a complete bounded TLS record; reject malformed/truncated lengths."""
    if len(record) < 5 or int.from_bytes(record[3:5], "big") != len(record) - 5:
        raise ValueError("incomplete TLS record")
    if record[0] == 21:
        if len(record) < 7:
            raise ValueError("incomplete TLS alert")
        return "|||"
    if record[0] != 22 or len(record) < 44 or record[5] != 2:
        raise ValueError("expected TLS ServerHello")
    end = 9 + int.from_bytes(record[6:9], "big")
    if end > len(record) or end < 47:
        raise ValueError("invalid ServerHello length")
    version = record[9:11].hex()
    if version not in ("0300", "0301", "0302", "0303", "0304", "0305"):
        raise ValueError("invalid ServerHello version")
    offset = 44 + record[43]
    if offset + 3 > end:
        raise ValueError("invalid ServerHello session length")
    cipher = record[offset:offset + 2].hex()
    offset += 3
    types, alpn = [], ""
    if offset < end:
        if offset + 2 > end:
            raise ValueError("truncated extensions")
        ext_end = offset + 2 + int.from_bytes(record[offset:offset + 2], "big")
        offset += 2
        if ext_end != end:
            raise ValueError("invalid extension block length")
        while offset < end:
            if offset + 4 > end:
                raise ValueError("truncated extension header")
            kind = record[offset:offset + 2].hex()
            size = int.from_bytes(record[offset + 2:offset + 4], "big")
            offset += 4
            if offset + size > end:
                raise ValueError("truncated extension value")
            value = record[offset:offset + size]
            if kind == "0010":
                if size < 3 or int.from_bytes(value[:2], "big") != size - 2 or value[2] != size - 3:
                    raise ValueError("invalid ALPN")
                alpn = value[3:].decode("ascii")
                if "|" in alpn or "," in alpn:
                    raise ValueError("invalid ALPN delimiter")
            types.append(kind)
            offset += size
    return f"{cipher}|{version}|{alpn}|{'-'.join(types)}"


def jarm_hash(handshakes: list[str]) -> str:
    if len(handshakes) != 10:
        raise ValueError("JARM requires exactly ten probe responses")
    if all(value == "|||" for value in handshakes):
        return "0" * 62
    prefix, suffix = "", ""
    for response in handshakes:
        cipher, version, alpn, extensions = response.split("|")
        number = _HASH_CIPHERS.index(cipher) + 1 if cipher in _HASH_CIPHERS else len(_HASH_CIPHERS) + 1
        prefix += f"{number:02x}" if cipher else "00"
        prefix += "abcdef"[int(version[-1])] if version else "0"
        suffix += alpn + extensions
    return prefix + hashlib.sha256(suffix.encode()).hexdigest()[:32]


def _read_record(sock, deadline, clock):
    def exact(size):
        chunks = bytearray()
        while len(chunks) < size:
            remaining = deadline - clock()
            if remaining <= 0:
                raise TimeoutError("JARM handshake deadline exceeded")
            sock.settimeout(remaining)
            chunk = sock.recv(size - len(chunks))
            if not chunk:
                raise ValueError("truncated TLS response")
            chunks.extend(chunk)
        return bytes(chunks)
    header = exact(5)
    size = int.from_bytes(header[3:5], "big")
    if size > _MAX_RECORD_BYTES:
        raise ValueError("TLS record exceeds response limit")
    return header + exact(size)


def collect_jarm(target, *, scope_guard: ScopeGuard, consume, resolver=None, connector=None,
                 timeout=10, rate_limit=2, clock=time.monotonic, sleep=time.sleep) -> dict:
    """Ten raw ClientHellos, not a verified TLS session or proof of TLS identity.

    Connector shares transport.connect_address(ip, port, timeout); DNS is resolved
    once and every answer is scope-checked before opening any connection. A domain
    needs explicit domain authorization, and resolved IPs follow active scope rules.
    Literal IP input requires explicit IP/CIDR authorization. Budget failures propagate.
    """
    for value in (timeout, rate_limit):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError("timeout and rate_limit must be positive finite numbers")
    if not callable(consume):
        raise ValueError("JARM requires a budget consume callback")
    parsed = urlsplit(target)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError("JARM target must be an HTTPS URL without credentials, query or fragment")
    host = parsed.hostname.lower().rstrip(".")
    port = parsed.port if parsed.port is not None else 443
    if not 1 <= port <= 65535:
        raise ValueError("invalid TLS port")
    scope_guard.assert_in_scope(target, resolve_dns=False)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        allowed, reason = scope_guard.check_domain(host)
        if not allowed:
            raise PermissionError(reason)
        addresses = list(dict.fromkeys(str(ipaddress.ip_address(a)) for a in (resolver or resolve_addresses)(host)))
        if not addresses:
            raise OSError("DNS returned no addresses")
        for address in addresses:
            scope_guard.assert_active_address(host, address)
    else:
        addresses = [str(literal)]
        allowed, reason = scope_guard.check_ip(addresses[0])
        if not allowed:
            raise PermissionError(reason)
    connector = connector or connect_address
    responses = []
    last = None
    for index in range(10):
        if last is not None:
            sleep(max(0, 1 / rate_limit - (clock() - last)))
        consume_budget(consume)
        last = clock()
        deadline = last + timeout
        sock = None
        try:
            packet = build_probe(host, index)
            sock = connector(addresses[0], port, timeout)
            remaining = deadline - clock()
            if remaining <= 0:
                raise TimeoutError("JARM handshake deadline exceeded")
            sock.settimeout(remaining)
            sock.sendall(packet)
            responses.append(parse_server_hello(_read_record(sock, deadline, clock)))
        except (OSError, ValueError, UnicodeError):
            return {"status": "failed", "error": "JARM handshake failed or invalid TLS response", "input": target,
                    "handshakes_attempted": index + 1, "handshakes_completed": len(responses)}
        finally:
            if sock is not None:
                sock.close()
    fingerprint = jarm_hash(responses)
    evidence = {"status": "done" if fingerprint != "0" * 62 else "no_fingerprint", "input": target,
                "url": target, "host": host, "port": port, "connect_ip": addresses[0],
                "handshakes_attempted": 10, "handshakes_completed": 10,
                "fingerprint_version": "jarm-1.0", "certificate_verified": False}
    if fingerprint != "0" * 62:
        evidence["jarm_hash"] = fingerprint
    return evidence
