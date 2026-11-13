"""Fixed-address, scope-checked active HTTP transport (standard library only)."""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import math
import re
import socket
import ssl
import threading
import time
from html import unescape

from assetops.core.scope_guard import ScopeGuard


class BudgetExceeded(RuntimeError):
    """The active request budget is exhausted; no further network work is allowed."""


class ActiveStepStopped(RuntimeError):
    """A server requested that the active step stop."""


def consume_budget(consume):
    if consume is not None and consume() is False:
        raise BudgetExceeded("active budget exhausted")


def resolve_addresses(host):
    return list(dict.fromkeys(row[4][0] for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)))


def connect_address(address, port, timeout):
    family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((address, port))
        return sock
    except BaseException:
        sock.close()
        raise


class ControlledTransport:
    def __init__(self, scope: ScopeGuard, *, resolver=None, connector=None,
                 clock=time.monotonic, sleep=time.sleep, consume=None,
                 rate_limit=2, timeout=10, max_response_bytes=262144, max_requests=100):
        for name, value in (("rate_limit", rate_limit), ("timeout", timeout),
                            ("max_response_bytes", max_response_bytes), ("max_requests", max_requests)):
            if isinstance(value, bool) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be positive and finite")
        if int(max_response_bytes) != max_response_bytes or int(max_requests) != max_requests:
            raise ValueError("byte and request limits must be integers")
        self.scope = scope
        self.resolver = resolver or resolve_addresses
        self.connector = connector or connect_address
        self.clock, self.sleep, self.consume = clock, sleep, consume
        self.rate_limit, self.timeout = rate_limit, timeout
        self.max_response_bytes, self.max_requests = int(max_response_bytes), int(max_requests)
        self.used = 0
        self.stopped = False
        self._last = None
        self._lock = threading.Lock()

    def _reserve(self):
        if self.used >= self.max_requests:
            raise BudgetExceeded("active transport request budget exhausted")
        if self._last is not None:
            self.sleep(max(0, 1 / self.rate_limit - (self.clock() - self._last)))
        consume_budget(self.consume)
        self.used += 1
        self._last = self.clock()

    def request(self, host, *, connect_ip=None, port=None, scheme="https", collision=False):
        with self._lock:
            return self._request(host, connect_ip=connect_ip, port=port, scheme=scheme, collision=collision)

    def _request(self, host, *, connect_ip, port, scheme, collision):
        if self.stopped:
            raise ActiveStepStopped("active step stopped after HTTP 429/503")
        if scheme not in {"http", "https"}:
            raise ValueError("only HTTP/HTTPS GET / is supported")
        if not isinstance(host, str):
            raise ValueError("host must be a domain name")
        host = host.lower().rstrip(".")
        allowed, reason = self.scope.check_domain(host)
        if not allowed:
            raise PermissionError(reason)
        port = port if port is not None else (443 if scheme == "https" else 80)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("invalid port")
        if collision and connect_ip is None:
            raise PermissionError("Host collision requires an explicitly authorized connection IP")
        if connect_ip is None:
            addresses = list(dict.fromkeys(str(ipaddress.ip_address(a)) for a in self.resolver(host)))
            if not addresses:
                raise OSError("DNS returned no addresses")
        else:
            addresses = [str(ipaddress.ip_address(connect_ip))]
        # Reject the whole DNS answer before opening any connection.
        for address in addresses:
            self.scope.assert_active_address(host, address, collision=collision)
        address = addresses[0]
        self._reserve()
        deadline = self.clock() + self.timeout
        sock = None
        conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
        try:
            sock = self.connector(address, port, self.timeout)
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise TimeoutError("active HTTP request timed out")
            sock.settimeout(remaining)
            if scheme == "https":
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            conn.sock = sock
            authority = host if port == (443 if scheme == "https" else 80) else f"{host}:{port}"
            conn.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", authority)
            conn.putheader("Connection", "close")
            conn.endheaders()
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise TimeoutError("active HTTP request timed out")
            sock.settimeout(remaining)
            response = conn.getresponse()
            if response.status in {429, 503}:
                self.stopped = True
            chunks, size = [], 0
            while size < self.max_response_bytes:
                remaining = deadline - self.clock()
                if remaining <= 0:
                    raise TimeoutError("active HTTP request timed out")
                sock.settimeout(remaining)
                chunk = response.read1(min(16384, self.max_response_bytes - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            body = b"".join(chunks)
            title = re.search(r"<title\b[^>]*>(.*?)</title\s*>", body.decode("utf-8", "replace"), re.I | re.S)
            return {"connect_ip": address, "port": port, "scheme": scheme, "host": host,
                    "sni": host if scheme == "https" else "", "status_code": response.status,
                    "content_length": size, "body_hash": hashlib.sha256(body).hexdigest(),
                    "title": unescape(re.sub(r"\s+", " ", title.group(1))).strip()[:512] if title else "",
                    "truncated": size == self.max_response_bytes, "stopped": self.stopped}
        finally:
            conn.close()
            if sock is not None:
                sock.close()
