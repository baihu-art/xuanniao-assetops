"""Offline safety and enumeration tests; no real sockets or DNS."""
import io
import ssl

import pytest

from assetops.active.host_collision import run_host_collision
from assetops.active.subdomain_brute import run_subdomain_brute
from assetops.active.transport import ActiveStepStopped, BudgetExceeded, ControlledTransport
from assetops.core.scope_guard import ScopeGuard, ScopeRules, TargetScope


def guard(domains=None, ips=None, cidrs=None, excludes=None, paths=None):
    return ScopeGuard([TargetScope(domains=domains or ["*.example.com"], ips=ips or [], cidrs=cidrs or [])],
                      ScopeRules(out_of_scope_domains=excludes or [], prohibited_paths=paths or []))


class FakeSocket:
    def __init__(self, response=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"):
        self.response = response
        self.sent = b""
        self.closed = False
        self.timeouts = []

    def sendall(self, data):
        self.sent += data

    def makefile(self, *args, **kwargs):
        return io.BytesIO(self.response)

    def settimeout(self, value):
        self.timeouts.append(value)

    def close(self):
        self.closed = True


def transport(scope=None, response=None, **kwargs):
    sockets, calls = [], []

    def connect(ip, port, timeout):
        calls.append((ip, port, timeout))
        sock = FakeSocket() if response is None else FakeSocket(response)
        sockets.append(sock)
        return sock

    client = ControlledTransport(scope or guard(), connector=connect, resolver=lambda host: ["8.8.8.8"],
                                 sleep=lambda seconds: None, **kwargs)
    return client, sockets, calls


@pytest.mark.parametrize("host", ["evil.com", "a.example.com/path", "a.example.com\r\nX: x", "8.8.8.8"])
def test_invalid_host_zero_connection(host):
    client, _, calls = transport()
    with pytest.raises(PermissionError):
        client.request(host, scheme="http")
    assert calls == []


def test_all_dns_addresses_validated_before_connect_and_explicit_limits():
    client, _, calls = transport()
    client.resolver = lambda host: ["8.8.8.8", "127.0.0.1"]
    with pytest.raises(PermissionError):
        client.request("a.example.com", scheme="http")
    assert not calls
    client.scope = guard(ips=["8.8.8.8"])
    client.resolver = lambda host: ["1.1.1.1"]
    with pytest.raises(PermissionError):
        client.request("a.example.com", scheme="http")
    assert not calls


def test_fixed_ip_ipv6_and_explicit_special_address():
    client, sockets, calls = transport(guard(ips=["::1"]))
    row = client.request("a.example.com", connect_ip="::1", scheme="http", collision=True)
    assert row["connect_ip"] == "::1"
    assert calls == [("::1", 80, 10)]
    assert sockets[0].sent == b"GET / HTTP/1.1\r\nHost: a.example.com\r\nConnection: close\r\n\r\n"
    assert sockets[0].closed


def test_host_collision_double_authorization_and_paths():
    for scope in (guard(), guard(ips=["8.8.8.8"], excludes=["a.example.com"]),
                  guard(ips=["8.8.8.8"], paths=["/"])):
        client, _, calls = transport(scope)
        with pytest.raises(PermissionError):
            client.request("a.example.com", connect_ip="8.8.8.8", collision=True, scheme="http")
        assert not calls
    assert not guard(domains=["8.8.8.8"]).check_ip("8.8.8.8")[0]


def test_https_sni_verified_and_tls_failure_consumes(monkeypatch):
    seen = []

    class Context:
        def wrap_socket(self, sock, server_hostname):
            seen.append(server_hostname)
            return sock

    monkeypatch.setattr("assetops.active.transport.ssl.create_default_context", lambda: Context())
    client, _, calls = transport(guard(ips=["8.8.8.8"]))
    row = client.request("a.example.com", connect_ip="8.8.8.8", collision=True)
    assert row["sni"] == "a.example.com" and seen == ["a.example.com"]

    def fail(*args, **kwargs):
        raise ssl.SSLCertVerificationError("certificate mismatch")

    monkeypatch.setattr(Context, "wrap_socket", fail)
    with pytest.raises(ssl.SSLCertVerificationError):
        client.request("a.example.com", connect_ip="8.8.8.8", collision=True)
    assert client.used == 2 and len(calls) == 2


def test_no_redirect_cookies_or_proxy(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://evil.example:1234")
    response = b"HTTP/1.1 302 Found\r\nLocation: http://evil.com/\r\nSet-Cookie: secret=x\r\nContent-Length: 0\r\n\r\n"
    client, sockets, calls = transport(response=response)
    assert client.request("a.example.com", scheme="http")["status_code"] == 302
    client.request("a.example.com", scheme="http")
    assert len(calls) == 2 and b"Cookie" not in sockets[1].sent


def test_body_bound_zero_length_and_hash():
    client, _, _ = transport(response=b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nabcdefghijklmnopqrst", max_response_bytes=5)
    row = client.request("a.example.com", scheme="http")
    assert row["content_length"] == 5 and row["truncated"]
    client, _, _ = transport()
    row = client.request("a.example.com", scheme="http")
    assert row["content_length"] == 0 and not row["truncated"] and len(row["body_hash"]) == 64


@pytest.mark.parametrize("status", [429, 503])
def test_server_stop(status):
    client, _, calls = transport(response=f"HTTP/1.1 {status} Stop\r\nContent-Length: 0\r\n\r\n".encode())
    assert client.request("a.example.com", scheme="http")["stopped"]
    with pytest.raises(ActiveStepStopped):
        client.request("a.example.com", scheme="http")
    assert len(calls) == 1


def test_budget_and_timeout_no_retry():
    remaining = [1]

    def consume():
        remaining[0] -= 1
        return remaining[0] >= 0

    client, _, calls = transport(consume=consume)
    client.request("a.example.com", scheme="http")
    with pytest.raises(BudgetExceeded):
        client.request("a.example.com", scheme="http")
    assert len(calls) == 1 and client.used == 1
    client, _, _ = transport(max_requests=1)
    client.connector = lambda *args: (_ for _ in ()).throw(TimeoutError("timeout"))
    with pytest.raises(TimeoutError):
        client.request("a.example.com", scheme="http")
    with pytest.raises(BudgetExceeded):
        client.request("a.example.com", scheme="http")


def test_rate_limit_injected_clock():
    now, waits = [0.0], []

    def sleep(seconds):
        waits.append(seconds)
        now[0] += seconds

    client, _, _ = transport(clock=lambda: now[0])
    client.sleep = sleep
    for _ in range(3):
        client.request("a.example.com", scheme="http")
    assert waits == [0.5, 0.5]


class FakeTransport:
    def __init__(self, status=200, max_requests=100):
        self.calls = []
        self.status = status
        self.max_requests = max_requests

    def request(self, host, *, connect_ip, scheme="https", port=None, collision=False):
        if len(self.calls) >= self.max_requests:
            raise BudgetExceeded("test budget exhausted")
        self.calls.append(host)
        return {"host": host, "connect_ip": connect_ip, "scheme": scheme,
                "port": port or 443, "sni": host if scheme == "https" else "",
                "status_code": self.status, "content_length": 0,
                "body_hash": "same", "title": ""}


def test_collision_same_403_unconfirmed_and_multi_host_preserved():
    fake = FakeTransport(status=403)
    result = run_host_collision(guard(ips=["8.8.8.8"]), ["8.8.8.8"],
                                ["a.example.com", "b.example.com"], transport=fake, ports=[("https", 443)])
    rows = [row for row in result["results"] if row["classification"] != "baseline"]
    assert [row["host"] for row in rows] == ["a.example.com", "b.example.com"]
    assert all(row["classification"] == "unconfirmed" for row in rows)
    assert all(row["sni"] == row["host"] for row in rows)


def test_random_baseline_never_bypasses_exact_scope_and_budget_partial():
    fake = FakeTransport(max_requests=2)
    result = run_host_collision(guard(domains=["a.example.com", "b.example.com"], ips=["8.8.8.8"]),
                                ["8.8.8.8"], ["a.example.com", "b.example.com"], transport=fake,
                                ports=[("http", 80)], random_label=lambda: "random")
    assert fake.calls == ["a.example.com", "a.example.com"]
    assert result["limited"] and result["errors"]
    assert result["results"][0]["confidence_limited"]


def test_dns_three_baselines_wildcard_and_bound():
    calls = []

    def resolver(host):
        calls.append(host)
        return ["8.8.8.8"]

    result = run_subdomain_brute(guard(), "example.com", labels=["www", "www", "bad.label", "extra"],
                                 resolver=resolver, max_candidates=3, sleep=lambda _: None)
    assert len(calls) == 4 and result["summary"]["baselines"] == 3
    assert result["summary"]["wildcard"] and result["limited"]
    assert result["results"][-1]["classification"] == "candidate"
    assert result["errors"][0]["error"] == "invalid non-recursive DNS label"


def test_dns_exact_root_does_not_authorize_children():
    calls = []
    result = run_subdomain_brute(guard(domains=["example.com"]), "example.com", labels=["www"],
                                 resolver=lambda host: calls.append(host))
    assert not calls and result["errors"] and not result["results"]


def test_dns_unauthorized_baselines_are_not_resolved():
    calls = []
    result = run_subdomain_brute(guard(domains=["example.com", "www.example.com"]), "example.com",
                                 labels=["www"], resolver=lambda host: calls.append(host) or ["8.8.8.8"],
                                 sleep=lambda _: None)
    assert calls == ["www.example.com"]
    assert len(result["errors"]) == 3
    assert result["results"][-1]["classification"] == "candidate"


def test_dns_budget_counts_baselines_and_http_opt_in():
    counts = []
    fake = FakeTransport()
    result = run_subdomain_brute(guard(), "example.com", labels=["www"],
                                 resolver=lambda host: ["8.8.8.8"], transport=fake,
                                 consume=lambda: counts.append(1), max_requests=3, sleep=lambda _: None)
    assert len(counts) == 3 and not fake.calls
    assert result["limited"] and len(result["results"]) == 3


def test_dns_http_differential_and_no_independent_wildcard_claim():
    fake = FakeTransport()
    result = run_subdomain_brute(guard(), "example.com", labels=["www"],
                                 resolver=lambda host: ["8.8.8.8"], transport=fake, verify_http=True,
                                 sleep=lambda _: None)
    assert len(fake.calls) == 4
    row = result["results"][-1]
    assert row["classification"] == "candidate" and row["http"]["classification"] == "candidate"
    assert row["http"]["sni"] == "www.example.com"


def test_dns_budget_callback_exhaustion_preserves_results():
    used = []

    def consume():
        if len(used) == 2:
            raise BudgetExceeded("persistent run budget exhausted")
        used.append(1)

    result = run_subdomain_brute(guard(), "example.com", labels=["www"],
                                 resolver=lambda host: ["8.8.8.8"], consume=consume,
                                 sleep=lambda _: None)
    assert result["limited"] and len(result["results"]) == 2
    assert "persistent run budget" in result["errors"][0]["error"]


def test_collision_differential_not_length_only_and_candidate_limit():
    class Different(FakeTransport):
        def request(self, host, **kwargs):
            row = super().request(host, **kwargs)
            row["body_hash"] = host
            return row

    result = run_host_collision(guard(ips=["8.8.8.8"]), ["8.8.8.8"],
                                ["a.example.com", "b.example.com"], transport=Different(),
                                ports=[("http", 80)], max_candidates=1)
    assert result["limited"]
    assert result["results"][-1]["classification"] == "differential"
    assert result["results"][-1]["content_length"] == 0


def test_bad_http_response_preserves_structured_errors():
    client, _, _ = transport(guard(ips=["8.8.8.8"]), response=b"not-http\r\n")
    result = run_host_collision(client.scope, ["8.8.8.8"], ["a.example.com"],
                                transport=client, ports=[("http", 80)])
    assert len(result["errors"]) == 2 and not result["results"]


def test_wordlist_bounded_and_missing(tmp_path):
    with pytest.raises(ValueError, match="exactly one"):
        run_subdomain_brute(guard(), "example.com")
    with pytest.raises(FileNotFoundError):
        run_subdomain_brute(guard(), "example.com", wordlist_path=tmp_path / "absent")
    path = tmp_path / "words.txt"
    path.write_text("a" * 100, encoding="utf-8")
    with pytest.raises(ValueError, match="byte size"):
        run_subdomain_brute(guard(), "example.com", wordlist_path=path, max_wordlist_bytes=10)
