import hashlib

import pytest

from assetops.active import jarm
from assetops.active.transport import BudgetExceeded
from assetops.core.scope_guard import ScopeGuard, ScopeRules, TargetScope


def scope():
    return ScopeGuard([TargetScope(domains=["*.example.com"], ips=["192.0.2.10", "2001:db8::10"])], ScopeRules())


def server_hello():
    extensions = bytes.fromhex("001000050003026832002b00020304")
    body = bytes.fromhex("0303") + b"R" * 32 + b"\x00" + bytes.fromhex("c02f00") + len(extensions).to_bytes(2,"big") + extensions
    handshake = b"\x02" + len(body).to_bytes(3,"big") + body
    return bytes.fromhex("160303") + len(handshake).to_bytes(2,"big") + handshake


class Socket:
    def __init__(self, response):
        self.response = response
        self.closed = False
        self.sent = []
    def settimeout(self, value):
        assert value > 0
    def sendall(self, packet):
        self.sent.append(packet)
    def recv(self, size):
        # Deliberately fragment both header and body.
        value = self.response[:min(size, 3)]
        self.response = self.response[len(value):]
        return value
    def close(self):
        self.closed = True


def test_reference_clienthello_vectors(monkeypatch):
    # SHA256 values from Salesforce JARM 1.0 with fixed urandom and GREASE.
    expected = [
        "87f603686aeb64298e811de97a48768539959360327956966713c9cbd492a2b5",
        "47e8d11ef0c847dd17f2a6a2086a4a7c72d7faa7fad820f2cfd21db5d575c794",
        "a1a2e1fd8ed4ed963019548a1eb2c95699cac2c46bbc12cff7e6a71ccef20136",
        "621b09efeab0af7389403d0457c2d87969306d7abeb5419dc3ae52c8b9a97817",
        "3e76b9c052a63fe7fafab4c6e6b4961139117bde537e1bf5fe12763c56f6b791",
        "bfe348df883cdd3a7343b876526fb57c2e5bbddfdada54f780b61cc88265cacb",
        "c7464ca17ef964a3c0ddbbdfb2702c978034cb10bcdb343c540704bcb26d9fc2",
        "ab33fb076a9df9c1e2d28ae719aa32a00e7d5680de9d24489f48a7f081b79a8a",
        "bc353612c5bbc384d49249d9c618e1b8ecf5da291ab0f69cebf486028f179237",
        "9022868e7ae016da1c3ed80a534a13a0a6bb338ba5e7ba377b3fc06b37042ad3",
    ]
    monkeypatch.setattr(jarm.os,"urandom",lambda n:b"R"*n)
    monkeypatch.setattr(jarm,"_grease",lambda:bytes.fromhex("0a0a"))
    assert [hashlib.sha256(jarm.build_probe("a.example.com",i)).hexdigest() for i in range(10)] == expected


def test_reference_hash_and_parser():
    parsed = jarm.parse_server_hello(server_hello())
    assert parsed == "c02f|0303|h2|0010-002b"
    assert jarm.jarm_hash([parsed]*10) == "29d29d29d29d29d29d29d29d29d29d0d4477735211fff828089be1851dd24c"
    assert jarm.jarm_hash(["1301|0303||002b"]*10) == "41d41d41d41d41d41d41d41d41d41d4f1dbd1908f46ba8828ca0cc2bfeb8c9"
    assert jarm.jarm_hash(["|||"]*10) == "0"*62
    with pytest.raises(ValueError):
        jarm.jarm_hash([parsed]*9)


def test_ten_fixed_ip_budgeted_handshakes():
    calls, sockets, consumed, sleeps, resolutions = [], [], [], [], []
    def resolver(host):
        resolutions.append(host)
        return ["192.0.2.10"]
    def connector(ip, port, timeout):
        assert len(consumed) == len(calls)+1
        calls.append((ip,port,timeout))
        sock = Socket(server_hello())
        sockets.append(sock)
        return sock
    result = jarm.collect_jarm("https://a.example.com:8443",scope_guard=scope(),consume=lambda:consumed.append(1),resolver=resolver,connector=connector,clock=lambda:0,sleep=sleeps.append)
    assert result["status"] == "done"
    assert len(result["jarm_hash"]) == 62
    assert calls == [("192.0.2.10",8443,10)]*10
    assert resolutions == ["a.example.com"]
    assert len(consumed) == 10
    assert sleeps == [0.5]*9
    assert all(s.closed and len(s.sent)==1 for s in sockets)
    assert result["certificate_verified"] is False
    assert "body" not in result


@pytest.mark.parametrize("addresses", [["192.0.2.10","127.0.0.1"],["10.0.0.1"],["192.0.2.11"]])
def test_all_addresses_checked_before_zero_connections(addresses):
    with pytest.raises(PermissionError):
        jarm.collect_jarm("https://a.example.com",scope_guard=scope(),consume=lambda:pytest.fail("no budget"),resolver=lambda h:addresses,connector=lambda *a:pytest.fail("no connection"))


def test_domain_blacklist_zero_resolution():
    guard = ScopeGuard([TargetScope(domains=["*.example.com"])],ScopeRules(out_of_scope_domains=["a.example.com"]))
    with pytest.raises(PermissionError):
        jarm.collect_jarm("https://a.example.com",scope_guard=guard,consume=lambda:None,resolver=lambda h:pytest.fail("no DNS"))


def test_budget_failure_propagates_closes_prior_socket():
    calls=[]
    def consume():
        if calls:
            raise BudgetExceeded("stop")
    def connector(*args):
        calls.append(Socket(server_hello()))
        return calls[-1]
    with pytest.raises(BudgetExceeded):
        jarm.collect_jarm("https://a.example.com",scope_guard=scope(),consume=consume,resolver=lambda h:["192.0.2.10"],connector=connector,sleep=lambda t:None)
    assert len(calls)==1 and calls[0].closed


@pytest.mark.parametrize("response", [bytes.fromhex("160303ffff"), server_hello()[:-1], b"", b"not tls"])
def test_bad_responses_fail_not_fingerprint(response):
    sock=Socket(response)
    result=jarm.collect_jarm("https://a.example.com",scope_guard=scope(),consume=lambda:None,resolver=lambda h:["192.0.2.10"],connector=lambda *a:sock)
    assert result["status"] == "failed"
    assert "jarm_hash" not in result
    assert result["handshakes_attempted"] == 1
    assert sock.closed


def test_all_alerts_no_zero_fingerprint():
    result=jarm.collect_jarm("https://192.0.2.10",scope_guard=scope(),consume=lambda:None,connector=lambda *a:Socket(bytes.fromhex("15030300020228")),sleep=lambda t:None)
    assert result["status"] == "no_fingerprint"
    assert "jarm_hash" not in result


def test_timeout_closes_and_counts_attempt():
    consumed=[]
    sock=Socket(server_hello())
    def send(packet):
        raise TimeoutError()
    sock.sendall=send
    result=jarm.collect_jarm("https://[2001:db8::10]",scope_guard=scope(),consume=lambda:consumed.append(1),connector=lambda *a:sock)
    assert result["status"] == "failed"
    assert sock.closed and consumed == [1]


def test_budget_false_zero_connections():
    with pytest.raises(BudgetExceeded):
        jarm.collect_jarm("https://192.0.2.10",scope_guard=scope(),consume=lambda:False,connector=lambda *a:pytest.fail("no connection"))


def test_deadline_expiry_and_connect_error():
    for connector in (lambda *a: Socket(server_hello()), lambda *a: (_ for _ in ()).throw(OSError("secret detail"))):
        ticks=iter([0,11])
        result=jarm.collect_jarm("https://192.0.2.10",scope_guard=scope(),consume=lambda:None,connector=connector,clock=lambda:next(ticks))
        assert result["status"] == "failed"
        assert "secret" not in result["error"]
        assert "jarm_hash" not in result


@pytest.mark.parametrize("target", ["http://a.example.com", "https://user:pass@a.example.com", "https://a.example.com:0", "https://a.example.com:99999", "https://a.example.com/?query=secret"])
def test_invalid_targets_zero_connections(target):
    with pytest.raises(ValueError):
        jarm.collect_jarm(target,scope_guard=scope(),consume=lambda:pytest.fail("no budget"),connector=lambda *a:pytest.fail("no connection"))


@pytest.mark.parametrize("kwargs", [{"timeout":0},{"rate_limit":True},{"timeout":float("nan")}])
def test_invalid_limits(kwargs):
    with pytest.raises(ValueError):
        jarm.collect_jarm("https://a.example.com",scope_guard=scope(),consume=lambda:None,**kwargs)
