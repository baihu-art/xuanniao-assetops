import json
import subprocess

import pytest

from assetops.active.fingerprints import FaviconResponse, collect_favicon, favicon_mmh3, normalize_fingerprints
from assetops.active.httpx_probe import probe_targets
from assetops.core.scope_guard import ScopeGuard, ScopeRules, TargetScope


def guard(paths=None):
    return ScopeGuard([TargetScope(domains=["*.example.com"], ips=["192.0.2.10"])], ScopeRules(prohibited_paths=paths or []))


@pytest.mark.parametrize("value", [-12345,"-12345","+12345",0])
def test_favicon_signed_and_alias(value):
    assert normalize_fingerprints({"favicon":value})["favicon_hash"] == str(int(value))


@pytest.mark.parametrize("value", [True,1.5,"x",2**31,-2**31-1])
def test_invalid_favicon(value):
    assert normalize_fingerprints({"favicon_hash":value}) == {}


@pytest.mark.parametrize("value", ["0"*62,"a"*61,"g"*62,"abcdef",True])
def test_invalid_jarm(value):
    assert normalize_fingerprints({"jarm":value}) == {}


def test_jarm_alias():
    assert normalize_fingerprints({"jarm":"A"*62}) == {"jarm_hash":"a"*62}
    assert normalize_fingerprints({"jarm_hash":"b"*62}) == {"jarm_hash":"b"*62}


@pytest.mark.parametrize("options", [{"favicon":True},{"jarm":True}])
def test_external_fingerprints_fail_closed(tmp_path,options):
    def forbidden(*args,**kwargs):
        pytest.fail("must not execute external fingerprints")
    result = probe_targets(["a.example.com"],scope_guard=guard(),executable=str(tmp_path/"httpx.exe"),run=forbidden,**options)
    assert result.error.startswith("unsupported:")


def test_typed_options(tmp_path):
    with pytest.raises(TypeError):
        probe_targets([],scope_guard=guard(),executable=str(tmp_path/"httpx.exe"),favicon="false")


@pytest.mark.parametrize("row", [
    {"input":"b.example.com:443","url":"https://b.example.com"},
    {"input":"a.example.com:443","url":"https://b.example.com"},
    {"input":"a.example.com:443","url":"https://a.example.com:8443"},
    {"input":"a.example.com:443","url":"https://evil.test"},
    {"input":"a.example.com:443","url":"https://a.example.com","a":["127.0.0.1"]},
])
def test_output_binding(tmp_path,row):
    result = probe_targets(["a.example.com:443"],scope_guard=guard(),executable=str(tmp_path/"httpx.exe"),run=lambda *args,**kwargs:subprocess.CompletedProcess(args[0],0,json.dumps(row),""))
    assert result.results == []
    assert result.skipped == 1


def test_favicon_fixed_path_and_no_body_evidence():
    calls = []
    def fetch(url,**kwargs):
        calls.append((url,kwargs))
        return FaviconResponse(url,200,b"icon bytes")
    result = collect_favicon("https://a.example.com/page",scope_guard=guard(),fetch=fetch)
    assert calls == [("https://a.example.com/favicon.ico",{"max_bytes":262144,"follow_redirects":False})]
    assert result["favicon_hash"] == favicon_mmh3(b"icon bytes")
    assert "body" not in result
    assert favicon_mmh3(b"") == "0"
    assert favicon_mmh3(b"hello") == "1155597304"


def test_favicon_prohibited_path_zero_calls():
    with pytest.raises(PermissionError):
        collect_favicon("https://a.example.com",scope_guard=guard(["/favicon*"]),fetch=lambda *a,**k:pytest.fail("forbidden"))


@pytest.mark.parametrize("response,status", [(FaviconResponse("https://a.example.com/favicon.ico",302,b""),"no_fingerprint"),(FaviconResponse("https://a.example.com/favicon.ico",429,b""),"stopped"),(FaviconResponse("https://a.example.com/favicon.ico",503,b""),"stopped"),(FaviconResponse("https://a.example.com/favicon.ico",200,b"x",True),"failed"),(FaviconResponse("https://evil.test/favicon.ico",200,b"x"),"failed")])
def test_favicon_stops_redirects_and_limits(response,status):
    assert collect_favicon("https://a.example.com",scope_guard=guard(),fetch=lambda *a,**k:response)["status"] == status


def test_transport_favicon_adapter():
    class Transport:
        def request_favicon(self,host,**kwargs):
            assert host == "a.example.com"
            assert kwargs == {"port":8443,"scheme":"https"}
            return {"status_code":200,"body":b"hello","truncated":False}
    assert collect_favicon("https://a.example.com:8443",scope_guard=guard(),transport=Transport())["status"] == "done"
    assert collect_favicon("https://a.example.com",scope_guard=guard())["status"] == "unsupported"
