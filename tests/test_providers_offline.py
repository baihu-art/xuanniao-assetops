"""真实 Provider 的离线响应测试，不访问外部网络。"""

import urllib.error

import pytest

from assetops.providers.base import ProviderConfigError, ProviderError
from assetops.providers.passive import PassiveDnsProvider, CtProvider, WhoisProvider, AsnProvider

from assetops.config.loader import AssetOpsConfig
from assetops.core.http import HttpClient
from assetops.core.scope_guard import ScopeGuard, TargetScope
from assetops.providers.fofa import FofaProvider
from assetops.providers.hunter import HunterProvider
from assetops.providers.quake import QuakeProvider
from assetops.providers.shodan import ShodanProvider


class FakeHttp:
    def __init__(self, *, get_responses=None, post_responses=None):
        self.get_responses = iter(get_responses or [])
        self.post_responses = iter(post_responses or [])
        self.calls = []

    def get(self, url, headers=None):
        self.calls.append(("GET", url, headers))
        return next(self.get_responses)

    def post(self, url, body, headers=None):
        self.calls.append(("POST", url, body, headers))
        return next(self.post_responses)


def make_scope():
    return ScopeGuard([TargetScope(name="testcorp", domains=["*.testcorp.example"])])


def test_fofa_offline_response_and_query():
    provider = FofaProvider(
        scope_guard=make_scope(),
        config=AssetOpsConfig(_fofa_email="test@example.com", _fofa_key="secret"),
    )
    http = FakeHttp(get_responses=[(
        {"size": 1, "results": [[
            "app.testcorp.example", "192.0.2.10", "443", "Portal", "",
            "HTTP/1.1 200 OK\nServer: nginx", "CN", "Shanghai", "testcorp.example",
        ]]}, 200, "",
    )])
    provider._http = http

    assets = provider.search("testcorp.example")

    assert len(assets) == 1
    assert assets[0].host == "app.testcorp.example"
    assert assets[0].server == "nginx"
    assert "qbase64=" in http.calls[0][1]


def test_fofa_key_only_auth_does_not_send_email():
    config = AssetOpsConfig(_fofa_key="secret")
    assert config.has_provider_credentials("fofa")
    provider = FofaProvider(scope_guard=make_scope(), config=config)
    assert provider.is_configured()
    http = FakeHttp(get_responses=[(
        {"size": 1, "results": [[
            "app.testcorp.example", "192.0.2.10", "443", "Portal", "",
            "", "CN", "Shanghai", "testcorp.example",
        ]]}, 200, "",
    )])
    provider._http = http

    assets = provider.search("testcorp.example")

    assert len(assets) == 1
    url = http.calls[0][1]
    assert "key=secret" in url
    assert "email=" not in url


def test_fofa_missing_key_raises_config_error_without_http():
    provider = FofaProvider(
        scope_guard=make_scope(),
        config=AssetOpsConfig(_fofa_email="test@example.com"),
    )
    assert not provider.is_configured()
    http = FakeHttp()
    provider._http = http
    with pytest.raises(ProviderConfigError):
        provider.search("testcorp.example")
    assert http.calls == []


def test_hunter_offline_response():
    provider = HunterProvider(
        scope_guard=make_scope(),
        config=AssetOpsConfig(_hunter_key="secret"),
    )
    http = FakeHttp(get_responses=[(
        {"code": 200, "data": {"total": 1, "arr": [{
            "url": "https://api.testcorp.example/login",
            "ip": "192.0.2.11", "port": 443, "web_title": "API",
            "component": [{"name": "nginx"}], "country_name": "China",
        }]}}, 200, "",
    )])
    provider._http = http

    assets = provider.search("testcorp.example")

    assert len(assets) == 1
    assert assets[0].host == "api.testcorp.example"
    assert assets[0].server == "nginx"
    assert "search=" in http.calls[0][1]


def test_quake_offline_response():
    provider = QuakeProvider(
        scope_guard=make_scope(),
        config=AssetOpsConfig(_quake_token="secret"),
    )
    http = FakeHttp(post_responses=[(
        {"code": 0, "meta": {"total": 1}, "data": [{
            "ip": "192.0.2.12", "port": 8443,
            "hostname": "admin.testcorp.example",
            "service": {"http": {"host": "admin.testcorp.example", "title": "Admin"}},
            "location": {"country_cn": "中国", "province_cn": "上海"},
        }]}, 200, "",
    )])
    provider._http = http

    assets = provider.search("testcorp.example")

    assert len(assets) == 1
    assert assets[0].host == "admin.testcorp.example"
    assert assets[0].port == "8443"
    assert http.calls[0][3] == {"X-QuakeToken": "secret"}


def test_shodan_dns_fallback_offline_response():
    provider = ShodanProvider(
        scope_guard=make_scope(),
        config=AssetOpsConfig(_shodan_key="secret"),
    )
    http = FakeHttp(get_responses=[
        ({"error": "This query requires a paid plan"}, 200, ""),
        ({"subdomains": ["www", "admin"]}, 200, ""),
    ])
    provider._http = http

    assets = provider.search("testcorp.example")

    assert [asset.host for asset in assets] == [
        "www.testcorp.example", "admin.testcorp.example",
    ]
    assert all(asset.observations[0].confidence == "low" for asset in assets)
    assert http.calls[1][1].startswith("https://api.shodan.io/dns/domain/")


def test_fofa_short_page_stops_and_filters_out_of_scope_results():
    provider = FofaProvider(
        scope_guard=make_scope(),
        config=AssetOpsConfig(_fofa_email="e", _fofa_key="k"),
    )
    http = FakeHttp(get_responses=[(
        {"size": 1000, "results": [
            ["inside.testcorp.example", "192.0.2.20", "80", "", "", "", "", "", ""],
            ["outside.example", "192.0.2.21", "80", "", "", "", "", "", ""],
        ]}, 200, "",
    )])
    provider._http = http

    assets = provider.search("testcorp.example")

    assert [asset.host for asset in assets] == ["inside.testcorp.example"]
    assert len(http.calls) == 1


def test_hunter_pagination_stops_on_short_page():
    provider = HunterProvider(
        scope_guard=make_scope(),
        config=AssetOpsConfig(_hunter_key="k"),
    )
    first_page = [{
        "url": f"https://node-{index}.testcorp.example",
        "ip": f"192.0.2.{30 + index}", "port": 443,
    } for index in range(100)]
    second_page = [{
        "url": "last.testcorp.example", "ip": "192.0.2.130", "port": 443,
    }]
    http = FakeHttp(get_responses=[
        ({"code": 200, "data": {"total": 101, "arr": first_page}}, 200, ""),
        ({"code": 200, "data": {"total": 101, "arr": second_page}}, 200, ""),
    ])
    provider._http = http

    assets = provider.search("testcorp.example")

    assert len(assets) == 101
    assert len(http.calls) == 2
    assert "page=2" in http.calls[1][1]


def test_quake_max_pages_is_bounded_when_total_is_unknown():
    provider = QuakeProvider(
        scope_guard=make_scope(),
        config=AssetOpsConfig(_quake_token="k"),
    )
    provider.max_pages = 2
    page = [{
        "ip": f"192.0.2.{40 + index}", "port": 443,
        "hostname": f"node-{index}.testcorp.example",
        "service": {"http": {"host": f"node-{index}.testcorp.example"}},
    } for index in range(100)]
    response = {"code": 0, "meta": {"total": 0}, "data": page}
    http = FakeHttp(post_responses=[(response, 200, ""), (response, 200, "")])
    provider._http = http

    assets = provider.search("testcorp.example")

    assert len(assets) == 200
    assert len(http.calls) == 2
    assert "start=100" in http.calls[1][1]


def test_shodan_pagination_stops_at_reported_total():
    provider = ShodanProvider(
        scope_guard=make_scope(),
        config=AssetOpsConfig(_shodan_key="k"),
    )
    first_page = [{
        "hostnames": [f"node-{index}.testcorp.example"],
        "ip_str": f"192.0.2.{60 + index}", "port": 443,
    } for index in range(100)]
    second_page = [{
        "hostnames": ["last.testcorp.example"], "ip_str": "192.0.2.160", "port": 443,
    }]
    http = FakeHttp(get_responses=[
        ({"total": 101, "matches": first_page}, 200, ""),
        ({"total": 101, "matches": second_page}, 200, ""),
    ])
    provider._http = http

    assets = provider.search("testcorp.example")

    assert len(assets) == 101
    assert len(http.calls) == 2
    assert "page=2" in http.calls[1][1]


def test_provider_business_errors_return_no_assets_without_extra_requests():
    cases = [
        (FofaProvider, AssetOpsConfig(_fofa_email="e", _fofa_key="k"),
         FakeHttp(get_responses=[({"error": True, "errmsg": "bad query"}, 200, "")])),
        (HunterProvider, AssetOpsConfig(_hunter_key="k"),
         FakeHttp(get_responses=[({"code": 403, "message": "denied"}, 200, "")])),
        (QuakeProvider, AssetOpsConfig(_quake_token="k"),
         FakeHttp(post_responses=[({"code": 403, "message": "denied"}, 200, "" )])),
        (ShodanProvider, AssetOpsConfig(_shodan_key="k"),
         FakeHttp(get_responses=[({"error": "invalid key"}, 200, "")])),
    ]
    for provider_type, config, http in cases:
        provider = provider_type(scope_guard=make_scope(), config=config)
        provider._http = http
        assert provider.search("testcorp.example") == []
        assert len(http.calls) == 1


def test_provider_stops_on_http_error_response():
    provider = HunterProvider(
        scope_guard=make_scope(),
        config=AssetOpsConfig(_hunter_key="k"),
    )
    http = FakeHttp(get_responses=[(None, 503, "HTTP 503")])
    provider._http = http

    assert provider.search("testcorp.example") == []
    assert len(http.calls) == 1


def test_provider_ignores_malformed_fofa_items():
    provider = FofaProvider(
        scope_guard=make_scope(),
        config=AssetOpsConfig(_fofa_email="e", _fofa_key="k"),
    )
    provider._http = FakeHttp(get_responses=[(
        {"size": 2, "results": [None, ["ok.testcorp.example", "192.0.2.90", "443"]]},
        200, "",
    )])

    assets = provider.search("testcorp.example")

    assert len(assets) == 1


def test_provider_rejects_out_of_scope_before_http():
    for provider in (
        FofaProvider(scope_guard=make_scope(), config=AssetOpsConfig(_fofa_email="e", _fofa_key="k")),
        QuakeProvider(scope_guard=make_scope(), config=AssetOpsConfig(_quake_token="k")),
        HunterProvider(scope_guard=make_scope(), config=AssetOpsConfig(_hunter_key="k")),
        ShodanProvider(scope_guard=make_scope(), config=AssetOpsConfig(_shodan_key="k")),
    ):
        http = FakeHttp()
        provider._http = http
        try:
            provider.search("not-authorized.example")
        except PermissionError:
            pass
        else:
            raise AssertionError("out-of-scope target was not rejected")
        assert http.calls == []


def test_http_client_retries_429_then_returns_json(monkeypatch):
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"ok": true}'

    attempts = {"count": 0}

    def fake_urlopen(request, timeout, context):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise urllib.error.HTTPError(
                request.full_url, 429, "Too Many Requests", {},
                __import__("io").BytesIO(b"secret token"),
            )
        return Response()

    waits = []
    monkeypatch.setattr("assetops.core.http.urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("assetops.core.http.time.sleep", waits.append)

    client = HttpClient(rate_limit=0, max_retries_429=1)
    data, status, error = client.get("https://example.test/api?key=secret")

    assert data == {"ok": True}
    assert status == 200
    assert error == ""
    assert attempts["count"] == 2
    assert waits == [10]


def test_http_client_returns_error_after_429_retries_exhausted(monkeypatch):
    def fake_urlopen(request, timeout, context):
        raise urllib.error.HTTPError(
            request.full_url, 429, "Too Many Requests", {},
            __import__("io").BytesIO(b"secret token"),
        )

    waits = []
    monkeypatch.setattr("assetops.core.http.urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("assetops.core.http.time.sleep", waits.append)

    client = HttpClient(rate_limit=0, max_retries_429=1)
    data, status, error = client.get("https://example.test/api?token=secret")

    assert data is None
    assert status == 429
    assert error == "HTTP 429"
    assert waits == [10]


def test_http_client_reports_non_json_response(monkeypatch):
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"not json"

    monkeypatch.setattr("assetops.core.http.urllib.request.urlopen", lambda *args, **kwargs: Response())

    client = HttpClient(rate_limit=0)
    data, status, error = client.get("https://example.test/api")

    assert data is None
    assert status == 200
    assert error == "non-JSON response (len=8)"


PASSIVE_CASES = [
    (PassiveDnsProvider, "testcorp.example", {"Status": 0, "Answer": [
        {"name": "app.testcorp.example.", "type": 1, "TTL": 300, "data": "192.0.2.10"},
        {"name": "outside.example.", "type": 1, "data": "192.0.2.20"},
        {"name": "testcorp.example.", "type": 5, "data": "alias.testcorp.example."},
        {"name": "testcorp.example.", "type": 5, "data": "outside.example."},
        None,
    ]}, ["app.testcorp.example", "alias.testcorp.example"]),
    (CtProvider, "testcorp.example", [
        {"id": 42, "issuer_name": "Fixture CA", "name_value":
         "app.testcorp.example\n*.testcorp.example\noutside.example\napp.testcorp.example"},
        {"name_value": None}, None,
    ], ["testcorp.example", "app.testcorp.example"]),
    (WhoisProvider, "testcorp.example", {"WhoisRecord": {
        "domainName": "testcorp.example", "registrarName": "Fixture Registrar",
        "createdDate": "2020-01-01", "nameServers": {"hostNames": ["ns.outside.example"]},
    }}, ["testcorp.example"]),
    (AsnProvider, "192.0.2.10", {
        "ip": "192.0.2.10", "asn": 64500, "as_name": "Fixture ASN",
        "prefix": "192.0.0.0/16", "as_domain": "outside.example",
    }, [""]),
]


@pytest.fixture
def passive_scope(monkeypatch):
    def deny_dns(*args, **kwargs):
        raise AssertionError("offline providers must not resolve DNS")
    monkeypatch.setattr("socket.gethostbyname", deny_dns)
    return ScopeGuard([TargetScope(
        name="offline", domains=["*.testcorp.example"], ips=["192.0.2.10"],
    )])


def passive_config():
    return AssetOpsConfig(
        passive_dns_endpoint="https://fixture.invalid/dns", ct_endpoint="https://fixture.invalid/ct",
        whois_endpoint="https://fixture.invalid/whois", asn_endpoint="https://fixture.invalid/asn",
        _whois_key="fixture-key", _asn_key="fixture-key",
    )


@pytest.mark.parametrize("provider_type,target,response,hosts", PASSIVE_CASES)
def test_passive_normal_and_scope_filter(passive_scope, provider_type, target, response, hosts):
    provider = provider_type(scope_guard=passive_scope, config=passive_config())
    http = FakeHttp(get_responses=[(response, 200, "")])
    provider._http = http
    before = passive_scope.summary()
    assets = provider.search(target)
    assert [asset.host for asset in assets] == hosts
    assert passive_scope.summary() == before
    assert len(http.calls) == 1
    assert all(asset.sources == {provider.name} for asset in assets)
    assert all(asset.observations[0].evidence["source_target"] == target for asset in assets)
    if provider_type is PassiveDnsProvider:
        assert assets[0].observations[0].evidence["ttl"] == 300
        assert "name=testcorp.example&type=ANY" in http.calls[0][1]
    elif provider_type is CtProvider:
        assert assets[0].observations[0].evidence["wildcard"] is True
        assert "q=testcorp.example&output=json" in http.calls[0][1]
    elif provider_type is WhoisProvider:
        assert assets[0].observations[0].evidence["registrar"] == "Fixture Registrar"
    else:
        assert assets[0].ip == "192.0.2.10"
        assert assets[0].observations[0].evidence["prefix"] == "192.0.0.0/16"
    if provider.requires_credentials:
        assert http.calls[0][2]["Authorization"] == "Bearer fixture-key"
        assert "fixture-key" not in http.calls[0][1]


@pytest.mark.parametrize("provider_type,target,response,hosts", PASSIVE_CASES)
def test_passive_missing_config_and_preflight_scope(passive_scope, provider_type, target, response, hosts):
    provider = provider_type(scope_guard=passive_scope, config=AssetOpsConfig())
    provider._http = FakeHttp()
    assert not provider.is_configured()
    with pytest.raises(ProviderConfigError):
        provider.search(target)
    provider._config = passive_config()
    with pytest.raises(PermissionError):
        provider.search("outside.example")
    assert provider._http.calls == []


@pytest.mark.parametrize("provider_type,target", [(case[0], case[1]) for case in PASSIVE_CASES])
@pytest.mark.parametrize("response,status,error", [
    ({"error": "secret fixture-key"}, 200, ""),
    ({"success": False}, 200, ""),
    (None, 503, "secret fixture-key"),
    ({}, 403, ""),
    ("not a JSON object", 200, ""),
])
def test_passive_errors_are_failures(passive_scope, provider_type, target, response, status, error):
    provider = provider_type(scope_guard=passive_scope, config=passive_config())
    provider._http = FakeHttp(get_responses=[(response, status, error)])
    with pytest.raises(ProviderError) as exc:
        provider.search(target)
    assert "secret" not in str(exc.value)
    assert "fixture-key" not in str(exc.value)
    assert len(provider._http.calls) == 1


def test_passive_dns_domain_does_not_authorize_ip(passive_scope):
    provider = PassiveDnsProvider(scope_guard=passive_scope, config=passive_config())
    provider._http = FakeHttp(get_responses=[({"Status": 0, "Answer": [
        {"name": "app.testcorp.example", "type": 1, "data": "198.51.100.1"},
        {"name": "app.testcorp.example", "type": 28, "data": "2001:db8::1"},
        {"name": "app.testcorp.example", "type": 1, "data": "invalid-ip"},
    ]}, 200, "")])
    assets = provider.search("testcorp.example")
    assert len(assets) == 2
    assert all(asset.ip == "" for asset in assets)
    assert assets[0].observations[0].evidence["record_data"] == "198.51.100.1"
    assert not passive_scope.check("198.51.100.1", resolve_dns=False)[0]


@pytest.mark.parametrize("provider_type,target,response", [
    (WhoisProvider, "testcorp.example", {"WhoisRecord": {"domainName": "outside.example"}}),
    (AsnProvider, "192.0.2.10", {"ip": "198.51.100.1", "asn": 64500}),
])
def test_passive_metadata_rejects_foreign_result(passive_scope, provider_type, target, response):
    provider = provider_type(scope_guard=passive_scope, config=passive_config())
    provider._http = FakeHttp(get_responses=[(response, 200, "")])
    assert provider.search(target) == []


@pytest.mark.parametrize("provider_type,field", [(WhoisProvider, "_whois_key"), (AsnProvider, "_asn_key")])
def test_passive_key_required_even_with_endpoint(passive_scope, provider_type, field):
    config = passive_config()
    setattr(config, field, "")
    provider = provider_type(scope_guard=passive_scope, config=config)
    provider._http = FakeHttp()
    assert not provider.is_configured()
    target = "192.0.2.10" if provider_type is AsnProvider else "testcorp.example"
    with pytest.raises(ProviderConfigError):
        provider.search(target)
    assert provider._http.calls == []


def test_passive_config_env_and_registry(monkeypatch):
    from assetops.core.run_manager import RunManager
    for provider_type, _, _, _ in PASSIVE_CASES:
        name = provider_type.name
        monkeypatch.setenv(f"{name.upper()}_ENDPOINT", f"https://fixture.invalid/{name}")
        monkeypatch.setenv(f"{name.upper()}_KEY", "fixture-key")
    config = AssetOpsConfig.from_env()
    for provider_type, _, _, _ in PASSIVE_CASES:
        assert config.has_provider_credentials(provider_type.name)
        assert RunManager.PROVIDERS[provider_type.name] is provider_type
        assert config.safe_view()["credentials_present"][provider_type.name]
    assert "fixture-key" not in str(config.safe_view())


@pytest.mark.parametrize("response", [{"Status": 2}, {"Status": 0, "Answer": {}}])
def test_passive_dns_business_and_shape_errors(passive_scope, response):
    provider = PassiveDnsProvider(scope_guard=passive_scope, config=passive_config())
    provider._http = FakeHttp(get_responses=[(response, 200, "")])
    with pytest.raises(ProviderError):
        provider.search("testcorp.example")


def test_passive_dns_falls_back_to_typed_queries_when_any_refused(passive_scope):
    responses = [
        ({"Status": 0, "Answer": [
            {"name": "testcorp.example.", "type": 13, "data": '"RFC8482"'},
        ]}, 200, ""),
        ({"Status": 0, "Answer": [
            {"name": "app.testcorp.example.", "type": 1, "TTL": 300, "data": "192.0.2.10"},
        ]}, 200, ""),
        ({"Status": 0, "Answer": [
            {"name": "app.testcorp.example.", "type": 28, "data": "2001:db8::1"},
        ]}, 200, ""),
        ({"Status": 0, "Answer": [
            {"name": "testcorp.example.", "type": 2, "data": "ns1.testcorp.example."},
        ]}, 200, ""),
        ({"Status": 0, "Answer": [
            {"name": "app.testcorp.example.", "type": 5, "data": "alias.testcorp.example."},
        ]}, 200, ""),
        ({"Status": 0, "Answer": [
            {"name": "testcorp.example.", "type": 15, "data": "10 mail.testcorp.example."},
        ]}, 200, ""),
    ]
    provider = PassiveDnsProvider(scope_guard=passive_scope, config=passive_config())
    provider._http = FakeHttp(get_responses=responses)
    assets = provider.search("testcorp.example")
    hosts = {asset.host for asset in assets}
    assert hosts == {
        "app.testcorp.example", "ns1.testcorp.example",
        "alias.testcorp.example", "mail.testcorp.example",
    }
    query_urls = [call[1] for call in provider._http.calls]
    assert "type=ANY" in query_urls[0]
    assert any("type=A&" in url or url.endswith("type=A") for url in query_urls[1:])
    assert any("type=MX" in url for url in query_urls)
    mx_asset = next(asset for asset in assets if asset.host == "mail.testcorp.example")
    assert mx_asset.observations[0].evidence["record_type"] == 15
