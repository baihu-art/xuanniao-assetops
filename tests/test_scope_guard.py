"""ScopeGuard 单元测试。"""

from assetops.core.scope_guard import ScopeGuard, TargetScope, ScopeRules


def test_domain_match():
    guard = ScopeGuard(
        targets=[TargetScope(name="corp", domains=["example.com", "*.example.com"])],
        rules=ScopeRules(),
    )
    ok, _ = guard.check("https://admin.example.com/login")
    assert ok is True
    ok, _ = guard.check("https://api.example.com")
    assert ok is True
    ok, _ = guard.check("https://example.net")
    assert ok is False


def test_cidr_match():
    guard = ScopeGuard(
        targets=[TargetScope(name="corp", cidrs=["192.0.2.0/24"])],
        rules=ScopeRules(),
    )
    ok, _ = guard.check("192.0.2.100")
    assert ok is True
    ok, _ = guard.check("10.0.0.1")
    assert ok is False


def test_no_scope_default_deny():
    guard = ScopeGuard(targets=[], rules=ScopeRules())
    ok, reason = guard.check("https://example.com")
    assert ok is False
    assert "no scope configured" in reason


def test_blacklist_priority():
    guard = ScopeGuard(
        targets=[TargetScope(name="corp", domains=["*.example.com"])],
        rules=ScopeRules(out_of_scope_domains=["test.example.com"]),
    )
    ok, _ = guard.check("https://api.example.com")
    assert ok is True
    ok, _ = guard.check("https://test.example.com")
    assert ok is False


def test_from_dict():
    guard = ScopeGuard.from_dict({
        "targets": [{"domains": ["foo.bar"], "cidrs": ["10.0.0.0/8"]}],
        "rules": {"out_of_scope_domains": ["exclude.foo.bar"]},
    })
    assert guard.check("foo.bar")[0] is True
    assert guard.check("exclude.foo.bar")[0] is False
    assert guard.check("10.1.2.3")[0] is True
