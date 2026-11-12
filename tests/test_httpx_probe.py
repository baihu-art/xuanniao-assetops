import json
import subprocess

from assetops.active.httpx_probe import HttpxProbeResult, HttpxProbeSummary, probe_targets
from assetops.config.loader import AssetOpsConfig
from assetops.core.run_manager import RunManager
from assetops.core.scope_guard import ScopeGuard, TargetScope, ScopeRules
from assetops.storage import ArchiveStore, Database, list_assets


def _scope():
    return ScopeGuard([TargetScope(name="ok", domains=["*.example.com"])], ScopeRules())


def test_httpx_probe_uses_safe_command_and_parses_jsonl(tmp_path):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, '{"input":"a.example.com:443","url":"https://a.example.com:443","status_code":200,"title":"OK"}\n', "")

    result = probe_targets(["a.example.com:443", "evil.test"], scope_guard=_scope(),
                           executable=str(tmp_path / "httpx.exe"), run=fake_run)
    assert result.error == ""
    assert result.results[0].status_code == 200
    assert result.skipped == 1
    assert calls[0][0][:4] == [str(tmp_path / "httpx.exe"), "-json", "-duc", "-silent"]
    assert calls[0][1]["shell"] is False


def test_httpx_probe_normalizes_fields_and_filters_sensitive_data(tmp_path):
    row = {
        "input": "a.example.com:443",
        "url": "https://a.example.com:443",
        "status_code": 200,
        "title": "Login",
        "webserver": "nginx",
        "a": ["192.0.2.10"],
        "ip": "192.0.2.10",
        "asn": "AS64500",
        "cname": "origin.example.net",
        "tech": ["nginx", "React"],
        "favicon_hash": "123456",
        "jarm": "abcdef",
        "content_type": "text/html",
        "method": "GET",
        "words": 120,
        "lines": 18,
        "content_length": 4096,
        "time": "123ms",
        "body": "secret response body",
        "headers": {"Authorization": "Bearer secret"},
        "unknown": "ignored",
    }

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, json.dumps(row) + "\n", "")

    result = probe_targets(["a.example.com:443"], scope_guard=_scope(),
                           executable=str(tmp_path / "httpx.exe"), run=fake_run)
    evidence = result.results[0].raw
    assert evidence["status_code"] == 200
    assert evidence["tech"] == ["nginx", "React"]
    assert evidence["content_length"] == 4096
    assert "body" not in evidence
    assert "headers" not in evidence
    assert "unknown" not in evidence


def test_httpx_probe_drops_invalid_field_types_and_limits_evidence(tmp_path):
    row = {
        "input": "a.example.com",
        "url": "http://a.example.com",
        "status_code": {"bad": True},
        "title": "x" * 50000,
        "tech": "nginx",
        "a": {"bad": True},
        "body": "secret",
    }

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, json.dumps(row) + "\n", "")

    result = probe_targets(["a.example.com"], scope_guard=_scope(),
                           executable=str(tmp_path / "httpx.exe"), run=fake_run)
    evidence = result.results[0].raw
    assert result.results[0].status_code is None
    assert "status_code" not in evidence
    assert "tech" not in evidence
    assert "a" not in evidence
    assert len(json.dumps(evidence, ensure_ascii=False).encode("utf-8")) <= 32768
    assert len(evidence["title"]) <= 4096


def test_httpx_probe_rejects_bad_json_timeout_and_nonzero(tmp_path):
    def bad(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, "not-json\n", "")
    assert probe_targets(["a.example.com"], scope_guard=_scope(), executable=str(tmp_path / "httpx"), run=bad).error.startswith("bad JSONL")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 1)
    assert "timeout" in probe_targets(["a.example.com"], scope_guard=_scope(), executable=str(tmp_path / "httpx"), run=timeout).error

    def failed(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 2, "", "boom")
    assert "non-zero exit 2" in probe_targets(["a.example.com"], scope_guard=_scope(), executable=str(tmp_path / "httpx"), run=failed).error


def test_httpx_probe_rejects_relative_path_and_unapproved_args(tmp_path):
    try:
        probe_targets(["a.example.com"], scope_guard=_scope(), executable="httpx")
        assert False
    except Exception as exc:
        assert "absolute" in str(exc)
    try:
        probe_targets(["a.example.com"], scope_guard=_scope(), executable=str(tmp_path / "httpx"), extra_args=("-danger",))
        assert False
    except Exception as exc:
        assert "unsupported" in str(exc)


def test_run_manager_active_httpx_is_explicit_and_appends_observation(tmp_path, monkeypatch):
    db = Database(tmp_path / "db.sqlite")
    archive = ArchiveStore(tmp_path / "archives")
    config = AssetOpsConfig(httpx_enabled=True, httpx_path=str(tmp_path / "httpx"))
    mgr = RunManager(db, archive, _scope(), config)
    run = mgr.create_run("example.com", providers=["mock"])
    run = mgr.execute(run.id)
    assert not any(step.name == "active_httpx" for step in run.steps)

    def fake_probe(*args, **kwargs):
        return HttpxProbeSummary([HttpxProbeResult(
            target="webmail.example.com:443", url="https://webmail.example.com:443",
            ok=True, status_code=200, title="Login", webserver="nginx",
            raw={"url": "https://webmail.example.com:443", "status_code": 200,
                 "title": "Login", "webserver": "nginx", "tech": ["nginx"],
                 "body": "must not be present"},
        )])

    monkeypatch.setattr("assetops.core.run_manager.probe_targets", fake_probe)
    result = mgr.execute_httpx(run.id)
    step = next(s for s in result.steps if s.name == "active_httpx")
    assert step.status == "done"
    asset = next(asset for asset in list_assets(db, limit=50) if "httpx" in asset.sources)
    assert asset.title == "Example WebMail Login"
    assert asset.asset_type == "web_service"
    assert asset.server == "nginx/1.20.1"
    db.close()


def test_run_manager_httpx_failure_marks_completed_run_failed(tmp_path, monkeypatch):
    db = Database(tmp_path / "db.sqlite")
    archive = ArchiveStore(tmp_path / "archives")
    config = AssetOpsConfig(httpx_enabled=True, httpx_path=str(tmp_path / "httpx"))
    mgr = RunManager(db, archive, _scope(), config)
    run = mgr.create_run("example.com", providers=["mock"])
    run = mgr.execute(run.id)

    monkeypatch.setattr(
        "assetops.core.run_manager.probe_targets",
        lambda *args, **kwargs: HttpxProbeSummary([], error="timeout: fake"),
    )
    result = mgr.execute_httpx(run.id)
    step = next(s for s in result.steps if s.name == "active_httpx")
    assert result.status == "failed"
    assert step.status == "failed"
    assert "active_httpx failure" in result.notes
    db.close()
