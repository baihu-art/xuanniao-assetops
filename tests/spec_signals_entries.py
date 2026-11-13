"""CLI/MCP及当前Run导出的离线契约测试。"""

import importlib
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from assetops import cli
from assetops.analysis import signals
from assetops.models.asset import Asset, Observation
from assetops.models.run import Run, RunStep
from assetops.storage import Database
from assetops.storage.queries import insert_run, upsert_asset, insert_observation


@pytest.fixture
def evidence_db(tmp_path):
    db = Database(tmp_path / "test.db")
    run = Run(id="run_one", steps=[RunStep(name="asset_analysis", status="done"),
                                  RunStep(name="host_collision", status="failed", limited=True)])
    insert_run(db, run)
    insert_run(db, Run(id="run_two"))
    asset = Asset(id="asset1", host="later.example", ip="203.0.113.1", port="443", primary_key="203.0.113.1:443", title="OTHER RUN")
    aid = upsert_asset(db, asset)
    for obs in [
        Observation(run_id=run.id, source="httpx", evidence={"host": "old.example", "ip": asset.ip, "port": "443", "title": "A|B\nC token=hidden", "favicon_hash": "-123", "jarm_hash": "abc", "body": "BODY_SECRET", "headers": {"Authorization": "SECRET"}}),
        Observation(run_id=run.id, source="favicon", evidence={"favicon_hash": "-456", "host": "old.example"}),
        Observation(run_id=run.id, source="jarm", evidence={"jarm_hash": "a" * 62, "host": "old.example", "handshakes_attempted": 10, "handshakes_completed": 10, "certificate_verified": False, "fingerprint_version": "jarm-v1", "truncated": False}),
        Observation(run_id=run.id, source="analysis", evidence={"rule_version": "yingzhao-v1", "score": 61, "priority": "high", "dimensions": {"exposure": 30}, "input_observation_ids": ["obs1"]}),
        Observation(run_id=run.id, source="host_collision", evidence={"classification": "unconfirmed", "host": "old.example", "connect_ip": asset.ip, "baseline_different": False}),
        Observation(run_id="run_two", source="httpx", evidence={"title": "OTHER_RUN_SECRET", "host": "later.example"}),
    ]:
        insert_observation(db, obs.run_id, obs, aid)
    yield db
    db.close()


def test_signals_schema_isolation_redaction_and_report(evidence_db, tmp_path):
    result = signals.export_signals(evidence_db, tmp_path, "run_one")
    assert set(result["paths"]) == set(signals.KINDS)
    for kind, location in result["paths"].items():
        path = Path(location)
        assert path.parent == tmp_path / "runs" / "run_one" / "signals"
        text = path.read_text(encoding="utf-8")
        assert not any(secret in text for secret in ("OTHER_RUN_SECRET", "OTHER RUN", "BODY_SECRET", "hidden", "Authorization"))
        payload = json.loads(text)
        assert set(payload) == {"schema_version", "run_id", "kind", "status", "data", "warnings"}
        assert set(payload["data"]) == ({"assets"} if kind == "assets" else {"results"})
    data = signals.build_signals(evidence_db, "run_one")
    assert data["assets"]["data"]["assets"][0]["host"] == "old.example"
    assert any(r.get("evidence", {}).get("favicon_hash") == "-456" for r in data["favicon"]["data"]["results"])
    assert any(r.get("evidence", {}).get("jarm_hash") == "a" * 62 for r in data["jarm"]["data"]["results"])
    jarm = next(r["evidence"] for r in data["jarm"]["data"]["results"] if r["evidence"].get("fingerprint_version"))
    assert jarm["handshakes_attempted"] == jarm["handshakes_completed"] == 10
    assert jarm["certificate_verified"] is False and jarm["truncated"] is False
    assert data["analysis"]["status"] == "done"
    assert data["host_collision"]["warnings"]
    assert data["analysis"]["data"]["results"][0]["evidence"]["dimensions"] == {"exposure": 30}
    report = signals.export_report(evidence_db, tmp_path, "run_one", "markdown")
    text = Path(report["path"]).read_text(encoding="utf-8")
    assert "A\\|B C" in text and "五维评分" in text and "候选验证状态" in text
    assert not list(tmp_path.rglob("*.tmp"))


@pytest.mark.parametrize("run_id", ["../escape", "", "unknown"])
def test_export_rejects_bad_run(evidence_db, tmp_path, run_id):
    with pytest.raises(ValueError):
        signals.export_signals(evidence_db, tmp_path, run_id)


@pytest.mark.parametrize("argv,method,options,step", [
    (["analyze", "run_one"], "execute_analyze", {}, "asset_analysis"),
    (["httpx", "run_one", "--favicon", "--jarm"], "execute_httpx", {"favicon": True, "jarm": True}, "active_httpx"),
    (["host-collision", "run_one", "--hosts", "a.example", "--ips", "203.0.113.1"], "execute_host_collision", {"hosts": ["a.example"], "ips": ["203.0.113.1"]}, "host_collision"),
    (["subdomain-brute", "run_one", "example", "--labels", "www", "api", "--verify-http"], "execute_subdomain_brute", {"domain": "example", "labels": ["www", "api"], "wordlist": None, "verify_http": True}, "subdomain_brute"),
])
def test_cli_forwards_options(monkeypatch, capsys, argv, method, options, step):
    calls = []
    def execute(run_id, **kwargs):
        calls.append((run_id, kwargs))
        return Run(id=run_id, status="completed", steps=[RunStep(name=step, status="done")])
    mgr = SimpleNamespace(**{method: execute})
    monkeypatch.setattr(cli, "_setup", lambda: (mgr, None, SimpleNamespace(is_configured=True)))
    assert cli.main(argv) == 0
    assert calls == [("run_one", options)]
    assert json.loads(capsys.readouterr().out)["step"]["name"] == step


def test_cli_failed_step_is_nonzero(monkeypatch, capsys):
    mgr = SimpleNamespace(execute_analyze=lambda rid: Run(id=rid, steps=[RunStep(name="asset_analysis", status="failed", error="offline failure")]))
    monkeypatch.setattr(cli, "_setup", lambda: (mgr, None, None))
    assert cli.main(["analyze", "x"]) == 1
    assert "offline failure" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.main(["subdomain-brute", "x", "example"])
    with pytest.raises(SystemExit):
        cli.main(["export-report"])


def test_mcp_registered_tools_forward_and_export(monkeypatch, evidence_db, tmp_path):
    class FakeMCP:
        def __init__(self, **kwargs):
            self.tools = {}
        def tool(self):
            def register(fn):
                self.tools[fn.__name__] = fn
                return fn
            return register
    fake = ModuleType("mcp.server.fastmcp")
    fake.FastMCP = FakeMCP
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fake)
    import assetops.mcp_server as server
    server = importlib.reload(server)
    calls = []
    def execute(rid, **kwargs):
        calls.append(kwargs)
        return Run(id=rid, steps=[RunStep(name="active_httpx", status="skipped")])
    mgr = SimpleNamespace(_db=evidence_db, execute_httpx=execute)
    monkeypatch.setattr(server, "_ensure", lambda: mgr)
    monkeypatch.setattr(server, "_config", SimpleNamespace(data_root=str(tmp_path)))
    assert {"analyze", "host_collision", "subdomain_brute", "export_signals"} <= server.mcp.tools.keys()
    assert server.active_httpx("run_one", jarm=True)["step"]["status"] == "skipped"
    assert calls == [{"favicon": False, "jarm": True}]
    assert len(server.export_signals("run_one")["paths"]) == 7
    assert server.export_report("run_one")["asset_count"] == 1
    assert "error" in server.export_report("unknown")
