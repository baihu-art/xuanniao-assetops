from assetops.config.loader import AssetOpsConfig
from assetops.core.run_manager import RunManager
from assetops.core.scope_guard import ScopeGuard
from assetops.storage import Database, ArchiveStore
from assetops.storage.queries import load_run_assets


def manager(tmp_path, **config):
    db = Database(tmp_path / "runs.db")
    scope = ScopeGuard.from_dict({"targets": [{"domains": ["*.example.com"], "ips": ["192.0.2.1"]}]})
    mgr = RunManager(db, ArchiveStore(tmp_path / "archive"), scope, AssetOpsConfig(**config))
    run = mgr.create_run("example.com", providers=["mock"])
    mgr.execute(run.id)
    return db, mgr, run.id


def test_analysis_is_offline_and_idempotent(tmp_path):
    db, mgr, run_id = manager(tmp_path)
    try:
        first = mgr.execute_analyze(run_id)
        assert first.steps[-1].status == "done", first.steps[-1].error
        total = first.total_observations
        second = mgr.execute_analyze(run_id)
        assert second.total_observations == total
        assert all(any(o.source == "analysis" for o in a.observations) for a in load_run_assets(db, run_id))
    finally:
        db.close()


def test_enumeration_disabled_without_network(tmp_path):
    db, mgr, run_id = manager(tmp_path)
    try:
        assert mgr.execute_host_collision(run_id).steps[-1].status == "skipped"
        assert mgr.execute_subdomain_brute(run_id, domain="example.com", labels=["www"]).steps[-1].status == "skipped"
        assert db.fetch_one("SELECT count(*) AS n FROM active_budgets")["n"] == 0
    finally:
        db.close()


def test_favicon_uses_controlled_transport_and_preserves_evidence(tmp_path, monkeypatch):
    db, mgr, run_id = manager(tmp_path, httpx_enabled=True)
    from assetops.active.transport import ControlledTransport
    def fake(self, host, *, port=None, scheme="https"):
        self.consume()
        return {"status_code": 200, "body": b"test icon", "truncated": False}
    monkeypatch.setattr(ControlledTransport, "request_favicon", fake, raising=False)
    try:
        result = mgr.execute_httpx(run_id, favicon=True)
        assert result.steps[-1].status == "done", result.steps[-1].error
        assert result.steps[-1].active_used > 0
        observations = [o for a in load_run_assets(db, run_id) for o in a.observations if o.source == "favicon"]
        assert observations and all("favicon_hash" in o.evidence for o in observations)
        assert all("body" not in o.evidence for o in observations)
    finally:
        db.close()


def test_jarm_pipeline_keeps_hash_and_handshake_budget(tmp_path, monkeypatch):
    db, mgr, run_id = manager(tmp_path, httpx_enabled=True, httpx_max_targets=1)
    import assetops.active.jarm as module
    def fake(target, **kwargs):
        for _ in range(10):
            kwargs["consume"]()
        return {"status": "done", "jarm_hash": "a" * 62, "certificate_verified": False}
    monkeypatch.setattr(module, "collect_jarm", fake)
    try:
        result = mgr.execute_httpx(run_id, jarm=True)
        assert result.steps[-1].status == "done", result.steps[-1].error
        assert result.steps[-1].active_used >= 10
        assert result.steps[-1].active_used % 10 == 0
        assert any(o.source == "jarm" and o.evidence["jarm_hash"] == "a" * 62
                   for a in load_run_assets(db, run_id) for o in a.observations)
    finally:
        db.close()


def test_subdomain_partial_results_and_budget(tmp_path, monkeypatch):
    db, mgr, run_id = manager(tmp_path, subdomain_brute_enabled=True, active_max_requests=2)
    import assetops.active.subdomain_brute as module
    def fake(scope, root_domain, **kwargs):
        kwargs["consume"]()
        kwargs["consume"]()
        return {"results": [{"host": "www.example.com", "addresses": ["192.0.2.1"], "classification": "candidate"}],
                "summary": {"dns_found": 1}, "errors": [{"error": "active step budget exhausted"}], "limited": True}
    monkeypatch.setattr(module, "run_subdomain_brute", fake)
    try:
        result = mgr.execute_subdomain_brute(run_id, domain="example.com", labels=["www"])
        assert result.steps[-1].status == "failed"
        assert result.steps[-1].limited
        assert result.steps[-1].active_reserved == 2
        assert any(o.source == "subdomain_brute" for a in load_run_assets(db, run_id) for o in a.observations)
    finally:
        db.close()
