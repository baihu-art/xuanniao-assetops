"""MVP 端到端集成测试 — 用 Mock Provider 跑通完整闭环。"""

import tempfile
from pathlib import Path

from assetops.core.run_manager import RunManager
from assetops.core.scope_guard import ScopeGuard, TargetScope, ScopeRules
from assetops.providers.base import ProviderError
from assetops.storage import ArchiveStore, Database, count_assets, list_assets


def test_mock_end_to_end():
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "test.db")
        archive = ArchiveStore(Path(tmp) / "archives")
        scope = ScopeGuard(
            targets=[TargetScope(name="testcorp", domains=["*.testcorp.example"])],
            rules=ScopeRules(),
        )
        mgr = RunManager(db, archive, scope)

        # 创建
        run = mgr.create_run("testcorp.example", providers=["mock"])
        assert run.status == "created"
        assert scope.is_configured

        # 执行
        run = mgr.execute(run.id)
        assert run.status == "completed"
        assert run.total_assets > 0
        assert run.total_observations > 0

        # 查询
        assets = list_assets(db, limit=50)
        assert len(assets) == run.total_assets

        total = count_assets(db)
        assert total == run.total_assets

        # 归档存在
        assert len(list(archive.root.iterdir())) > 0

        db.close()


def test_provider_failure_is_not_reported_as_success():
    class FailingProvider:
        name = "failing"

        def __init__(self, **kwargs):
            pass

        def is_configured(self):
            return True

        def search(self, target):
            raise ProviderError("offline provider failure")

    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "test.db")
        archive = ArchiveStore(Path(tmp) / "archives")
        scope = ScopeGuard(
            targets=[TargetScope(name="testcorp", domains=["*.testcorp.example"])],
            rules=ScopeRules(),
        )
        mgr = RunManager(db, archive, scope)
        mgr.PROVIDERS["failing"] = FailingProvider

        run = mgr.create_run("testcorp.example", providers=["failing"])
        result = mgr.execute(run.id)

        assert result.status == "failed"
        assert result.steps[0].status == "failed"
        assert result.steps[0].summary == ""
        assert "offline provider failure" in result.steps[0].error
        db.close()
