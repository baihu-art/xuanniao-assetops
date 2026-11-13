"""资产查询的 Run 隔离与分页测试。"""

from pathlib import Path

from assetops.core.scope_guard import ScopeGuard, TargetScope
from assetops.models.asset import Asset, Observation, make_primary_key
from assetops.models.run import Run
from assetops.storage import Database, count_assets, insert_observation, insert_run, list_assets, upsert_asset


def make_asset(host: str, *, priority: str = "medium") -> Asset:
    asset = Asset(host=host, domain="testcorp.example", priority=priority)
    asset.primary_key = make_primary_key(asset.ip, asset.port, asset.host)
    return asset


def test_run_filter_deduplicates_observations_and_matches_count(tmp_path: Path):
    db = Database(tmp_path / "test.db")
    run_one = Run(target="testcorp.example")
    run_two = Run(target="testcorp.example")
    insert_run(db, run_one)
    insert_run(db, run_two)

    shared = make_asset("shared.testcorp.example", priority="high")
    only_one = make_asset("one.testcorp.example")
    only_two = make_asset("two.testcorp.example")
    for asset in (shared, only_one, only_two):
        upsert_asset(db, asset)

    insert_observation(db, run_one.id, Observation(run_id=run_one.id, source="mock"), shared.id)
    insert_observation(db, run_one.id, Observation(run_id=run_one.id, source="mock"), shared.id)
    insert_observation(db, run_one.id, Observation(run_id=run_one.id, source="mock"), only_one.id)
    insert_observation(db, run_two.id, Observation(run_id=run_two.id, source="mock"), shared.id)
    insert_observation(db, run_two.id, Observation(run_id=run_two.id, source="mock"), only_two.id)

    assert {a.host for a in list_assets(db, run_id=run_one.id)} == {
        "shared.testcorp.example", "one.testcorp.example",
    }
    assert count_assets(db, run_id=run_one.id) == 2
    assert count_assets(db, run_id=run_one.id, priority="high") == 1
    assert count_assets(db, run_id=run_two.id) == 2
    assert count_assets(db) == 3
    db.close()


def test_run_filter_pagination_is_stable(tmp_path: Path):
    db = Database(tmp_path / "test.db")
    run = Run(target="testcorp.example")
    insert_run(db, run)
    for index in range(3):
        asset = make_asset(f"host-{index}.testcorp.example")
        upsert_asset(db, asset)
        insert_observation(db, run.id, Observation(run_id=run.id, source="mock"), asset.id)

    first = list_assets(db, run_id=run.id, limit=2, offset=0)
    second = list_assets(db, run_id=run.id, limit=2, offset=2)
    assert len(first) == 2
    assert len(second) == 1
    assert {a.host for a in first + second} == {
        "host-0.testcorp.example", "host-1.testcorp.example", "host-2.testcorp.example",
    }
    db.close()
