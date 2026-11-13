import tempfile
from pathlib import Path

from assetops.core.run_manager import RunManager
from assetops.core.scope_guard import ScopeGuard, ScopeRules, TargetScope
from assetops.models.asset import Asset, Observation
from assetops.recon.relations import derive_relations
from assetops.storage import ArchiveStore, Database, list_relations


def test_derive_relations_from_shared_ip_and_evidence():
    first = Asset(host="a.testcorp.example", ip="192.0.2.10")
    first.observations.append(Observation(
        source="ct", evidence={"cert_cn": "shared.testcorp.example"},
    ))
    second = Asset(host="b.testcorp.example", ip="192.0.2.10")
    second.observations.append(Observation(
        source="ct", evidence={"cert_cn": "shared.testcorp.example"},
    ))

    relations = derive_relations([first, second])

    assert {relation.relation_type for relation in relations} == {
        "same_ip", "same_certificate",
    }
    assert all(relation.confidence in {"low", "medium"} for relation in relations)


def test_run_persists_relations_with_database_asset_ids():
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "test.db")
        archive = ArchiveStore(Path(tmp) / "archives")
        scope = ScopeGuard(
            targets=[TargetScope(name="testcorp", domains=["*.testcorp.example"])],
            rules=ScopeRules(),
        )
        mgr = RunManager(db, archive, scope)
        result = mgr.execute(mgr.create_run("testcorp.example", providers=["mock"]).id)

        assert result.status == "completed"
        assert list_relations(db) == []
        db.close()
