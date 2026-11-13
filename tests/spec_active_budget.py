import pytest

from assetops.models.run import Run, RunStep
from assetops.storage import Database
from assetops.storage.queries import insert_run, get_run, reserve_active_budget, update_run


def test_reservations_persist_and_are_shared_between_connections(tmp_path):
    path = tmp_path / "budget.db"
    db = Database(path)
    other = Database(path)
    try:
        run = Run(budget_max=3)
        insert_run(db, run)
        reserve_active_budget(db, run.id, 2)
        reserve_active_budget(other, run.id, 1)
        with pytest.raises(RuntimeError, match="exhausted"):
            reserve_active_budget(db, run.id, 1)
        assert db.fetch_one("SELECT used FROM active_budgets WHERE run_id=?", (run.id,))["used"] == 3
        run.steps.append(RunStep(name="probe", active_reserved=3, active_used=3, limited=True))
        update_run(db, run)
        assert get_run(other, run.id).steps[0].active_reserved == 3
    finally:
        other.close()
        db.close()


def test_legacy_step_defaults_and_run_lock(tmp_path):
    db = Database(tmp_path / "lock.db")
    other = Database(tmp_path / "lock.db")
    try:
        run = Run()
        insert_run(db, run)
        db.execute("UPDATE runs SET steps_json=? WHERE id=?", ('[{"name":"old"}]', run.id))
        assert get_run(db, run.id).steps[0].active_used == 0
        db.execute("INSERT INTO active_run_locks(run_id) VALUES (?)", (run.id,))
        import sqlite3
        with pytest.raises(sqlite3.IntegrityError):
            other.execute("INSERT INTO active_run_locks(run_id) VALUES (?)", (run.id,))
    finally:
        other.close()
        db.close()
