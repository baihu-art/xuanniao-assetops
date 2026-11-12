"""SQLite 查询接口 — 对上层暴露强类型 CRUD。"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from assetops.models.asset import Asset, Observation
from assetops.models.relation import AssetRelation
from assetops.models.run import Run, RunStep
from assetops.storage.database import Database


def insert_run(db: Database, run: Run) -> None:
    db.execute(
        """
        INSERT INTO runs (id, name, target, status, created_at, started_at, finished_at,
                          rate_limit, timeout, budget_max, providers_json, steps_json,
                          total_assets, total_obs, report_path, archive_path,
                          scope_json, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run.id, run.name, run.target, run.status,
            run.created_at, run.started_at, run.finished_at,
            run.rate_limit, run.timeout, run.budget_max,
            json.dumps(run.providers_enabled),
            json.dumps([s.__dict__ for s in run.steps]),
            run.total_assets, run.total_observations,
            run.report_path, run.archive_path,
            json.dumps(run.scope_summary),
            run.notes,
        ),
    )


def update_run(db: Database, run: Run) -> None:
    db.execute(
        """
        UPDATE runs SET status=?, started_at=?, finished_at=?,
                       providers_json=?, steps_json=?,
                       total_assets=?, total_obs=?, report_path=?, archive_path=?,
                       scope_json=?, notes=?
        WHERE id=?
        """,
        (
            run.status, run.started_at, run.finished_at,
            json.dumps(run.providers_enabled),
            json.dumps([s.__dict__ for s in run.steps]),
            run.total_assets, run.total_observations,
            run.report_path, run.archive_path,
            json.dumps(run.scope_summary),
            run.notes,
            run.id,
        ),
    )


def get_run(db: Database, run_id: str) -> Run | None:
    row = db.fetch_one("SELECT * FROM runs WHERE id = ?", (run_id,))
    if row is None:
        return None
    return Run(
        id=row["id"], name=row["name"], target=row["target"],
        status=row["status"], created_at=row["created_at"],
        started_at=row["started_at"], finished_at=row["finished_at"],
        rate_limit=row["rate_limit"], timeout=row["timeout"],
        budget_max=row["budget_max"],
        providers_enabled=json.loads(row["providers_json"]),
        steps=[RunStep(**s) for s in json.loads(row["steps_json"])],
        total_assets=row["total_assets"], total_observations=row["total_obs"],
        report_path=row["report_path"], archive_path=row["archive_path"],
        scope_summary=json.loads(row["scope_json"]),
        notes=row["notes"],
    )


def list_runs(db: Database, limit: int = 50) -> list[Run]:
    rows = db.fetch_all(
        "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,),
    )
    return [get_run(db, r["id"]) for r in rows if get_run(db, r["id"])]


def upsert_asset(db: Database, asset: Asset) -> str:
    """插入或更新 Asset，返回 DB 中真实的 asset.id。

    如果是 UPDATE 分支，DB 中已有该 primary_key 的资产，
    返回其已有的 id（而非传入 asset 对象上那个可能是新生成的 uuid）。
    调用方用返回的 id 来做后续 Observation 的外键关联。
    """
    existing = db.fetch_one("SELECT id FROM assets WHERE primary_key = ?", (asset.primary_key,))
    now = datetime.now(timezone.utc).isoformat()
    tags_json = json.dumps(asset.tags)
    sources_json = json.dumps(sorted(asset.sources))

    if existing is None:
        db.execute(
            """
            INSERT INTO assets (id, primary_key, ip, port, host, asset_type, title, server,
                                domain, country, city, priority, tags_json, sources_json,
                                first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                asset.id, asset.primary_key, asset.ip, asset.port, asset.host,
                asset.asset_type, asset.title, asset.server,
                asset.domain, asset.country, asset.city,
                asset.priority, tags_json, sources_json,
                asset.first_seen_at, asset.last_seen_at,
            ),
        )
        return asset.id

    db.execute(
        """
        UPDATE assets SET
            title        = CASE WHEN title='' THEN ? ELSE title END,
            server       = CASE WHEN server='' THEN ? ELSE server END,
            asset_type   = CASE WHEN asset_type='unknown' THEN ? ELSE asset_type END,
            country      = CASE WHEN country='' THEN ? ELSE country END,
            city         = CASE WHEN city='' THEN ? ELSE city END,
            priority     = CASE WHEN priority='medium' AND ?='high' THEN 'high' ELSE priority END,
            sources_json = ?,
            tags_json    = ?,
            last_seen_at = ?
        WHERE primary_key = ?
        """,
        (
            asset.title, asset.server, asset.asset_type,
            asset.country, asset.city, asset.priority,
            sources_json, tags_json, now, asset.primary_key,
        ),
    )
    return existing["id"]


def _asset_filter_sql(
    *,
    run_id: str | None = None,
    domain: str | None = None,
    priority: str | None = None,
    port: str | None = None,
    source: str | None = None,
) -> tuple[str, list]:
    clauses = ["1=1"]
    params: list = []
    if run_id:
        clauses.append(
            "EXISTS (SELECT 1 FROM observations o "
            "WHERE o.asset_id = assets.id AND o.run_id = ?)"
        )
        params.append(run_id)
    if domain:
        clauses.append("domain LIKE ?")
        params.append(f"%{domain}%")
    if priority:
        clauses.append("priority = ?")
        params.append(priority)
    if port:
        clauses.append("port = ?")
        params.append(port)
    if source:
        clauses.append("sources_json LIKE ?")
        params.append(f"%{source}%")
    return " AND ".join(clauses), params


def list_assets(
    db: Database,
    *,
    run_id: str | None = None,
    domain: str | None = None,
    priority: str | None = None,
    port: str | None = None,
    source: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[Asset]:
    where, params = _asset_filter_sql(
        run_id=run_id, domain=domain, priority=priority, port=port, source=source,
    )
    sql = (
        "SELECT * FROM assets WHERE " + where +
        " ORDER BY CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, "
        "last_seen_at DESC, id ASC LIMIT ? OFFSET ?"
    )
    params.extend([limit, offset])

    rows = db.fetch_all(sql, tuple(params))
    result = []
    for r in rows:
        a = Asset(
            id=r["id"], ip=r["ip"], port=r["port"], host=r["host"],
            asset_type=r["asset_type"], title=r["title"], server=r["server"],
            domain=r["domain"], country=r["country"], city=r["city"],
            primary_key=r["primary_key"], priority=r["priority"],
            tags=json.loads(r["tags_json"]),
            sources=set(json.loads(r["sources_json"])),
            first_seen_at=r["first_seen_at"], last_seen_at=r["last_seen_at"],
        )
        result.append(a)
    return result


def count_assets(
    db: Database,
    *,
    run_id: str | None = None,
    domain: str | None = None,
    priority: str | None = None,
    port: str | None = None,
    source: str | None = None,
) -> int:
    where, params = _asset_filter_sql(
        run_id=run_id, domain=domain, priority=priority, port=port, source=source,
    )
    row = db.fetch_one("SELECT COUNT(*) as c FROM assets WHERE " + where, tuple(params))
    return row["c"] if row else 0


def upsert_relation(db: Database, relation: AssetRelation) -> None:
    db.execute(
        """
        INSERT INTO asset_relations
            (id, source_asset_id, target_asset_id, relation_type,
             confidence, evidence_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_asset_id, target_asset_id, relation_type) DO UPDATE SET
            confidence=excluded.confidence,
            evidence_json=excluded.evidence_json
        """,
        (
            relation.id, relation.source_asset_id, relation.target_asset_id,
            relation.relation_type, relation.confidence,
            json.dumps(relation.evidence), relation.created_at,
        ),
    )


def list_relations(
    db: Database, *, asset_id: str | None = None,
    relation_type: str | None = None, limit: int = 200,
) -> list[AssetRelation]:
    clauses = ["1=1"]
    params: list = []
    if asset_id:
        clauses.append("(source_asset_id = ? OR target_asset_id = ?)")
        params.extend([asset_id, asset_id])
    if relation_type:
        clauses.append("relation_type = ?")
        params.append(relation_type)
    params.append(limit)
    rows = db.fetch_all(
        "SELECT * FROM asset_relations WHERE " + " AND ".join(clauses)
        + " ORDER BY created_at DESC LIMIT ?", tuple(params),
    )
    return [AssetRelation(
        id=row["id"], source_asset_id=row["source_asset_id"],
        target_asset_id=row["target_asset_id"], relation_type=row["relation_type"],
        confidence=row["confidence"], evidence=json.loads(row["evidence_json"]),
        created_at=row["created_at"],
    ) for row in rows]


def insert_observation(db: Database, run_id: str, obs: Observation, asset_id: str) -> None:
    db.execute(
        """
        INSERT INTO observations (id, run_id, asset_id, source, confidence,
                                   evidence_json, first_seen_at, last_seen_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            obs.id, run_id, asset_id, obs.source, obs.confidence,
            json.dumps(obs.evidence), obs.first_seen_at, obs.last_seen_at,
        ),
    )
