"""SQLite 数据库管理 — 连接、建表、基础操作。

用 WAL 模式 + RLock 保证线程安全。用 Python sqlite3 原生
with connection: 上下文管理器自动处理事务 BEGIN/COMMIT/ROLLBACK。
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Iterator


TABLES_DDL = """
CREATE TABLE IF NOT EXISTS runs (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL DEFAULT '',
    target          TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'created',
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    finished_at     TEXT,
    rate_limit      INTEGER NOT NULL DEFAULT 5,
    timeout         INTEGER NOT NULL DEFAULT 30,
    budget_max      INTEGER NOT NULL DEFAULT 10000,
    providers_json  TEXT NOT NULL DEFAULT '[]',
    steps_json      TEXT NOT NULL DEFAULT '[]',
    total_assets    INTEGER NOT NULL DEFAULT 0,
    total_obs       INTEGER NOT NULL DEFAULT 0,
    report_path     TEXT NOT NULL DEFAULT '',
    archive_path    TEXT NOT NULL DEFAULT '',
    scope_json      TEXT NOT NULL DEFAULT '{}',
    notes           TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS assets (
    id              TEXT PRIMARY KEY,
    primary_key     TEXT NOT NULL UNIQUE,
    ip              TEXT NOT NULL DEFAULT '',
    port            TEXT NOT NULL DEFAULT '',
    host            TEXT NOT NULL DEFAULT '',
    asset_type      TEXT NOT NULL DEFAULT 'unknown',
    title           TEXT NOT NULL DEFAULT '',
    server          TEXT NOT NULL DEFAULT '',
    domain          TEXT NOT NULL DEFAULT '',
    country         TEXT NOT NULL DEFAULT '',
    city            TEXT NOT NULL DEFAULT '',
    priority        TEXT NOT NULL DEFAULT 'medium',
    tags_json       TEXT NOT NULL DEFAULT '[]',
    sources_json    TEXT NOT NULL DEFAULT '[]',
    first_seen_at   TEXT NOT NULL,
    last_seen_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
    id              TEXT PRIMARY KEY,
    run_id          TEXT NOT NULL,
    asset_id        TEXT NOT NULL,
    source          TEXT NOT NULL,
    confidence      TEXT NOT NULL DEFAULT 'medium',
    evidence_json   TEXT NOT NULL DEFAULT '{}',
    first_seen_at   TEXT NOT NULL,
    last_seen_at     TEXT NOT NULL,
    FOREIGN KEY (run_id)     REFERENCES runs(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id)   REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS asset_relations (
    id              TEXT PRIMARY KEY,
    source_asset_id TEXT NOT NULL,
    target_asset_id TEXT NOT NULL,
    relation_type   TEXT NOT NULL,
    confidence      TEXT NOT NULL DEFAULT 'low',
    evidence_json   TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    UNIQUE(source_asset_id, target_asset_id, relation_type),
    FOREIGN KEY (source_asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (target_asset_id) REFERENCES assets(id) ON DELETE CASCADE
);
"""

INDEXES_DDL = """
CREATE INDEX IF NOT EXISTS idx_assets_ip_port   ON assets(ip, port);
CREATE INDEX IF NOT EXISTS idx_assets_host      ON assets(host);
CREATE INDEX IF NOT EXISTS idx_assets_domain    ON assets(domain);
CREATE INDEX IF NOT EXISTS idx_assets_priority   ON assets(priority);
CREATE INDEX IF NOT EXISTS idx_obs_run           ON observations(run_id);
CREATE INDEX IF NOT EXISTS idx_obs_asset         ON observations(asset_id);
CREATE INDEX IF NOT EXISTS idx_obs_source        ON observations(source);
CREATE INDEX IF NOT EXISTS idx_rel_source        ON asset_relations(source_asset_id);
CREATE INDEX IF NOT EXISTS idx_rel_target        ON asset_relations(target_asset_id);
CREATE INDEX IF NOT EXISTS idx_rel_type          ON asset_relations(relation_type);
"""


class Database:
    """SQLite 封装。线程安全（RLock），用 with connection: 自动事务。"""

    def __init__(self, db_path: str | Path):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._init()

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                str(self._db_path),
                check_same_thread=False,
                timeout=30.0,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def _init(self) -> None:
        conn = self._connect()
        with self._lock:
            with conn:
                conn.executescript(TABLES_DDL)
                conn.executescript(INDEXES_DDL)

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        conn = self._connect()
        with self._lock:
            with conn:
                return conn.execute(sql, params)

    def executemany(self, sql: str, param_seq) -> sqlite3.Cursor:
        conn = self._connect()
        with self._lock:
            with conn:
                return conn.executemany(sql, param_seq)

    def fetch_all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        conn = self._connect()
        with self._lock:
            with conn:
                return conn.execute(sql, params).fetchall()

    def fetch_one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        conn = self._connect()
        with self._lock:
            with conn:
                return conn.execute(sql, params).fetchone()
