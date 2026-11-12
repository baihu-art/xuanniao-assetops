"""MCP Server — 玄鸟 AssetOps 的 MCP 入口（MVP 6 工具）。

不依赖 FastMCP 也能跑 CLI；MCP 工具返回摘要，大结果持久化到 SQLite。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    FastMCP = None

from assetops.config.loader import AssetOpsConfig
from assetops.core.run_manager import RunManager
from assetops.core.scope_guard import ScopeGuard
from assetops.storage import (
    ArchiveStore, Database,
    count_assets, get_run, list_assets as query_assets,
    list_relations as query_relations, list_runs,
)


mcp = FastMCP(name="AssetOps") if FastMCP is not None else None


_config: AssetOpsConfig | None = None
_db: Database | None = None
_archive: ArchiveStore | None = None
_scope: ScopeGuard | None = None
_run_manager: RunManager | None = None


def _atomic_write(path: Path, content: str) -> None:
    fd, temp_path = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except BaseException:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def _ensure() -> RunManager:
    global _config, _db, _archive, _scope, _run_manager
    if _run_manager is not None:
        return _run_manager

    _config = AssetOpsConfig.from_env()
    try:
        from dotenv import load_dotenv
        env_path = Path.cwd() / ".env"
        if env_path.is_file():
            load_dotenv(env_path)
            _config = AssetOpsConfig.from_env()
    except ImportError:
        pass

    _db = Database(Path(_config.data_root) / "assetops.db")
    _archive = ArchiveStore(Path(_config.data_root) / "archives")
    _scope = ScopeGuard.from_file(_config.scope_file)
    _run_manager = RunManager(_db, _archive, _scope, _config)
    return _run_manager


if mcp is not None:
    @mcp.tool()
    def create_run(target: str, providers: list[str] | None = None,
                   rate_limit: int = 5, timeout: int = 30, budget_max: int = 10000) -> dict:
        mgr = _ensure()
        run = mgr.create_run(target, providers=providers,
                             rate_limit=rate_limit, timeout=timeout, budget_max=budget_max)
        return {"run_id": run.id, "name": run.name, "status": run.status,
                "target": run.target, "scope_loaded": mgr._scope.is_configured}

    @mcp.tool()
    def active_httpx(run_id: str) -> dict:
        mgr = _ensure()
        run = mgr.execute_httpx(run_id)
        step = next((s for s in run.steps if s.name == "active_httpx"), None)
        return {"run_id": run.id, "status": run.status,
                "step": step.__dict__ if step else None}

    @mcp.tool()
    def check_scope(target: str) -> dict:
        mgr = _ensure()
        ok, reason = mgr._scope.check(target)
        return {"in_scope": ok, "reason": reason, "scope_configured": mgr._scope.is_configured}

    @mcp.tool()
    def recon_domain(target: str, providers: list[str] | None = None) -> dict:
        mgr = _ensure()
        run = mgr.create_run(target, providers=providers)
        run = mgr.execute(run.id)
        high = count_assets(_db, run_id=run.id, priority="high")
        return {
            "run_id": run.id, "status": run.status,
            "total_assets": run.total_assets, "total_observations": run.total_observations,
            "high_priority_count": high,
            "db_path": str(Path(mgr._db._db_path)),
            "archive_root": str(mgr._archive.root),
            "note": "完整资产列表已入库，使用 list_assets 查询",
        }

    @mcp.tool()
    def list_assets(domain: str | None = None, priority: str | None = None,
                    port: str | None = None, source: str | None = None,
                    run_id: str | None = None, limit: int = 50, offset: int = 0) -> dict:
        _ensure()
        if limit < 1 or offset < 0:
            return {"error": "limit must be positive and offset must be non-negative"}
        limit = min(limit, 200)
        total = count_assets(_db, run_id=run_id, domain=domain, priority=priority,
                             port=port, source=source)
        assets = query_assets(_db, run_id=run_id, domain=domain, priority=priority,
                              port=port, source=source, limit=limit, offset=offset)
        return {"assets": [a.to_dict() for a in assets], "total": total,
                "limit": limit, "offset": offset, "has_more": (offset + len(assets)) < total}

    @mcp.tool()
    def list_relations(asset_id: str | None = None, relation_type: str | None = None,
                       limit: int = 200) -> dict:
        _ensure()
        if limit < 1:
            return {"error": "limit must be positive"}
        relations = query_relations(
            _db, asset_id=asset_id, relation_type=relation_type,
            limit=min(limit, 1000),
        )
        return {"relations": [relation.to_dict() for relation in relations],
                "count": len(relations)}

    @mcp.tool()
    def get_run_state(run_id: str | None = None, limit: int = 10) -> dict:
        mgr = _ensure()
        if run_id:
            run = get_run(_db, run_id)
            if run is None:
                return {"error": f"Run {run_id} not found"}
            return {"run": run.to_dict()}
        else:
            runs = list_runs(_db, limit=limit)
            return {"runs": [r.to_dict() for r in runs], "count": len(runs)}

    @mcp.tool()
    def export_report(run_id: str | None = None, format: str = "json") -> dict:
        mgr = _ensure()
        if format not in {"json", "markdown"}:
            return {"error": f"unsupported format: {format}"}
        if run_id and get_run(_db, run_id) is None:
            return {"error": f"Run {run_id} not found"}
        report_dir = Path(_config.data_root) / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        assets = query_assets(_db, run_id=run_id, limit=50000)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

        if format == "json":
            path = report_dir / f"report-{ts}.json"
            _atomic_write(path, json.dumps({
                "run_id": run_id, "generated_at": ts,
                "total_assets": len(assets), "assets": [a.to_dict() for a in assets],
            }, ensure_ascii=False, indent=2) + "\n")
        elif format == "markdown":
            path = report_dir / f"report-{ts}.md"
            lines = [
                "# 玄鸟 AssetOps 资产报告", "",
                f"- 生成时间：{ts}", f"- Run ID：{run_id or '(全部)'}",
                f"- 资产总数：{len(assets)}", "",
                "## 资产列表", "",
                "| 优先级 | Host | IP:Port | 标题 | Server | 来源 |",
                "|--------|------|---------|------|--------|------|",
            ]
            for a in sorted(assets, key=lambda x: (x.priority != "high", x.host)):
                sources = ", ".join(sorted(a.sources))
                values = [a.priority, a.host, f"{a.ip}:{a.port}", a.title, a.server, sources]
                escaped = [str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ") for value in values]
                lines.append("| " + " | ".join(escaped) + " |")
            _atomic_write(path, "\n".join(lines) + "\n")
        return {"format": format, "path": str(path),
                "asset_count": len(assets), "summary": f"报告已生成到 {path}"}


def serve() -> None:
    if FastMCP is None or mcp is None:
        print("[assetops] mcp 未安装。请先: pip install fastmcp", file=sys.stderr)
        sys.exit(1)
    mcp.run()


if __name__ == "__main__":
    serve()
