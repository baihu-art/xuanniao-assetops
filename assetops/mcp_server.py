"""MCP Server — 玄鸟 AssetOps 的 MCP 入口（MVP 6 工具）。

不依赖 FastMCP 也能跑 CLI；MCP 工具返回摘要，大结果持久化到 SQLite。
"""

from __future__ import annotations

import sys
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


def _step_result(run, name: str) -> dict:
    step = next((s for s in reversed(run.steps) if s.name == name), None)
    return {"run_id": run.id, "status": run.status,
            "step": step.__dict__ if step else None}


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
    def active_httpx(run_id: str, favicon: bool = False, jarm: bool = False) -> dict:
        """主动步骤默认关闭，须显式授权和预算。普通探活需外部httpx路径；favicon/JARM为Python受控指纹采集、不含普通探活。"""
        mgr = _ensure()
        run = mgr.execute_httpx(run_id, favicon=favicon, jarm=jarm)
        step = next((s for s in run.steps if s.name == "active_httpx"), None)
        return {"run_id": run.id, "status": run.status,
                "step": step.__dict__ if step else None}

    @mcp.tool()
    def analyze(run_id: str) -> dict:
        """仅用当前Run观测进行五维评分，不联网，不证明漏洞。"""
        run = _ensure().execute_analyze(run_id)
        return _step_result(run, "asset_analysis")

    @mcp.tool()
    def host_collision(run_id: str, hosts: list[str] | None = None,
                       ips: list[str] | None = None) -> dict:
        """主动Host候选验证，默认关闭；须域名与连接IP双重授权，受持久化预算限额约束。"""
        run = _ensure().execute_host_collision(run_id, hosts=hosts, ips=ips)
        return _step_result(run, "host_collision")

    @mcp.tool()
    def subdomain_brute(run_id: str, domain: str, labels: list[str] | None = None,
                        wordlist: str | None = None, verify_http: bool = False) -> dict:
        """主动DNS枚举，默认关闭；显式提供标签或本地小字典，逐候选授权、限额；HTTP验证另需显式开启。"""
        run = _ensure().execute_subdomain_brute(run_id, domain=domain, labels=labels,
                                               wordlist=wordlist, verify_http=verify_http)
        return _step_result(run, "subdomain_brute")

    @mcp.tool()
    def export_signals(run_id: str) -> dict:
        """离线原子导出该Run的七类结构化信号；不触发探测，不导出正文或密钥。"""
        from assetops.analysis.signals import export_signals as write_signals
        mgr = _ensure()
        return write_signals(mgr._db, _config.data_root, run_id)

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
    def export_report(run_id: str, format: str = "json") -> dict:
        """离线导出单个Run报告，含五维评分、指纹和候选状态。"""
        from assetops.analysis.signals import export_report as write_report
        mgr = _ensure()
        try:
            return write_report(mgr._db, _config.data_root, run_id, format)
        except ValueError as exc:
            return {"error": str(exc)}


def serve() -> None:
    if FastMCP is None or mcp is None:
        print("[assetops] mcp 未安装。请先: pip install fastmcp", file=sys.stderr)
        sys.exit(1)
    mcp.run()


if __name__ == "__main__":
    serve()
