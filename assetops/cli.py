"""CLI 入口 — 与 MCP 共用同一套核心服务。

用法：
  assetops run example.com
  assetops run example.com --providers mock
  assetops list-assets --priority high
  assetops runs
  assetops export-report --format markdown
  assetops scope-check https://example.com/admin
  assetops config
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assetops.config.loader import AssetOpsConfig
from assetops.core.run_manager import RunManager
from assetops.core.scope_guard import ScopeGuard
from assetops.storage import (
    ArchiveStore, Database,
    count_assets, get_run, list_assets, list_runs,
)


def _setup():
    try:
        from dotenv import load_dotenv
        env_path = Path.cwd() / ".env"
        if env_path.is_file():
            load_dotenv(env_path)
    except ImportError:
        pass

    config = AssetOpsConfig.from_env()
    db = Database(Path(config.data_root) / "assetops.db")
    archive = ArchiveStore(Path(config.data_root) / "archives")
    scope = ScopeGuard.from_file(config.scope_file)
    return RunManager(db, archive, scope, config), config, scope


# ---------------------------------------------------------------------------

def cmd_run(args) -> int:
    mgr, config, scope = _setup()

    if not scope.is_configured:
        print("[error] 未检测到授权范围配置 (scope.json)。默认拒绝所有目标。", file=sys.stderr)
        print("        请先基于 scope.example.json 创建 scope.json。", file=sys.stderr)
        return 1

    providers = args.providers.split(",") if args.providers else ["mock"]
    run = mgr.create_run(
        args.target,
        providers=providers,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        budget_max=args.budget_max,
    )

    print(f"[assetops] Run id={run.id} target={run.target}")
    print(f"[assetops]   providers={run.providers_enabled}  rate_limit={run.rate_limit}/s")
    print(f"[assetops]   db={Path(config.data_root) / 'assetops.db'}")
    print(f"[assetops]   scope={config.scope_file}")
    print()

    run = mgr.execute(run.id)

    print(f"\n[assetops] 完成  status={run.status}")
    print(f"[assetops]   总资产={run.total_assets}  总观测={run.total_observations}")
    for step in run.steps:
        extra = f" ({step.error})" if step.error else ""
        print(f"    - {step.name}: {step.status} — {step.summary}{extra}")

    assets = list_assets(mgr._db, priority="high", limit=20)
    if assets:
        print(f"\n[assetops] 高优先级资产 ({len(assets)}):")
        for a in assets:
            sources = ",".join(sorted(a.sources))
            print(f"    {a.host}:{a.port}  {a.title[:50]}  [{sources}]")

    return 0 if run.status == "completed" else 1


def cmd_httpx(args) -> int:
    mgr, _, scope = _setup()
    if not scope.is_configured:
        print("[error] 未检测到授权范围配置。", file=sys.stderr)
        return 1
    try:
        run = mgr.execute_httpx(args.run_id)
    except (ValueError, RuntimeError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
    step = next((s for s in run.steps if s.name == "active_httpx"), None)
    print(json.dumps({"run_id": run.id, "status": run.status,
                      "step": step.__dict__ if step else None}, ensure_ascii=False))
    return 0 if step and step.status in {"done", "skipped"} else 1


def cmd_scope_check(args) -> int:
    _, _, scope = _setup()
    ok, reason = scope.check(args.target)
    if ok:
        print(f"[scope] IN SCOPE: {reason}")
        return 0
    else:
        print(f"[scope] OUT OF SCOPE: {reason}", file=sys.stderr)
        return 1


def cmd_list_assets(args) -> int:
    mgr, _, _ = _setup()
    assets = list_assets(
        mgr._db, domain=args.domain, priority=args.priority, port=args.port,
        limit=args.limit, offset=args.offset,
    )
    total = count_assets(mgr._db)

    if args.json:
        print(json.dumps({"total": total, "offset": args.offset, "limit": args.limit,
                          "assets": [a.to_dict() for a in assets]}, ensure_ascii=False, indent=2))
    else:
        print(f"[assetops] assets: total={total} returned={len(assets)} offset={args.offset}")
        print(f"{'priority':<8} {'host':<40} {'ip:port':<18} {'sources':<15} title")
        print("-" * 105)
        for a in assets:
            sources = ",".join(sorted(a.sources))
            print(f"{a.priority:<8} {a.host[:38]:<40} {a.ip}:{a.port:<16} {sources:<15} {a.title[:60]}")
    return 0


def cmd_runs(args) -> int:
    mgr, _, _ = _setup()
    if args.run_id:
        run = get_run(mgr._db, args.run_id)
        if run is None:
            print(f"[error] Run {args.run_id} not found", file=sys.stderr)
            return 1
        print(json.dumps(run.to_dict(), ensure_ascii=False, indent=2))
    else:
        runs = list_runs(mgr._db, limit=args.limit)
        print(f"[assetops] recent {len(runs)} runs:")
        print(f"{'id':<14} {'target':<20} {'status':<12} {'assets':<8} {'obs':<8} created_at")
        print("-" * 80)
        for r in runs:
            print(f"{r.id:<14} {r.target[:18]:<20} {r.status:<12} {r.total_assets:<8} {r.total_observations:<8} {r.created_at[:19]}")
    return 0


def cmd_export_report(args) -> int:
    from datetime import datetime, timezone
    mgr, config, _ = _setup()
    report_dir = Path(config.data_root) / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    assets = list_assets(mgr._db, run_id=args.run_id, limit=50000)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    if args.format == "json":
        path = report_dir / f"report-{ts}.json"
        path.write_text(json.dumps({
            "run_id": args.run_id, "generated_at": ts,
            "total_assets": len(assets),
            "assets": [a.to_dict() for a in assets],
        }, ensure_ascii=False, indent=2), encoding="utf-8")
    elif args.format == "markdown":
        path = report_dir / f"report-{ts}.md"
        lines = [
            "# 玄鸟 AssetOps 资产报告", "",
            f"- 生成时间：{ts}", f"- Run ID：{args.run_id or '(全部)'}",
            f"- 资产总数：{len(assets)}", "",
            "## 资产列表", "",
            "| 优先级 | Host | IP:Port | 标题 | Server | 来源 |",
            "|--------|------|---------|------|--------|------|",
        ]
        for a in sorted(assets, key=lambda x: (x.priority != "high", x.host)):
            sources = ", ".join(sorted(a.sources))
            lines.append(f"| {a.priority} | {a.host} | {a.ip}:{a.port} | {a.title} | {a.server} | {sources} |")
        path.write_text("\n".join(lines), encoding="utf-8")
    else:
        print(f"[error] unsupported format: {args.format}", file=sys.stderr)
        return 1

    print(f"[assetops] report -> {path}  ({len(assets)} assets)")
    return 0


def cmd_config(args) -> int:
    _, config, scope = _setup()
    view = config.safe_view()
    view["scope_summary"] = scope.summary()
    print(json.dumps(view, ensure_ascii=False, indent=2))
    return 0


# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="assetops", description="玄鸟 AssetOps — 面向明确授权目标的 AI 资产收集智能体",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="执行一次被动测绘")
    p.add_argument("target")
    p.add_argument("--providers", default=None)
    p.add_argument("--rate-limit", type=int, default=5)
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--budget-max", type=int, default=10000)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("httpx", help="对已有 Run 执行主动 httpx 探活")
    p.add_argument("run_id")
    p.set_defaults(func=cmd_httpx)

    p = sub.add_parser("scope-check", help="检查目标是否在授权范围内")
    p.add_argument("target")
    p.set_defaults(func=cmd_scope_check)

    p = sub.add_parser("list-assets", help="查询资产列表")
    p.add_argument("--domain", default=None)
    p.add_argument("--priority", default=None)
    p.add_argument("--port", default=None)
    p.add_argument("--json", action="store_true")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--offset", type=int, default=0)
    p.set_defaults(func=cmd_list_assets)

    p = sub.add_parser("runs", help="查询 Run 状态")
    p.add_argument("--run-id", default=None)
    p.add_argument("--limit", type=int, default=10)
    p.set_defaults(func=cmd_runs)

    p = sub.add_parser("export-report", help="导出报告")
    p.add_argument("--run-id", default=None)
    p.add_argument("--format", choices=["json", "markdown"], default="json")
    p.set_defaults(func=cmd_export_report)

    p = sub.add_parser("config", help="显示当前配置（脱敏）")
    p.set_defaults(func=cmd_config)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
