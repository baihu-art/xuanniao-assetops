"""Run 管理器 — 任务生命周期与流程编排。

职责：
- 创建 Run（写入 DB + 记录初始状态）
- 状态机驱动：created → running → completed/failed/cancelled
- 编排 Provider 执行流程
- 跟踪执行预算、汇总入库
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import ipaddress

from assetops.active.httpx_probe import probe_targets

from assetops.config.loader import AssetOpsConfig
from assetops.core.scope_guard import ScopeGuard
from assetops.models.asset import Asset, Observation
from assetops.models.run import Run, RunStep
from assetops.providers.base import BaseProvider, ProviderError
from assetops.providers.mock import MockProvider
from assetops.providers.fofa import FofaProvider
from assetops.providers.quake import QuakeProvider
from assetops.providers.hunter import HunterProvider
from assetops.providers.shodan import ShodanProvider
from assetops.providers.passive import PassiveDnsProvider, CtProvider, WhoisProvider, AsnProvider
from assetops.recon.normalizer import merge_assets, apply_priority
from assetops.recon.relations import derive_relations
from assetops.storage import (
    ArchiveStore, Database,
    get_run, insert_observation, insert_run, upsert_asset, update_run,
    upsert_relation,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunManager:
    PROVIDERS: dict[str, type[BaseProvider]] = {
        "mock": MockProvider,
        "fofa": FofaProvider,
        "quake": QuakeProvider,
        "hunter": HunterProvider,
        "shodan": ShodanProvider,
        "passive_dns": PassiveDnsProvider,
        "ct": CtProvider,
        "whois": WhoisProvider,
        "asn": AsnProvider,
    }

    def __init__(
        self, db: Database, archive: ArchiveStore,
        scope_guard: ScopeGuard, config: AssetOpsConfig | None = None,
    ):
        self._db = db
        self._archive = archive
        self._scope = scope_guard
        self._config = config or AssetOpsConfig()

    # ----------------------------------------------------------
    # Run 创建
    # ----------------------------------------------------------

    def create_run(
        self, target: str, *,
        name: str | None = None,
        providers: list[str] | None = None,
        rate_limit: int = 5, timeout: int = 30, budget_max: int = 10000,
    ) -> Run:
        if not self._scope.is_configured:
            raise PermissionError(
                "Cannot create Run: no scope configured. Create scope.json first."
            )

        run = Run(
            name=name or f"assetops-{target}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            target=target,
            rate_limit=rate_limit, timeout=timeout, budget_max=budget_max,
            providers_enabled=providers or ["mock"],
            scope_summary=self._scope.summary(),
        )
        insert_run(self._db, run)
        return run

    # ----------------------------------------------------------
    # 执行（MVP 被动测绘闭环）
    # ----------------------------------------------------------

    def execute(self, run_id: str) -> Run:
        run = get_run(self._db, run_id)
        if run is None:
            raise ValueError(f"Run not found: {run_id}")
        if run.status not in ("created", "paused", "recovered"):
            raise RuntimeError(f"Run {run_id} is not executable (status={run.status})")

        run.transition_to("running")
        update_run(self._db, run)

        try:
            assets_from_all: list[list[Asset]] = []
            budget_used = 0

            for provider_name in run.providers_enabled:
                step = RunStep(name=f"recon_{provider_name}", status="running",
                               started_at=_now_iso())
                run.add_step(step)
                update_run(self._db, run)

                provider = self._resolve_provider(provider_name, run)
                provider_assets = self._run_provider(provider, run, step)
                remaining = max(run.budget_max - budget_used, 0)
                if len(provider_assets) > remaining:
                    provider_assets = provider_assets[:remaining]
                    if step.status == "running":
                        step.summary = f"budget limited to {len(provider_assets)} assets"
                budget_used += len(provider_assets)
                assets_from_all.append(provider_assets)

                step.finished_at = _now_iso()
                if step.status == "running":
                    step.status = "done"
                    step.summary = f"fetched {len(provider_assets)} assets"
                update_run(self._db, run)

            # 归一化与去重
            step_norm = RunStep(name="normalize_dedup", status="running", started_at=_now_iso())
            run.add_step(step_norm)
            update_run(self._db, run)

            merged = merge_assets(assets_from_all)
            apply_priority(merged)

            step_norm.finished_at = _now_iso()
            step_norm.status = "done"
            step_norm.summary = f"merged {sum(len(l) for l in assets_from_all)} raw → {len(merged)} unique assets"
            update_run(self._db, run)

            # 入库
            step_db = RunStep(name="persist", status="running", started_at=_now_iso())
            run.add_step(step_db)
            update_run(self._db, run)

            obs_count = 0
            persisted_assets: list[Asset] = []
            for asset in merged:
                asset_db_id = upsert_asset(self._db, asset)
                asset.id = asset_db_id
                persisted_assets.append(asset)
                for obs in asset.observations:
                    insert_observation(self._db, run.id, obs, asset_db_id)
                    obs_count += 1

            for relation in derive_relations(persisted_assets):
                upsert_relation(self._db, relation)

            run.total_assets = len(merged)
            run.total_observations = obs_count
            step_db.finished_at = _now_iso()
            step_db.status = "done"
            step_db.summary = f"persisted {len(merged)} assets, {obs_count} observations"
            update_run(self._db, run)

            provider_failures = [
                step for step in run.steps
                if step.name.startswith("recon_") and step.status == "failed"
            ]
            if provider_failures:
                details = "; ".join(
                    f"{step.name}: {step.error or step.summary}" for step in provider_failures
                )
                run.notes = f"{run.notes}\n[provider failures] {details}".strip()
                run.transition_to("failed")
            else:
                run.transition_to("completed")
            update_run(self._db, run)
            return run

        except Exception as exc:
            run.transition_to("failed")
            run.notes = f"{run.notes}\n[error] {type(exc).__name__}: {exc}"
            update_run(self._db, run)
            raise

    def execute_httpx(self, run_id: str) -> Run:
        """对已有 Run 的资产执行独立主动探活；默认不由 execute 调用。"""
        run = get_run(self._db, run_id)
        if run is None:
            raise ValueError(f"Run not found: {run_id}")
        if run.status not in {"completed", "failed"}:
            raise RuntimeError(f"Run {run_id} must be completed or failed (status={run.status})")

        step = RunStep(name="active_httpx", status="running", started_at=_now_iso())
        run.add_step(step)
        update_run(self._db, run)
        try:
            from assetops.storage.queries import list_assets
            assets = list_assets(self._db, run_id=run.id, limit=run.budget_max)
            targets = [self._asset_probe_target(a) for a in assets if a.host]
            if not self._config.httpx_enabled:
                step.status = "skipped"
                step.summary = "httpx disabled by configuration"
                return self._finish_active_step(run, step)
            if not self._config.httpx_path:
                step.status = "skipped"
                step.summary = "httpx path not configured"
                return self._finish_active_step(run, step)

            summary = probe_targets(
                targets, scope_guard=self._scope, executable=self._config.httpx_path,
                timeout=run.timeout, max_targets=self._config.httpx_max_targets,
                output_limit=self._config.httpx_output_limit,
            )
            if summary.error:
                step.status = "failed"
                step.error = summary.error
                return self._finish_active_step(run, step)
            by_target = {
                self._probe_result_key(self._asset_probe_target(a)): a
                for a in assets
            }
            inserted = 0
            for result in summary.results:
                asset = by_target.get(self._probe_result_key(result.url or result.target))
                if asset is None:
                    continue
                obs = Observation(
                    run_id=run.id, source="httpx", confidence="high",
                    evidence=result.raw or {"url": result.url, "status_code": result.status_code},
                )
                asset.sources.add("httpx")
                if result.title and not asset.title:
                    asset.title = result.title
                if result.webserver and not asset.server:
                    asset.server = result.webserver
                if asset.asset_type == "unknown":
                    asset.asset_type = "web_service"
                asset.id = upsert_asset(self._db, asset)
                insert_observation(self._db, run.id, obs, asset.id)
                inserted += 1
            run.total_observations += inserted
            step.status = "done"
            step.summary = f"probed {len(summary.results)} responses, appended {inserted} observations"
            return self._finish_active_step(run, step)
        except Exception as exc:
            step.status = "failed"
            step.error = f"{type(exc).__name__}: {exc}"
            return self._finish_active_step(run, step)

    @staticmethod
    def _asset_probe_target(asset: Asset) -> str:
        host = asset.host or asset.ip
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"{host}:{asset.port}" if asset.port else host

    @staticmethod
    def _probe_result_key(value: str) -> tuple[str, str]:
        parsed = urlparse(value if "://" in value else f"http://{value}")
        host = (parsed.hostname or "").lower()
        if not host:
            return "", ""
        if parsed.port is not None:
            port = str(parsed.port)
        else:
            port = "443" if parsed.scheme == "https" else "80"
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            pass
        return host, port

    def _finish_active_step(self, run: Run, step: RunStep) -> Run:
        step.finished_at = _now_iso()
        if step.status == "failed" and run.status == "completed":
            run.notes = f"{run.notes}\n[active_httpx failure] {step.error}".strip()
            run.transition_to("failed")
        update_run(self._db, run)
        return run

    # ----------------------------------------------------------
    # 内部方法
    # ----------------------------------------------------------

    def _resolve_provider(self, name: str, run: Run) -> BaseProvider:
        if name not in self.PROVIDERS:
            raise ProviderError(
                f"Unknown provider '{name}'. Available: {list(self.PROVIDERS.keys())}"
            )
        return self.PROVIDERS[name](
            scope_guard=self._scope,
            config=self._config,
            timeout=run.timeout,
            rate_limit=run.rate_limit,
        )

    def _run_provider(self, provider: BaseProvider, run: Run, step: RunStep) -> list[Asset]:
        if not provider.is_configured():
            step.status = "skipped"
            step.summary = "provider not configured (credentials missing)"
            return []

        try:
            raw_assets = provider.search(run.target)
            self._archive.save(
                provider=provider.name,
                data={
                    "run_id": run.id, "target": run.target,
                    "count": len(raw_assets),
                    "assets": [a.to_dict() for a in raw_assets],
                },
            )
            return raw_assets
        except ProviderError as exc:
            step.status = "failed"
            step.error = f"{type(exc).__name__}: {exc}"
            return []
