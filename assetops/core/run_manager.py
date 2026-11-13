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
import sqlite3
from contextlib import contextmanager
from functools import wraps

from assetops.storage.queries import load_run_assets, reserve_active_budget


def _exclusive_run(method):
    @wraps(method)
    def wrapped(self, run_id, *args, **kwargs):
        try:
            self._db.execute("INSERT INTO active_run_locks(run_id) VALUES (?)", (run_id,))
        except sqlite3.IntegrityError as exc:
            raise RuntimeError("Run not found or another operation is active; stale locks require operator review") from exc
        try:
            return method(self, run_id, *args, **kwargs)
        finally:
            self._db.execute("DELETE FROM active_run_locks WHERE run_id=?", (run_id,))
    return wrapped

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

    @_exclusive_run
    def execute_httpx(self, run_id: str, *, favicon: bool = False, jarm: bool = False) -> Run:
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
            assets = load_run_assets(self._db, run.id)
            for asset in assets:
                inputs = [o.evidence for o in asset.observations if o.source != "analysis"]
                for field in ("host", "ip", "port"):
                    values = [row[field] for row in inputs if row.get(field)]
                    setattr(asset, field, str(values[-1]) if values else "")
            targets = [self._asset_probe_target(a) for a in assets if a.host]
            if not self._config.httpx_enabled:
                step.status = "skipped"
                step.summary = "httpx disabled by configuration"
                return self._finish_active_step(run, step)
            if favicon or jarm:
                return self._execute_fingerprints(run, step, assets, favicon=favicon, jarm=jarm)
            if not self._config.httpx_path:
                step.status = "skipped"
                step.summary = "httpx path not configured"
                return self._finish_active_step(run, step)

            targets = [target for target in targets if self._scope.check(target, resolve_dns=False)[0]]
            budget_row = self._db.fetch_one("SELECT used FROM active_budgets WHERE run_id=?", (run.id,))
            remaining = max(run.budget_max - (budget_row["used"] if budget_row else 0), 0)
            limit = min(remaining, self._config.active_max_requests, self._config.httpx_max_targets)
            step.limited = len(targets) > limit
            targets = targets[:limit]
            if not targets:
                step.status = "skipped"
                step.summary = "no authorized targets or active budget exhausted"
                return self._finish_active_step(run, step)
            self._consume_active(run, step, len(targets))
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
            self._refresh_relations(run.id)
            return self._finish_active_step(run, step)
        except Exception as exc:
            step.status = "failed"
            step.error = f"{type(exc).__name__}: {exc}"
            return self._finish_active_step(run, step)

    def _execute_fingerprints(self, run: Run, step: RunStep, assets: list[Asset], *, favicon: bool, jarm: bool) -> Run:
        from assetops.active.fingerprints import collect_favicon
        transport = self._active_transport(run, step)
        errors, inserted = [], 0
        step.limited = len(assets) > self._config.httpx_max_targets
        for asset in assets[:self._config.httpx_max_targets]:
            host = asset.host
            if not host or not self._scope.check_domain(host)[0]:
                continue
            port = int(asset.port or 443)
            scheme = "https" if port in {443, 8443} else "http"
            target = f"{scheme}://{host}:{port}"
            collectors = []
            if favicon:
                collectors.append(("favicon", lambda: collect_favicon(target, scope_guard=self._scope,
                    transport=transport, max_bytes=min(self._config.active_max_response_bytes, 262144))))
            if jarm:
                from assetops.active.jarm import collect_jarm
                collectors.append(("jarm", lambda: collect_jarm(f"https://{host}:{port}", scope_guard=self._scope,
                    consume=lambda: self._consume_active(run, step),
                    timeout=self._config.active_timeout, rate_limit=self._config.active_rate_limit)))
            for source, collect in collectors:
                try:
                    evidence = collect()
                    if evidence.get("error"):
                        errors.append(str(evidence["error"]))
                    evidence = {"host": host, "port": port, **evidence}
                    insert_observation(self._db, run.id, Observation(run_id=run.id, source=source,
                        confidence="medium", evidence=evidence), asset.id)
                    run.total_observations += 1
                    inserted += 1
                    if evidence.get("status") in {"stopped", "unsupported", "failed"}:
                        errors.append(f"{source}: {evidence.get('status')}")
                        if evidence.get("status") == "stopped":
                            raise RuntimeError("active step stopped after HTTP 429/503")
                except Exception as exc:
                    errors.append(f"{type(exc).__name__}: {exc}")
                    step.status = "failed"
                    step.error = "; ".join(errors)[:2000]
                    step.summary = f"preserved {inserted} fingerprint observations"
                    self._refresh_relations(run.id)
                    return self._finish_active_step(run, step)
        step.status = "failed" if errors else "done"
        step.error = "; ".join(errors)[:2000]
        step.summary = f"collected {inserted} fingerprint observations"
        self._refresh_relations(run.id)
        return self._finish_active_step(run, step)

    def _active_transport(self, run: Run, step: RunStep):
        from assetops.active.transport import ControlledTransport
        return ControlledTransport(
            self._scope, consume=lambda: self._consume_active(run, step),
            rate_limit=self._config.active_rate_limit, timeout=self._config.active_timeout,
            max_response_bytes=self._config.active_max_response_bytes,
            max_requests=self._config.active_max_requests,
        )

    @contextmanager
    def _module_step(self, run_id: str, name: str, enabled: bool):
        run = get_run(self._db, run_id)
        if run is None:
            raise ValueError(f"Run not found: {run_id}")
        if run.status not in {"completed", "failed"}:
            raise RuntimeError("Run must be completed or failed")
        step = RunStep(name=name, status="running", started_at=_now_iso())
        run.add_step(step)
        update_run(self._db, run)
        try:
            if not enabled:
                step.status = "skipped"
                step.summary = f"{name} disabled by configuration"
            yield run, step
        except Exception as exc:
            step.status = "failed"
            step.error = f"{type(exc).__name__}: {exc}"
        finally:
            self._finish_active_step(run, step)

    def _store_module_results(self, run: Run, step: RunStep, source: str, summary: dict) -> None:
        from assetops.models.asset import make_primary_key
        inserted = 0
        for row in summary["results"]:
            if row.get("classification", "").endswith("baseline"):
                continue
            host = row.get("host", "")
            ip = row.get("connect_ip") or next(iter(row.get("addresses", [])), "")
            port = str(row.get("port", ""))
            asset = Asset(host=host, ip=ip, port=port, domain=run.target,
                          primary_key=make_primary_key(ip, port, host), sources={source})
            if not asset.primary_key:
                continue
            asset.id = upsert_asset(self._db, asset)
            insert_observation(self._db, run.id, Observation(run_id=run.id, source=source,
                               confidence="low", evidence=row), asset.id)
            inserted += 1
        run.total_observations += inserted
        from assetops.storage.queries import count_assets
        run.total_assets = count_assets(self._db, run_id=run.id)
        step.limited = bool(summary.get("limited"))
        step.status = "failed" if summary.get("errors") else "done"
        step.error = "; ".join(str(e.get("error", "")) for e in summary.get("errors", []))[:2000]
        step.summary = f"{summary['summary']}; observations={inserted}; limited={step.limited}"
        self._refresh_relations(run.id)

    @_exclusive_run
    def execute_host_collision(self, run_id: str, *, hosts=None, ips=None) -> Run:
        from assetops.active.host_collision import run_host_collision
        with self._module_step(run_id, "host_collision", self._config.host_collision_enabled) as (run, step):
            if step.status != "skipped":
                assets = load_run_assets(self._db, run_id)
                known_hosts = {a.host for a in assets if a.host}
                known_ips = {a.ip for a in assets if a.ip}
                for asset in assets:
                    for obs in asset.observations:
                        if obs.evidence.get("host"):
                            known_hosts.add(obs.evidence["host"])
                selected_hosts = known_hosts if hosts is None else set(hosts)
                selected_ips = known_ips if ips is None else set(ips)
                if not selected_hosts <= known_hosts or not selected_ips <= known_ips:
                    raise ValueError("collision candidates must be a subset of current Run assets")
                summary = run_host_collision(self._scope, sorted(selected_ips), sorted(selected_hosts),
                    transport=self._active_transport(run, step), max_candidates=self._config.active_max_requests)
                self._store_module_results(run, step, "host_collision", summary)
        return get_run(self._db, run_id)

    @_exclusive_run
    def execute_subdomain_brute(self, run_id: str, *, domain: str, labels=None, wordlist=None, verify_http=False) -> Run:
        from assetops.active.subdomain_brute import run_subdomain_brute
        with self._module_step(run_id, "subdomain_brute", self._config.subdomain_brute_enabled) as (run, step):
            if step.status != "skipped":
                summary = run_subdomain_brute(self._scope, domain, labels=labels, wordlist_path=wordlist,
                    verify_http=verify_http, transport=self._active_transport(run, step),
                    consume=lambda: self._consume_active(run, step),
                    max_candidates=self._config.active_max_requests,
                    max_requests=self._config.active_max_requests, rate_limit=self._config.active_rate_limit)
                self._store_module_results(run, step, "subdomain_brute", summary)
        return get_run(self._db, run_id)

    def _consume_active(self, run: Run, step: RunStep, amount: int = 1) -> None:
        from assetops.active.transport import BudgetExceeded
        if step.active_reserved + amount > self._config.active_max_requests:
            step.limited = True
            raise BudgetExceeded("active step budget exhausted")
        try:
            reserve_active_budget(self._db, run.id, amount)
        except RuntimeError as exc:
            step.limited = True
            raise BudgetExceeded(str(exc)) from exc
        step.active_reserved += amount
        step.active_used += amount
        update_run(self._db, run)

    def _refresh_relations(self, run_id: str) -> None:
        assets = load_run_assets(self._db, run_id)
        for asset in assets:
            asset.ip = ""
        for relation in derive_relations(assets):
            upsert_relation(self._db, relation)

    @_exclusive_run
    def execute_analyze(self, run_id: str) -> Run:
        from assetops.analysis.scoring import score_asset
        run = get_run(self._db, run_id)
        if run is None:
            raise ValueError(f"Run not found: {run_id}")
        if run.status not in {"completed", "failed"}:
            raise RuntimeError("Run must be completed or failed")
        step = RunStep(name="asset_analysis", status="running", started_at=_now_iso())
        run.add_step(step)
        update_run(self._db, run)
        try:
            inserted = 0
            for asset in load_run_assets(self._db, run_id):
                evidence = score_asset(asset, run_id)
                if any(o.source == "analysis" and o.evidence == evidence for o in asset.observations):
                    continue
                obs = Observation(run_id=run_id, source="analysis", confidence="low", evidence=evidence)
                insert_observation(self._db, run_id, obs, asset.id)
                self._db.execute("UPDATE assets SET priority=? WHERE id=?", (evidence["priority"], asset.id))
                inserted += 1
            run.total_observations += inserted
            step.status = "done"
            step.summary = f"scored {inserted} assets (yingzhao-v1; theoretical 100, rule ceiling 97)"
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
            run.notes = f"{run.notes}\n[{step.name} failure] {step.error}".strip()
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
