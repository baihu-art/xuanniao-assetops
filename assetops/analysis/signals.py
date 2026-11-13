"""当前 Run 的离线信号与报告；只导出结构化白名单，不导出原始正文。"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from assetops.storage.queries import get_run, load_run_assets

KINDS = ("assets", "httpx", "favicon", "jarm", "host_collision", "subdomain_brute", "analysis")
_FIELDS = set("handshakes_attempted handshakes_completed certificate_verified fingerprint_version truncated http baseline_different baseline_kind confidence_limited stopped response_sha256 host ip port domain title server webserver tech status status_code content_length content_hash response_hash body_hash scheme connect_ip sni confidence classification validation_state candidate differential unconfirmed wildcard wildcard_detected addresses resolved_ips baseline baseline_status baseline_hash baseline_length differences favicon_hash jarm_hash asset_id run_id rule_version category dimensions score priority reasons input_observation_ids missing_information theoretical_max rule_max exposure technical_risk data_value attack_surface uniqueness dns_status http_status verified http_verified result state limited".split())
_SENSITIVE = re.compile(r"(?i)(?:bearer\s+\S+|(?:api[_-]?key|token|secret|password|authorization)\s*[:=]\s*[^\s,;&]+)")


def _text(value: str) -> str:
    return _SENSITIVE.sub("[REDACTED]", value)[:2048]


def _clean(value):
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items() if k in _FIELDS}
    if isinstance(value, list):
        return [_clean(v) for v in value[:1000]]
    if isinstance(value, str):
        return _text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return None


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _run_dir(data_root, run_id: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", run_id):
        raise ValueError("invalid run_id")
    data_directory = Path(data_root).resolve()
    root = (data_directory / "runs").resolve()
    directory = (root / run_id).resolve()
    if not root.is_relative_to(data_directory) or not directory.is_relative_to(root):
        raise ValueError("run directory escapes data_root")
    return directory


def build_signals(db, run_id: str) -> dict[str, dict]:
    if not run_id or get_run(db, run_id) is None:
        raise ValueError("a valid run_id is required")
    run = get_run(db, run_id)
    assets = load_run_assets(db, run_id)
    records = {kind: [] for kind in KINDS}
    for asset in assets:
        observations = [o for o in asset.observations if o.run_id == run_id]
        record = {key: "" for key in ("host", "ip", "port", "domain", "title", "server", "priority")}
        record["id"] = asset.id
        for obs in sorted(observations, key=lambda o: (o.source == "analysis", o.source in {"httpx", "active_httpx", "host_collision", "subdomain_brute"}, o.last_seen_at, o.id)):
            for key in ("host", "ip", "port", "domain", "title", "server", "priority"):
                value = obs.evidence.get(key)
                if key == "server":
                    value = value or obs.evidence.get("webserver")
                if value is not None and value != "":
                    record[key] = _clean(value)
        record["sources"] = sorted({o.source for o in observations})
        record["observation_ids"] = [o.id for o in observations]
        records["assets"].append(record)
        for obs in observations:
            kind = "httpx" if obs.source == "active_httpx" else obs.source
            result = {"asset_id": asset.id, "observation_id": obs.id, "confidence": obs.confidence,
                      "evidence": _clean(obs.evidence)}
            if kind in records and kind != "assets":
                records[kind].append(result)
            for fingerprint in ("favicon", "jarm"):
                field = fingerprint + "_hash"
                if obs.evidence.get(field) and kind != fingerprint:
                    records[fingerprint].append({"asset_id": asset.id, "observation_id": obs.id,
                                                 "confidence": obs.confidence,
                                                 "evidence": {field: _clean(obs.evidence[field])}})
    output = {}
    step_names = {"httpx": "active_httpx", "analysis": "asset_analysis", "host_collision": "host_collision", "subdomain_brute": "subdomain_brute", "favicon": "active_httpx", "jarm": "active_httpx"}
    for kind in KINDS:
        step = next((s for s in reversed(run.steps) if s.name == step_names.get(kind)), None)
        status = step.status if step else ("available" if records[kind] or kind == "assets" else "not_run")
        output[kind] = {"schema_version": "1.0", "run_id": run_id, "kind": kind, "status": status,
                        "data": {"assets" if kind == "assets" else "results": records[kind]},
                        "warnings": (["步骤受限或未完整完成；已有结果已保留"] if step and (getattr(step, "limited", False) or step.status not in {"done", "completed"}) else [])}
    return output


def export_signals(db, data_root, run_id: str) -> dict:
    directory = _run_dir(data_root, run_id) / "signals"
    if not directory.resolve().is_relative_to(_run_dir(data_root, run_id)):
        raise ValueError("signals directory escapes run directory")
    signals = build_signals(db, run_id)
    paths = {}
    for kind, payload in signals.items():
        path = directory / f"{kind}.json"
        if path.is_symlink():
            raise ValueError("signal file must not be a symlink")
        atomic_write(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        paths[kind] = str(path)
    return {"run_id": run_id, "schema_version": "1.0", "paths": paths}


def export_report(db, data_root, run_id: str, format: str = "json") -> dict:
    if format not in {"json", "markdown"}:
        raise ValueError(f"unsupported format: {format}")
    signals = build_signals(db, run_id)
    assets = signals["assets"]["data"]["assets"]
    report = {"run_id": run_id, "total_assets": len(assets), "assets": assets,
              "scores": signals["analysis"]["data"]["results"],
              "fingerprints": {k: signals[k]["data"]["results"] for k in ("favicon", "jarm")},
              "candidates": {k: signals[k]["data"]["results"] for k in ("host_collision", "subdomain_brute")},
              "note": "评分理论满分100，yingzhao-v1规则最高97；未知不代表安全。相同指纹仅为关联线索，candidate/differential/unconfirmed不证明绕过。"}
    path = _run_dir(data_root, run_id) / f"report.{'md' if format == 'markdown' else 'json'}"
    if path.is_symlink():
        raise ValueError("report file must not be a symlink")
    if format == "json":
        content = json.dumps(report, ensure_ascii=False, indent=2)
    else:
        def cell(value):
            return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")
        lines = ["# 玄鸟 AssetOps 资产报告", "", f"Run ID: {run_id}", "", report["note"], "", "| 优先级 | Host | IP:Port | 标题 |", "|---|---|---|---|"]
        for a in assets:
            lines.append("| " + " | ".join(cell(v) for v in (a["priority"], a["host"], f"{a['ip']}:{a['port']}", a["title"])) + " |")
        for title, values in (("五维评分", report["scores"]), ("指纹关联线索", report["fingerprints"]), ("候选验证状态", report["candidates"])):
            lines.extend(["", f"## {title}", "", "| 结构化证据 |", "|---|"])
            lines.append("| " + cell(json.dumps(values, ensure_ascii=False)) + " |")
        content = "\n".join(lines)
    atomic_write(path, content + "\n")
    return {"run_id": run_id, "format": format, "path": str(path), "asset_count": len(assets)}
