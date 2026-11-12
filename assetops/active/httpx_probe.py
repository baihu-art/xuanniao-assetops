"""通过本机 httpx 二进制对已授权资产执行受限 HTTP 探活。"""

from __future__ import annotations

import json
import math
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from assetops.core.scope_guard import ScopeGuard


class HttpxProbeError(Exception):
    """探活执行或输出解析失败。"""


@dataclass
class HttpxProbeResult:
    target: str
    ok: bool
    status_code: int | None = None
    title: str = ""
    webserver: str = ""
    url: str = ""
    raw: dict | None = None
    error: str = ""


@dataclass
class HttpxProbeSummary:
    results: list[HttpxProbeResult]
    skipped: int = 0
    error: str = ""


_ALLOWED_FLAGS = ("-json", "-duc", "-silent", "-timeout", "-retries", "-threads")
_EVIDENCE_FIELDS = (
    "input", "status_code", "url", "title", "webserver", "server", "a", "ip",
    "asn", "cname", "tech", "favicon_hash", "jarm", "content_type", "method",
    "words", "lines", "content_length", "time",
)
_SENSITIVE_FIELDS = {"body", "response", "request", "headers", "header", "raw_response", "raw_request"}
_MAX_STRING_LENGTH = 4096
_MAX_LIST_ITEMS = 100
_MAX_EVIDENCE_BYTES = 32768


def _target_url(host: str, port: str) -> str:
    scheme = "https" if str(port) in {"443", "8443"} else "http"
    return f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"


def _read_jsonl(stdout: str, limit: int) -> list[dict]:
    rows: list[dict] = []
    for line in stdout.splitlines():
        if len(rows) >= limit:
            break
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise HttpxProbeError(f"bad JSONL output: {exc.msg}") from exc
        if not isinstance(value, dict):
            raise HttpxProbeError("bad JSONL output: expected object")
        rows.append(value)
    return rows


def _safe_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:_MAX_STRING_LENGTH] if value else ""


def _safe_number(value: Any) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value < 0:
        return None
    return value


def _safe_value(value: Any) -> Any:
    if isinstance(value, str):
        return value[:_MAX_STRING_LENGTH]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _safe_number(value)
    if isinstance(value, list):
        values = []
        for item in value[:_MAX_LIST_ITEMS]:
            safe = _safe_string(item) if isinstance(item, str) else _safe_value(item)
            if safe is not None and not isinstance(safe, (dict, list)):
                values.append(safe)
        return values
    return None


def _normalize_httpx_evidence(row: dict) -> dict:
    evidence: dict[str, Any] = {}
    for field in _EVIDENCE_FIELDS:
        if field in _SENSITIVE_FIELDS or field not in row:
            continue
        value = row[field]
        if field in {"status_code", "words", "lines", "content_length"}:
            value = _safe_number(value)
        elif field in {"a", "ip", "tech"}:
            value = _safe_value(value)
            if field == "tech" and not isinstance(value, list):
                value = None
        else:
            value = _safe_string(value)
        if value is not None:
            evidence[field] = value

    serialized = json.dumps(evidence, ensure_ascii=False, separators=(",", ":"))
    if len(serialized.encode("utf-8")) <= _MAX_EVIDENCE_BYTES:
        return evidence
    trimmed: dict[str, Any] = {}
    for field in ("input", "url", "status_code", "title", "webserver", "server"):
        if field in evidence:
            trimmed[field] = evidence[field]
    return trimmed


def _format_target(host: str, port: str) -> str:
    host = host.strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}" if port else host


def probe_targets(
    targets: Sequence[str],
    *,
    scope_guard: ScopeGuard,
    executable: str,
    timeout: int = 30,
    max_targets: int = 100,
    output_limit: int = 100,
    extra_args: Sequence[str] = (),
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> HttpxProbeSummary:
    """执行一次有界 httpx；调用方必须显式传入 enabled 之外的执行意图。"""
    if max_targets < 1 or output_limit < 1:
        raise ValueError("limits must be positive")
    executable_path = Path(executable)
    if not executable_path.is_absolute():
        raise HttpxProbeError("httpx executable must be an absolute path")
    allowed = set(_ALLOWED_FLAGS)
    for arg in extra_args:
        if not arg or arg.split("=", 1)[0] not in allowed:
            raise HttpxProbeError(f"unsupported httpx argument: {arg}")
    checked: list[str] = []
    skipped = 0
    for target in targets:
        if len(checked) >= max_targets:
            skipped += 1
            continue
        try:
            scope_guard.assert_in_scope(target)
        except PermissionError:
            skipped += 1
            continue
        checked.append(target)
    if not checked:
        return HttpxProbeSummary([], skipped=skipped)

    command = [str(executable_path), "-json", "-duc", "-silent", *extra_args, *checked]
    try:
        completed = run(
            command, shell=False, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return HttpxProbeSummary([], skipped=skipped, error=f"timeout: {exc}")
    except OSError as exc:
        return HttpxProbeSummary([], skipped=skipped, error=f"execution failed: {exc}")
    if completed.returncode != 0:
        detail = (completed.stderr or "").strip()[:500]
        return HttpxProbeSummary([], skipped=skipped, error=f"non-zero exit {completed.returncode}: {detail}")
    try:
        rows = _read_jsonl(completed.stdout or "", output_limit)
    except HttpxProbeError as exc:
        return HttpxProbeSummary([], skipped=skipped, error=str(exc))

    results: list[HttpxProbeResult] = []
    for row in rows:
        evidence = _normalize_httpx_evidence(row)
        target = str(evidence.get("input") or evidence.get("url") or "")
        status_code = evidence.get("status_code")
        results.append(HttpxProbeResult(
            target=target,
            ok=True,
            status_code=status_code if isinstance(status_code, int) else None,
            title=str(evidence.get("title") or ""),
            webserver=str(evidence.get("webserver") or evidence.get("server") or ""),
            url=str(evidence.get("url") or target),
            raw=evidence,
        ))
    return HttpxProbeSummary(results, skipped=skipped)
