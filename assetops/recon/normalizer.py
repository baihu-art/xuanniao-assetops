"""资产归一化与去重。

把来自多个 Provider 的 Asset 列表合并为去重集合，
同一 primary_key 的 Asset 会合并 Observation 并累积 sources。
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from assetops.models.asset import Asset, Observation


# ---------------------------------------------------------------------------
# 合并去重
# ---------------------------------------------------------------------------

def merge_assets(asset_lists: list[list[Asset]]) -> list[Asset]:
    """合并多个来源的 Asset 列表，按 primary_key 去重合并。"""
    bucket: dict[str, Asset] = {}

    for source_assets in asset_lists:
        for a in source_assets:
            key = a.primary_key
            if not key:
                bucket[id(a)] = a
                continue
            if key in bucket:
                _merge_into(bucket[key], a)
            else:
                bucket[key] = a

    return list(bucket.values())


def _merge_into(target: Asset, incoming: Asset) -> None:
    for obs in incoming.observations:
        _add_observation_if_new(target, obs)
    target.sources |= incoming.sources

    if not target.title and incoming.title:
        target.title = incoming.title
    if not target.server and incoming.server:
        target.server = incoming.server
    if not target.country and incoming.country:
        target.country = incoming.country
    if not target.city and incoming.city:
        target.city = incoming.city
    if not target.asset_type or target.asset_type == "unknown":
        if incoming.asset_type != "unknown":
            target.asset_type = incoming.asset_type
    if target.priority != "high" and incoming.priority == "high":
        target.priority = "high"

    for tag in incoming.tags:
        if tag not in target.tags:
            target.tags.append(tag)

    now = datetime.now(timezone.utc).isoformat()
    target.last_seen_at = now
    for obs in target.observations:
        if obs.first_seen_at < target.first_seen_at:
            target.first_seen_at = obs.first_seen_at
        if obs.last_seen_at > target.last_seen_at:
            target.last_seen_at = obs.last_seen_at


def _add_observation_if_new(target: Asset, new_obs: Observation) -> None:
    fp = _evidence_fingerprint(new_obs.evidence)
    for existing in target.observations:
        if existing.source == new_obs.source and _evidence_fingerprint(existing.evidence) == fp:
            return
    target.observations.append(new_obs)


def _evidence_fingerprint(evidence: dict) -> str:
    try:
        canon = json.dumps(evidence, sort_keys=True, default=str)
        return hashlib.md5(canon.encode()).hexdigest()
    except Exception:
        return str(evidence)


# ---------------------------------------------------------------------------
# 优先级分类（MVP 简化版，后续可替换 5 维打分模型）
# ---------------------------------------------------------------------------

HIGH_RISK_PORTS = {"22", "21", "3389", "5432", "1433", "3306", "6379", "27017",
                   "9200", "11211", "9090", "2375", "4243", "10250", "2376",
                   "6443", "4444"}

WEB_PORTS = {"80", "443", "8080", "8443", "8000", "3000"}

ADMIN_KEYWORDS = ["admin", "管理", "dashboard", "后台", "console", "manage", "jenkins",
                  "swagger", "graphql", "api", "kubernetes", "grafana", "prometheus"]

ENV_KEYWORDS = ["dev", "test", "staging", "uat", "pre"]


def classify_priority(asset: Asset) -> str:
    title_lower = (asset.title or "").lower()
    host_lower = (asset.host or "").lower()
    port_str = asset.port or ""
    port_num = int(port_str) if port_str.isdigit() else 0

    if any(kw in title_lower for kw in ADMIN_KEYWORDS):
        return "high"
    if any(kw in host_lower for kw in ENV_KEYWORDS):
        return "high"
    if port_str in HIGH_RISK_PORTS:
        return "high"
    if port_num > 0 and port_str not in WEB_PORTS and asset.title:
        return "high"
    if port_str in {"80", "443"} and not asset.title:
        return "low"
    return "medium"


def apply_priority(assets: list[Asset]) -> None:
    for a in assets:
        if a.priority == "medium":
            a.priority = classify_priority(a)
