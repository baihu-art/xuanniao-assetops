"""资产实体与观测记录模型。

Asset 是归一化后的资产实体（一个 primary_key 唯一对应一个 Asset），
Observation 是某次从某个数据源/工具看到这个 Asset 的观测记录
（包含来源、证据、置信度、发现时间）。两者分离后支持证据累积。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Literal


AssetType = Literal["host", "web_service", "non_web_service", "unknown"]
Confidence = Literal["low", "medium", "high"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_id() -> str:
    return uuid.uuid4().hex[:12]


@dataclass
class Observation:
    """单次观测 —— 从某个来源/工具看到某个资产的事实记录。"""
    id: str = field(default_factory=_make_id)
    run_id: str = ""
    source: str = ""                      # fofa / quake / hunter / shodan / httpx / ffuf ...
    confidence: Confidence = "medium"
    evidence: dict = field(default_factory=dict)
    first_seen_at: str = field(default_factory=_now_iso)
    last_seen_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Asset:
    """归一化后的资产实体。"""
    id: str = field(default_factory=_make_id)

    ip: str = ""
    port: str = ""
    host: str = ""

    asset_type: AssetType = "unknown"
    title: str = ""
    server: str = ""
    domain: str = ""
    country: str = ""
    city: str = ""

    primary_key: str = ""                  # 归一化主键: ip:port > host:port > ip > host
    priority: str = "medium"
    tags: list[str] = field(default_factory=list)

    first_seen_at: str = field(default_factory=_now_iso)
    last_seen_at: str = field(default_factory=_now_iso)

    observations: list[Observation] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)

    def to_dict(self, include_observations: bool = False) -> dict:
        d = {
            "id": self.id,
            "ip": self.ip,
            "port": self.port,
            "host": self.host,
            "asset_type": self.asset_type,
            "title": self.title,
            "server": self.server,
            "domain": self.domain,
            "country": self.country,
            "city": self.city,
            "primary_key": self.primary_key,
            "priority": self.priority,
            "tags": self.tags,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "sources": sorted(self.sources),
        }
        if include_observations:
            d["observations"] = [o.to_dict() for o in self.observations]
        return d

    def add_observation(self, obs: Observation) -> None:
        self.observations.append(obs)
        self.sources.add(obs.source)
        if obs.first_seen_at < self.first_seen_at:
            self.first_seen_at = obs.first_seen_at
        if obs.last_seen_at > self.last_seen_at:
            self.last_seen_at = obs.last_seen_at


def make_primary_key(ip: str, port: str, host: str) -> str:
    """按 ip:port > host:port > ip > host 的优先级生成归一化主键。"""
    ip = (ip or "").strip()
    port = (port or "").strip()
    host = (host or "").strip().lower()

    if ip and port:
        return f"{ip}:{port}"
    if host and port:
        return f"{host}:{port}"
    if ip:
        return ip
    if host:
        return host
    return ""
