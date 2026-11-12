"""资产之间的可解释关联边。"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import uuid


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_id() -> str:
    return uuid.uuid4().hex[:12]


@dataclass
class AssetRelation:
    source_asset_id: str
    target_asset_id: str
    relation_type: str
    confidence: str = "low"
    evidence: dict = field(default_factory=dict)
    id: str = field(default_factory=_make_id)
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict:
        return asdict(self)
