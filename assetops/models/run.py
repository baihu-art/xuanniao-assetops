"""Run（任务）状态模型与状态机。"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Literal


RunStatus = Literal[
    "created", "running", "paused", "completed",
    "failed", "cancelled", "recovered",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_id() -> str:
    return uuid.uuid4().hex[:12]


VALID_TRANSITIONS: dict[RunStatus, set[RunStatus]] = {
    "created":  {"running", "cancelled"},
    "running":  {"paused", "completed", "failed", "cancelled"},
    "paused":   {"running", "cancelled"},
    "failed":   {"recovered", "cancelled"},
    "recovered": {"running", "completed", "failed"},
    "completed": {"failed"},
    "cancelled": set(),
}


@dataclass
class RunStep:
    name: str
    status: Literal["pending", "running", "done", "skipped", "failed"] = "pending"
    started_at: str | None = None
    finished_at: str | None = None
    duration_seconds: float | None = None
    summary: str = ""
    error: str = ""
    active_reserved: int = 0
    active_used: int = 0
    limited: bool = False


@dataclass
class Run:
    id: str = field(default_factory=_make_id)
    name: str = ""
    target: str = ""
    status: RunStatus = "created"

    created_at: str = field(default_factory=_now_iso)
    started_at: str | None = None
    finished_at: str | None = None

    rate_limit: int = 5
    timeout: int = 30
    budget_max: int = 10000

    providers_enabled: list[str] = field(default_factory=list)
    steps: list[RunStep] = field(default_factory=list)

    total_assets: int = 0
    total_observations: int = 0
    report_path: str = ""
    archive_path: str = ""

    scope_summary: dict = field(default_factory=dict)
    notes: str = ""

    def can_transition_to(self, new_status: RunStatus) -> bool:
        return new_status in VALID_TRANSITIONS.get(self.status, set())

    def transition_to(self, new_status: RunStatus) -> None:
        if not self.can_transition_to(new_status):
            raise ValueError(
                f"Illegal Run state transition: {self.status} → {new_status}"
            )
        self.status = new_status
        if new_status == "running" and self.started_at is None:
            self.started_at = _now_iso()
        if new_status in {"completed", "failed", "cancelled", "recovered"}:
            self.finished_at = _now_iso()

    def add_step(self, step: RunStep) -> None:
        self.steps.append(step)

    def to_dict(self) -> dict:
        return asdict(self)
