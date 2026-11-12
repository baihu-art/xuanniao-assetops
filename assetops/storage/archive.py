"""原始响应归档 — 用文件系统存 Provider 原始 HTTP 响应。

每次归档一个独立 JSON 文件，命名含时间戳。原子写入保证完整性。
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ArchiveStore:
    def __init__(self, root: str | Path):
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    @property
    def root(self) -> Path:
        return self._root

    def save(self, provider: str, data: Any, *, suffix: str = "json") -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_provider = provider.replace("/", "_").replace("\\", "_")
        filename = f"{safe_provider}-{ts}.{suffix}"
        target = self._root / filename
        self._atomic_write(target, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        return target

    def save_raw(self, provider: str, content: bytes | str, *, suffix: str = "bin") -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_provider = provider.replace("/", "_").replace("\\", "_")
        filename = f"{safe_provider}-{ts}.{suffix}"
        target = self._root / filename
        if isinstance(content, str):
            self._atomic_write(target, content)
        else:
            self._atomic_write_bytes(target, content)
        return target

    def list(self, provider: str | None = None, limit: int = 100) -> list[Path]:
        files = sorted(self._root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
        if provider:
            files = [f for f in files if f.name.startswith(provider + "-")]
        return files[:limit]

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        fd, tmp_path = tempfile.mkstemp(
            dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, str(path))
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    @staticmethod
    def _atomic_write_bytes(path: Path, content: bytes) -> None:
        fd, tmp_path = tempfile.mkstemp(
            dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, str(path))
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
