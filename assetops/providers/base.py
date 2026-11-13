"""Provider 抽象基类 — 所有空间测绘数据源必须实现此接口。

Provider 内部必须自行调用 scope_guard 做安全校验，
每个 HTTP 请求通过 self._http（HttpClient，已带速率控制 + 429 退避）发送，
凭据通过 self._config.get_credential(name) 获取（统一脱敏管理）。
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from assetops.core.scope_guard import ScopeGuard
from assetops.core.http import HttpClient, normalize_country_code
from assetops.models.asset import Asset, Observation, make_primary_key

if TYPE_CHECKING:
    from assetops.config.loader import AssetOpsConfig


class ProviderError(Exception):
    pass


class ProviderConfigError(ProviderError):
    pass


class ProviderRateLimitError(ProviderError):
    pass


class BaseProvider(ABC):
    """空间测绘 Provider 抽象基类。"""

    name: str = "base"
    description: str = ""
    requires_credentials: bool = True
    max_pages: int = 100   # 有界翻页，防止死循环

    def __init__(
        self,
        *,
        scope_guard: ScopeGuard,
        config: "AssetOpsConfig | None" = None,
        timeout: int | None = None,
        rate_limit: int | None = None,
    ):
        from assetops.config.loader import AssetOpsConfig
        self._scope = scope_guard
        self._config = config or AssetOpsConfig()

        timeout = timeout or self._config.timeout
        rate_limit = rate_limit or self._config.rate_limit

        self._http = HttpClient(
            timeout=timeout,
            rate_limit=rate_limit,
            insecure_tls=self._config.insecure_tls,
            max_pages=self.max_pages,
        )

    def _assert_search_target(self, target: str) -> None:
        """在发出任何 Provider 请求前确认查询目标已获授权。"""
        self._scope.assert_in_scope(target)

    # ------------------------------------------------------------------
    # 子类必实现
    # ------------------------------------------------------------------

    @abstractmethod
    def is_configured(self) -> bool:
        ...

    @abstractmethod
    def search(self, target: str) -> list[Asset]:
        """执行搜索，返回归一化后的 Asset 列表。

        子类内部必须：
        1. 每条原始结果的 host 先调用 self._scope.assert_in_scope(host)
        2. 用 self._make_asset(...) 构造 Asset
        3. 用 normalize_country_code(...) 归一化国家
        4. 翻页终止条件必须包含 "页数 >= self.max_pages" 这个安全边界
        """
        ...

    # ------------------------------------------------------------------
    # 基类工具方法（供子类复用）
    # ------------------------------------------------------------------

    def _make_asset(
        self,
        *,
        ip: str = "", port: str = "", host: str = "",
        title: str = "", server: str = "",
        domain: str = "", country: str = "", city: str = "",
        evidence: dict | None = None, confidence: str = "medium",
    ) -> Asset:
        host = self._clean_host(host)
        port = self._clean_port(port)
        country = normalize_country_code(country) if country else ""
        pk = make_primary_key(ip, port, host)

        asset = Asset(
            ip=ip, port=port, host=host,
            title=title, server=server,
            domain=domain or host,
            country=country, city=city,
            primary_key=pk,
        )
        asset.sources.add(self.name)
        obs = Observation(
            source=self.name, confidence=confidence,
            evidence={"host": host, "ip": ip, "port": port, "title": title,
                      "webserver": server, **(evidence or {})},
        )
        asset.observations.append(obs)
        return asset

    # ------------------------------------------------------------------
    # 静态工具
    # ------------------------------------------------------------------

    @staticmethod
    def _clean_host(raw: str) -> str:
        if not raw:
            return ""
        host = raw.strip()
        if host.startswith(("http://", "https://")):
            parsed = urlparse(host)
            return (parsed.hostname or "").lower()
        if host.startswith("["):
            bracket_end = host.find("]")
            if bracket_end != -1:
                return host[1:bracket_end].lower()
            return host.lower()
        host = host.split("/", 1)[0]
        if host.count(":") == 1:
            host = host.split(":", 1)[0]
        return host.lower()

    @staticmethod
    def _clean_port(raw: str) -> str:
        if not raw:
            return ""
        port = str(raw).strip()
        if ":" in port:
            port = port.split(":")[0]
        if port and not port.isdigit():
            return ""
        return port
