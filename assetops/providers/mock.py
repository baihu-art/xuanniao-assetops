"""Mock Provider — 离线测试用，不需要真实 API 凭据。"""

from __future__ import annotations

from assetops.core.scope_guard import ScopeGuard
from assetops.models.asset import Asset
from assetops.providers.base import BaseProvider


MOCK_POOL = [
    ("webmail.example.com", "443", "Example WebMail Login", "nginx/1.20.1", "CN"),
    ("api.example.com", "443", "", "openresty/1.19.3", "CN"),
    ("www.example.com", "443", "Example Corporate Site", "Apache/2.4.41", "CN"),
    ("www.example.com", "80", "Example Corporate Site", "Apache/2.4.41", "CN"),
    ("dev-backend.example.com", "8080", "Example Dev API Console", "gunicorn/20.1.0", "CN"),
    ("staging.example.com", "8443", "Example Staging", "nginx/1.21.6", "CN"),
    ("jenkins.example.com", "8080", "Dashboard [Jenkins]", "Jetty/9.4.35", "CN"),
    ("vpn.example.com", "443", "Example VPN Gateway", "OpenVPN/2.4.11", "CN"),
    ("ns1.example.com", "53", "", "", "CN"),
    ("db-int.example.com", "3306", "", "MySQL 5.7.33", "CN"),
    ("cache.example.com", "6379", "", "Redis 6.2.1", "CN"),
]


class MockProvider(BaseProvider):
    name = "mock"
    description = "离线 Mock Provider — 生成假资产数据用于测试"
    requires_credentials = False

    def is_configured(self) -> bool:
        return True

    def search(self, target: str) -> list[Asset]:
        assets: list[Asset] = []
        for host, port, title, server, country in MOCK_POOL:
            full_host = host.replace("example.com", target)
            try:
                self._scope.assert_in_scope(full_host)
            except PermissionError:
                continue

            asset = self._make_asset(
                ip="", port=port, host=full_host,
                title=title, server=server,
                domain=target, country=country,
                evidence={"mock_generated": True, "target": target},
                confidence="low",
            )
            assets.append(asset)
        return assets
