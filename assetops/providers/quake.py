"""Quake (360) Provider — 迁移自英招 cyberspace_collect.py::collect_quake。

API: https://quake.360.net/api/v3/search/quake_service（POST）
Query: domain:"target"
认证: X-QuakeToken（Header）
翻页: start=0,100,200,... size=100
total 在 meta.total（可能为 0 但有数据），total=0 时最多翻 10 页。
"""

from __future__ import annotations

from assetops.models.asset import Asset
from assetops.providers.base import BaseProvider, ProviderConfigError


class QuakeProvider(BaseProvider):
    name = "quake"
    description = "360 Quake 空间测绘"
    requires_credentials = True
    max_pages = 100

    def is_configured(self) -> bool:
        return bool(self._config.get_credential("quake_token"))

    def search(self, target: str) -> list[Asset]:
        if not self.is_configured():
            raise ProviderConfigError("Quake credentials missing (QUAKE_TOKEN).")

        self._assert_search_target(target)
        token = self._config.get_credential("quake_token")
        query = f'domain:"{target}"'
        headers = {"X-QuakeToken": token}
        include_fields = [
            "ip", "port", "hostname", "org",
            "service.http.title", "service.http.host",
            "location.country_cn", "location.province_cn",
        ]

        assets: list[Asset] = []
        start = 0
        page_size = 100
        total = 0
        total_unknown = False  # Quake 额度不足时 total=0 但有数据

        while start < self.max_pages * page_size:
            url = (
                f"https://quake.360.net/api/v3/search/quake_service"
                f"?start={start}&size={page_size}"
            )
            body = {"query": query, "include": include_fields}

            data, status, err = self._http.post(url, body, headers=headers)
            if data is None:
                print(f"  [Quake] start={start}: HTTP {status} — {err}")
                break

            code = data.get("code", 0)
            if code != 0:
                print(f"  [Quake] API error code={code}: {data.get('message', '')}")
                break

            if start == 0:
                total = data.get("meta", {}).get("total", 0)
                if total == 0:
                    total = data.get("total", 0)
                if total == 0 and data.get("data"):
                    total_unknown = True
                    print(f"  [Quake] note: total unavailable (possible quota limit)")
                else:
                    print(f"  [Quake] total={total}")

            results = data.get("data", []) or []
            if not results:
                break

            new_count = 0
            for item in results:
                asset = self._parse_item(item, target)
                if asset is not None:
                    assets.append(asset)
                    new_count += 1

            print(f"  [Quake] start={start}: +{new_count} assets (cumulative={len(assets)})")

            if len(results) < page_size:
                break
            if not total_unknown and total > 0 and len(assets) >= total:
                break
            if total_unknown and start >= 10 * page_size:
                print(f"  [Quake] total unknown, reached 10-page safety limit")
                break

            start += page_size

        print(f"[Quake] done: {len(assets)} assets (total={total if not total_unknown else 'unknown'})")
        return assets

    # ---------------------------------------------------------------

    def _parse_item(self, item: dict, target: str) -> Asset | None:
        service = item.get("service", {}) or {}
        http_data = service.get("http", {}) or {}
        location = item.get("location", {}) or {}

        raw_host = http_data.get("host", "") or item.get("hostname", "")
        ip = item.get("ip", "")
        port = item.get("port", "")
        title = http_data.get("title", "")
        domain = self._clean_host(raw_host)
        country = location.get("country_cn", "") or location.get("country", "") or ""
        city = location.get("province_cn", "") or location.get("province", "") or ""

        clean_host = self._clean_host(raw_host)
        if not clean_host and not ip:
            return None

        try:
            self._scope.assert_in_scope(clean_host or ip)
        except PermissionError:
            return None

        return self._make_asset(
            ip=ip,
            port=self._clean_port(port),
            host=clean_host,
            title=title,
            server="",
            domain=domain or target,
            country=country,
            city=city,
            evidence={
                "service_keys": list(service.keys()) if isinstance(service, dict) else [],
                "http_data_keys": list(http_data.keys()) if isinstance(http_data, dict) else [],
                "source_target": target,
            },
            confidence="medium",
        )
