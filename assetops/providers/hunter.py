"""Hunter (奇安信) Provider — 迁移自英招 cyberspace_collect.py::collect_hunter。

API: https://hunter.qianxin.com/openApi/search
Query: domain.suffix="target"（URL safe base64 编码）
认证: api-key（URL 参数）
翻页: page=1,2,... page_size=100，is_web=3（全部类型）
"""

from __future__ import annotations

from assetops.models.asset import Asset
from assetops.providers.base import BaseProvider, ProviderConfigError
from assetops.core.http import url_safe_b64


class HunterProvider(BaseProvider):
    name = "hunter"
    description = "奇安信 Hunter 空间测绘"
    requires_credentials = True
    max_pages = 100

    def is_configured(self) -> bool:
        return bool(self._config.get_credential("hunter_key"))

    def search(self, target: str) -> list[Asset]:
        if not self.is_configured():
            raise ProviderConfigError("Hunter credentials missing (HUNTER_KEY).")

        self._assert_search_target(target)
        api_key = self._config.get_credential("hunter_key")
        query = f'domain.suffix="{target}"'
        search_b64 = url_safe_b64(query)

        assets: list[Asset] = []
        page = 1
        page_size = 100
        total = 0

        while page <= self.max_pages:
            url = (
                f"https://hunter.qianxin.com/openApi/search"
                f"?api-key={api_key}"
                f"&search={search_b64}"
                f"&page={page}&page_size={page_size}&is_web=3"
            )

            data, status, err = self._http.get(url)
            if data is None:
                print(f"  [Hunter] page {page}: HTTP {status} — {err}")
                break

            code = data.get("code")
            if code != 200:
                print(f"  [Hunter] API error code={code}: {data.get('message', '')}")
                break

            d = data.get("data", {}) or {}
            if page == 1:
                total = d.get("total", 0)
                print(f"  [Hunter] total={total}")

            results = d.get("arr", []) or []
            if not results:
                break

            new_count = 0
            for item in results:
                asset = self._parse_item(item, target)
                if asset is not None:
                    assets.append(asset)
                    new_count += 1

            print(f"  [Hunter] page {page}: +{new_count} assets (cumulative={len(assets)})")

            if len(results) < page_size:
                break
            if total > 0 and len(assets) >= total:
                break

            page += 1

        print(f"[Hunter] done: {len(assets)} assets from {page} pages (total={total})")
        return assets

    # ---------------------------------------------------------------

    def _parse_item(self, item: dict, target: str) -> Asset | None:
        raw_url = item.get("url", "")
        ip = item.get("ip", "")
        port = item.get("port", "")
        title = item.get("web_title", "")
        domain = self._clean_host(item.get("domain", ""))

        # component 取第一个 dict 的 name 做 server
        server = ""
        component = item.get("component")
        if isinstance(component, list) and component:
            first = component[0]
            if isinstance(first, dict):
                server = first.get("name", "")

        country = item.get("country", "") or item.get("country_name", "") or "China"
        city = item.get("city", "") or item.get("province", "") or ""

        clean_host = self._clean_host(raw_url)
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
            server=server,
            domain=domain or target,
            country=country,
            city=city,
            evidence={
                "raw_url": raw_url[:300] if raw_url else "",
                "component": component if isinstance(component, list) else [],
                "source_target": target,
            },
            confidence="medium",
        )
