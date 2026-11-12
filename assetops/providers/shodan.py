"""Shodan Provider — 迁移自英招 cyberspace_collect.py::collect_shodan + collect_shodan_dns。

API: https://api.shodan.io/shodan/host/search
Query: hostname:target
认证: key（URL 参数）
翻页: page=1,2,... 每页固定 100 条（API 不支持 size 参数）

免费 Key 遇到 credit/plan 错误时自动降级到 DNS domain 模式：
  https://api.shodan.io/dns/domain/target → 只拿子域名列表
"""

from __future__ import annotations

import urllib.parse

from assetops.models.asset import Asset
from assetops.providers.base import BaseProvider, ProviderConfigError


class ShodanProvider(BaseProvider):
    name = "shodan"
    description = "Shodan 空间测绘"
    requires_credentials = True
    max_pages = 100

    def is_configured(self) -> bool:
        return bool(self._config.get_credential("shodan_key"))

    def search(self, target: str) -> list[Asset]:
        if not self.is_configured():
            raise ProviderConfigError("Shodan credentials missing (SHODAN_KEY).")

        self._assert_search_target(target)
        api_key = self._config.get_credential("shodan_key")
        query = f"hostname:{target}"

        assets: list[Asset] = []
        page = 1
        page_size = 100  # Shodan API 每页固定 100 条
        total = 0

        while page <= self.max_pages:
            url = (
                f"https://api.shodan.io/shodan/host/search"
                f"?key={api_key}"
                f"&query={urllib.parse.quote(query)}"
                f"&page={page}"
            )

            data, status, err = self._http.get(url)

            # --- 错误处理 ---
            if data is None:
                print(f"  [Shodan] page {page}: HTTP {status} — {err}")
                break

            if "error" in data:
                error_msg = data["error"]
                print(f"  [Shodan] API error: {error_msg}")
                # 免费 Key 降级 DNS 模式
                err_lower = (error_msg or "").lower()
                if "credit" in err_lower or "plan" in err_lower:
                    print(f"  [Shodan] switching to dns/domain mode...")
                    return self._search_dns_direct(api_key, target)
                break

            # --- 正常翻页 ---
            if page == 1:
                total = data.get("total", 0)
                print(f"  [Shodan] total={total}")

            results = data.get("matches", []) or []
            if not results:
                break

            new_count = 0
            for item in results:
                asset = self._parse_match(item, target)
                if asset is not None:
                    assets.append(asset)
                    new_count += 1

            print(f"  [Shodan] page {page}: +{new_count} assets (cumulative={len(assets)})")

            # Shodan 不支持 size，每页固定 100；少于 100 就是最后一页
            if len(results) < page_size:
                break
            if total > 0 and len(assets) >= total:
                break

            page += 1

        print(f"[Shodan] done: {len(assets)} assets from {page} pages (total={total})")
        return assets

    # ---------------------------------------------------------------
    # 免费 Key 降级 — DNS domain 模式
    # ---------------------------------------------------------------

    def _search_dns_direct(self, api_key: str, target: str) -> list[Asset]:
        url = f"https://api.shodan.io/dns/domain/{target}?key={api_key}"
        data, status, err = self._http.get(url)

        if data is None:
            print(f"  [Shodan DNS] HTTP {status} — {err}")
            return []
        if "error" in data:
            print(f"  [Shodan DNS] API error: {data['error']}")
            return []

        subdomains = data.get("subdomains", []) or []
        assets: list[Asset] = []
        for item in subdomains:
            full_host = f"{item}.{target}" if item else target
            try:
                self._scope.assert_in_scope(full_host)
            except PermissionError:
                continue
            asset = self._make_asset(
                ip="", port="", host=full_host,
                domain=target,
                evidence={"dns_only": True, "source_target": target},
                confidence="low",
            )
            asset.sources.add("shodan-dns")
            assets.append(asset)

        print(f"[Shodan DNS] done: {len(assets)} subdomains")
        return assets

    # ---------------------------------------------------------------

    def _parse_match(self, item: dict, target: str) -> Asset | None:
        hostnames = item.get("hostnames", []) or []
        raw_host = hostnames[0] if hostnames else ""
        ip = item.get("ip_str", "")
        port = item.get("port", "")

        http_info = item.get("http", {}) or {}
        title = http_info.get("title", "") if isinstance(http_info, dict) else ""
        server = http_info.get("server", "") if isinstance(http_info, dict) else ""
        country = item.get("country_name", "")
        city = item.get("city", "")

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
            server=server,
            domain=clean_host or target,
            country=country,
            city=city,
            evidence={
                "hostnames": hostnames[:10],
                "product": item.get("product", ""),
                "cpe": item.get("cpe", ""),
                "source_target": target,
            },
            confidence="medium",
        )
