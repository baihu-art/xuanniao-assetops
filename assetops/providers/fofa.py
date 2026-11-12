"""FOFA Provider — 迁移自英招 cyberspace_collect.py::collect_fofa。

API: https://fofa.info/api/v1/search/all
Query: domain="target"
认证: key（URL 参数，必填）；email 为可选兼容参数，配置后才附带
翻页: page=1,2,... size=100
"""

from __future__ import annotations

import urllib.parse

from assetops.models.asset import Asset
from assetops.providers.base import BaseProvider, ProviderConfigError
from assetops.core.http import b64


class FofaProvider(BaseProvider):
    name = "fofa"
    description = "FOFA 空间测绘引擎 (fofa.info)"
    requires_credentials = True
    max_pages = 100

    def is_configured(self) -> bool:
        return bool(self._config.get_credential("fofa_key"))

    def search(self, target: str) -> list[Asset]:
        if not self.is_configured():
            raise ProviderConfigError(
                "FOFA credential missing (FOFA_KEY). "
                "Set it in .env or environment variables; FOFA_EMAIL is optional."
            )

        self._assert_search_target(target)
        email = self._config.get_credential("fofa_email")
        key = self._config.get_credential("fofa_key")
        query = f'domain="{target}"'
        qbase64 = b64(query)

        # key-only 认证；email 仅在显式配置时附带，保持对旧账号体系的兼容。
        auth_param = f"key={urllib.parse.quote(key)}"
        if email:
            auth_param = f"email={urllib.parse.quote(email)}&" + auth_param

        assets: list[Asset] = []
        page = 1
        page_size = 100
        total = 0

        while page <= self.max_pages:
            url = (
                f"https://fofa.info/api/v1/search/all"
                f"?{auth_param}"
                f"&qbase64={urllib.parse.quote(qbase64)}"
                f"&page={page}&size={page_size}"
                f"&fields=host,ip,port,title,server,banner,country,city,domain"
            )

            data, status, err = self._http.get(url)
            if data is None:
                print(f"  [FOFA] page {page}: HTTP {status} — {err}")
                break

            if data.get("error") and data.get("errmsg"):
                print(f"  [FOFA] API error: {data['errmsg']}")
                break

            if page == 1:
                total = data.get("size", 0)
                print(f"  [FOFA] total={total}")

            results = data.get("results", [])
            if not results:
                break

            new_count = 0
            for item in results:
                asset = self._parse_item(item, target)
                if asset is not None:
                    assets.append(asset)
                    new_count += 1

            print(f"  [FOFA] page {page}: +{new_count} assets (cumulative={len(assets)})")

            if len(results) < page_size:
                break
            if total > 0 and len(assets) >= total:
                break

            page += 1

        print(f"[FOFA] done: {len(assets)} assets from {page} pages (total={total})")
        return assets

    # ---------------------------------------------------------------

    def _parse_item(self, item, target: str) -> Asset | None:
        # FOFA 同时返回 list 和 dict 两种 item 格式
        if isinstance(item, list):
            # fields=host,ip,port,title,server,banner,country,city,domain
            host = item[0] if len(item) > 0 else ""
            ip = item[1] if len(item) > 1 else ""
            port = item[2] if len(item) > 2 else ""
            title = item[3] if len(item) > 3 else ""
            server = item[4] if len(item) > 4 else ""
            banner = item[5] if len(item) > 5 else ""
            country = item[6] if len(item) > 6 else ""
            city = item[7] if len(item) > 7 else ""
            domain = item[8] if len(item) > 8 else ""
            # server 为空时从 banner 中提取 Server header
            if not server and banner:
                for line in banner.split("\n"):
                    if line.lower().startswith("server:"):
                        server = line.split(":", 1)[1].strip()
                        break
        elif isinstance(item, dict):
            host = item.get("host", "")
            ip = item.get("ip", "")
            port = item.get("port", "")
            title = item.get("title", "")
            server = item.get("server", "")
            banner = item.get("banner", "")
            country = item.get("country", "")
            city = item.get("city", "")
            domain = item.get("domain", "")
        else:
            return None

        clean_host = self._clean_host(host)
        if not clean_host and not ip:
            return None

        # 安全校验 — 必须在 scope 内
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
            domain=self._clean_host(domain),
            country=country,
            city=city,
            evidence={
                "raw_host": host,
                "raw_banner": banner[:500] if banner else "",
                "source_target": target,
            },
            confidence="medium",
        )
