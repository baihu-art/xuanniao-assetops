"""离线可测的被动 JSON 数据源；endpoint 默认留空，不自动跟进关联资产。"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlencode

from assetops.models.asset import Asset
from assetops.providers.base import BaseProvider, ProviderConfigError, ProviderError


def _domain(value) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip().lower().rstrip(".")
    if len(value) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in value.split(".")
    ):
        return ""
    return value


def _allowed(provider: BaseProvider, value: str) -> bool:
    return bool(value) and provider._scope.check(value, resolve_dns=False)[0]


def _request(provider: BaseProvider, target: str, params: dict):
    provider._scope.assert_in_scope(target, resolve_dns=False)
    if not provider.is_configured():
        raise ProviderConfigError(f"{provider.name} endpoint or credentials missing")
    endpoint = getattr(provider._config, f"{provider.name}_endpoint")
    key = provider._config.get_credential(f"{provider.name}_key")
    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    separator = "&" if "?" in endpoint else "?"
    data, status, error = provider._http.get(endpoint + separator + urlencode(params), headers=headers)
    if error or status != 200 or data is None:
        raise ProviderError(f"{provider.name} HTTP response failed (status={status})")
    if isinstance(data, dict) and (
        data.get("error") or data.get("ErrorMessage") or data.get("success") is False
        or data.get("status") in ("error", "fail", "failed")
    ):
        raise ProviderError(f"{provider.name} API error")
    return data


class PassiveDnsProvider(BaseProvider):
    """DNS-over-HTTPS JSON: Status / Answer[{name, type, TTL, data}]。"""

    name = "passive_dns"
    description = "被动 DNS JSON 记录"
    requires_credentials = False
    max_pages = 1
    # RFC 8482 后部分公共 DoH（如 AliDNS）拒绝 ANY，此时按固定类型降级查询。
    _FALLBACK_TYPES = ("A", "AAAA", "NS", "CNAME", "MX")

    def is_configured(self) -> bool:
        return self._config.has_provider_credentials(self.name)

    def _query(self, target: str, record_type: str) -> list:
        data = _request(self, target, {"name": target, "type": record_type})
        if not isinstance(data, dict) or data.get("Status") != 0:
            raise ProviderError("passive_dns invalid response or DNS error")
        rows = data.get("Answer", [])
        if not isinstance(rows, list):
            raise ProviderError("passive_dns invalid Answer")
        return rows

    def _assets_from_rows(self, target: str, rows: list) -> list[Asset]:
        assets = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            owner = _domain(row.get("name"))
            if not _allowed(self, owner):
                continue
            record_type = row.get("type")
            value = row.get("data")
            evidence = {"record_name": owner, "record_type": record_type,
                        "record_data": value, "ttl": row.get("TTL"), "source_target": target}
            if record_type in (1, 28):
                try:
                    addr = ipaddress.ip_address(value)
                except (ValueError, TypeError):
                    continue
                if addr.version != (4 if record_type == 1 else 6):
                    continue
                ip = str(addr)
                # 域名授权不能隐式授予解析 IP 的授权，IP 仅保留为证据。
                assets.append(self._make_asset(
                    host=owner, ip=ip if _allowed(self, ip) else "", evidence=evidence,
                    confidence="low",
                ))
            elif record_type in (5, 2, 12):
                name = _domain(value)
                if _allowed(self, name):
                    assets.append(self._make_asset(host=name, evidence=evidence, confidence="low"))
            elif record_type == 15:
                # MX 数据形如 "10 mail.example.com."，只取交换器域名。
                exchange = _domain(str(value).split()[-1] if value else "")
                if _allowed(self, exchange):
                    assets.append(self._make_asset(host=exchange, evidence=evidence, confidence="low"))
        return assets

    def search(self, target: str) -> list[Asset]:
        rows = self._query(target, "ANY")
        assets = self._assets_from_rows(target, rows)
        if assets:
            return assets
        # ANY 被拒绝（RFC 8482 HINFO）或没有可用记录时，按固定记录类型降级。
        for record_type in self._FALLBACK_TYPES:
            assets.extend(self._assets_from_rows(target, self._query(target, record_type)))
        return assets


class CtProvider(BaseProvider):
    """crt.sh JSON 列表，name_value 可包含多行 SAN 和通配符。"""

    name = "ct"
    description = "证书透明度域名发现"
    requires_credentials = False
    max_pages = 1

    def is_configured(self) -> bool:
        return self._config.has_provider_credentials(self.name)

    def search(self, target: str) -> list[Asset]:
        data = _request(self, target, {"q": target, "output": "json"})
        if not isinstance(data, list):
            raise ProviderError("ct invalid response")
        assets = []
        for row in data:
            if not isinstance(row, dict) or not isinstance(row.get("name_value"), str):
                continue
            names = set(row["name_value"].splitlines())
            for raw in sorted(names):
                wildcard = raw.startswith("*.")
                name = _domain(raw[2:] if wildcard else raw)
                if not _allowed(self, name):
                    continue
                assets.append(self._make_asset(host=name, confidence="low", evidence={
                    "certificate_id": row.get("id"), "issuer_name": row.get("issuer_name"),
                    "serial_number": row.get("serial_number"), "not_before": row.get("not_before"),
                    "not_after": row.get("not_after"), "wildcard": wildcard,
                    "certificate_name": raw, "source_target": target,
                }))
        return assets


class WhoisProvider(BaseProvider):
    """JSON Whois API: WhoisRecord{domainName, registrarName, createdDate, expiresDate}。"""

    name = "whois"
    description = "域名 Whois 元数据"
    max_pages = 1

    def is_configured(self) -> bool:
        return self._config.has_provider_credentials(self.name)

    def search(self, target: str) -> list[Asset]:
        data = _request(self, target, {"domainName": target, "outputFormat": "JSON"})
        row = data.get("WhoisRecord") if isinstance(data, dict) else None
        if not isinstance(row, dict):
            raise ProviderError("whois invalid response")
        name = _domain(row.get("domainName"))
        if not _allowed(self, name):
            return []
        return [self._make_asset(host=name, confidence="low", evidence={
            "registrar": row.get("registrarName"), "created_date": row.get("createdDate"),
            "updated_date": row.get("updatedDate"), "expires_date": row.get("expiresDate"),
            "status": row.get("status"), "name_servers": row.get("nameServers"),
            "source_target": target,
        })]


class AsnProvider(BaseProvider):
    """IP-to-ASN JSON: {ip, asn, as_name, as_domain, country_code, prefix}。"""

    name = "asn"
    description = "IP 对应 ASN 元数据（不枚举 ASN 网段）"
    max_pages = 1

    def is_configured(self) -> bool:
        return self._config.has_provider_credentials(self.name)

    def search(self, target: str) -> list[Asset]:
        self._scope.assert_in_scope(target, resolve_dns=False)
        try:
            ipaddress.ip_address(target)
        except ValueError:
            raise ProviderError("asn requires an authorized IP address") from None
        data = _request(self, target, {"ip": target})
        if not isinstance(data, dict) or "asn" not in data:
            raise ProviderError("asn invalid response")
        try:
            ip = str(ipaddress.ip_address(data.get("ip")))
        except (ValueError, TypeError):
            raise ProviderError("asn invalid response IP") from None
        if not _allowed(self, ip):
            return []
        return [self._make_asset(ip=ip, confidence="low", evidence={
            "asn": data["asn"], "as_name": data.get("as_name"),
            "as_domain": data.get("as_domain"), "country_code": data.get("country_code"),
            "prefix": data.get("prefix"), "source_target": target,
        })]
