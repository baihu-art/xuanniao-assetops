from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _bool_env(name: str, default: bool = False) -> bool:
    val = os.environ.get(name, "").strip().lower()
    if not val:
        return default
    return val in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    val = os.environ.get(name, "").strip()
    if not val:
        return default
    try:
        return int(val)
    except ValueError:
        return default


@dataclass
class AssetOpsConfig:
    data_root: str = ""
    scope_file: str = ""

    timeout: int = 30
    rate_limit: int = 5
    budget_max: int = 10000
    insecure_tls: bool = False
    httpx_enabled: bool = False
    httpx_path: str = ""
    httpx_max_targets: int = 100
    httpx_output_limit: int = 100

    _fofa_email: str = ""
    _fofa_key: str = ""
    _quake_token: str = ""
    _hunter_key: str = ""
    _shodan_key: str = ""

    passive_dns_endpoint: str = ""
    ct_endpoint: str = ""
    whois_endpoint: str = ""
    asn_endpoint: str = ""
    _passive_dns_key: str = ""
    _ct_key: str = ""
    _whois_key: str = ""
    _asn_key: str = ""

    @classmethod
    def from_env(cls) -> "AssetOpsConfig":
        data_root = os.environ.get("ASSETOPS_DATA_ROOT", "").strip()
        if not data_root:
            data_root = str(Path.cwd() / "data")

        scope_file = os.environ.get("ASSETOPS_SCOPE_FILE", "").strip()
        if not scope_file:
            scope_file = str(Path.cwd() / "scope.json")

        return cls(
            data_root=data_root,
            scope_file=scope_file,
            timeout=_int_env("ASSETOPS_TIMEOUT", 30),
            rate_limit=_int_env("ASSETOPS_RATE_LIMIT", 5),
            budget_max=_int_env("ASSETOPS_BUDGET_MAX", 10000),
            insecure_tls=_bool_env("ASSETOPS_INSECURE_TLS", False),
            httpx_enabled=_bool_env("ASSETOPS_HTTPX_ENABLED", False),
            httpx_path=os.environ.get("ASSETOPS_HTTPX_PATH", "").strip(),
            httpx_max_targets=_int_env("ASSETOPS_HTTPX_MAX_TARGETS", 100),
            httpx_output_limit=_int_env("ASSETOPS_HTTPX_OUTPUT_LIMIT", 100),
            _fofa_email=os.environ.get("FOFA_EMAIL", "").strip(),
            _fofa_key=os.environ.get("FOFA_KEY", "").strip(),
            _quake_token=os.environ.get("QUAKE_TOKEN", "").strip(),
            _hunter_key=os.environ.get("HUNTER_KEY", "").strip(),
            _shodan_key=os.environ.get("SHODAN_KEY", "").strip(),
            passive_dns_endpoint=os.environ.get("PASSIVE_DNS_ENDPOINT", "").strip(),
            ct_endpoint=os.environ.get("CT_ENDPOINT", "").strip(),
            whois_endpoint=os.environ.get("WHOIS_ENDPOINT", "").strip(),
            asn_endpoint=os.environ.get("ASN_ENDPOINT", "").strip(),
            _passive_dns_key=os.environ.get("PASSIVE_DNS_KEY", "").strip(),
            _ct_key=os.environ.get("CT_KEY", "").strip(),
            _whois_key=os.environ.get("WHOIS_KEY", "").strip(),
            _asn_key=os.environ.get("ASN_KEY", "").strip(),
        )

    def get_credential(self, name: str) -> str:
        return getattr(self, f"_{name}", "")

    def has_provider_credentials(self, provider: str) -> bool:
        checks = {
            "fofa": bool(self._fofa_key),
            "quake": bool(self._quake_token),
            "hunter": bool(self._hunter_key),
            "shodan": bool(self._shodan_key),
            "passive_dns": bool(self.passive_dns_endpoint),
            "ct": bool(self.ct_endpoint),
            "whois": bool(self.whois_endpoint and self._whois_key),
            "asn": bool(self.asn_endpoint and self._asn_key),
        }
        return checks.get(provider, False)

    def safe_view(self) -> dict[str, Any]:
        return {
            "data_root": self.data_root,
            "scope_file": self.scope_file,
            "timeout": self.timeout,
            "rate_limit": self.rate_limit,
            "budget_max": self.budget_max,
            "insecure_tls": self.insecure_tls,
            "httpx_enabled": self.httpx_enabled,
            "httpx_path_configured": bool(self.httpx_path),
            "httpx_max_targets": self.httpx_max_targets,
            "httpx_output_limit": self.httpx_output_limit,
            "credentials_present": {
                "fofa": self.has_provider_credentials("fofa"),
                "quake": self.has_provider_credentials("quake"),
                "hunter": self.has_provider_credentials("hunter"),
                "shodan": self.has_provider_credentials("shodan"),
                "passive_dns": self.has_provider_credentials("passive_dns"),
                "ct": self.has_provider_credentials("ct"),
                "whois": self.has_provider_credentials("whois"),
                "asn": self.has_provider_credentials("asn"),
            },
        }
