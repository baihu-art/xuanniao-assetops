"""Scope Guard — 安全边界强制执行器。

核心原则：缺少授权默认拒绝。每个 Provider 调用、每次主动探测、
每次关联发现扩展前，都必须通过此模块校验目标是否在授权范围内。
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


@dataclass
class TargetScope:
    """单个授权目标的范围定义。"""
    name: str = ""
    domains: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)

    def domain_matches(self, hostname: str) -> bool:
        for pattern in self.domains:
            if self._domain_match(hostname, pattern):
                return True
        return False

    def ip_matches(self, hostname_or_ip: str, *, resolve_dns: bool = True) -> bool:
        try:
            addr = ipaddress.ip_address(hostname_or_ip)
        except ValueError:
            if not resolve_dns:
                return False
            try:
                resolved = socket.gethostbyname(hostname_or_ip)
                addr = ipaddress.ip_address(resolved)
            except (socket.gaierror, ValueError):
                return False

        for ip_str in self.ips:
            try:
                if addr == ipaddress.ip_address(ip_str):
                    return True
            except ValueError:
                continue

        for cidr in self.cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if addr in network:
                    return True
            except ValueError:
                continue

        return False

    @staticmethod
    def _domain_match(hostname: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return hostname == suffix or hostname.endswith("." + suffix)
        return hostname == pattern


@dataclass
class ScopeRules:
    out_of_scope_domains: list[str] = field(default_factory=list)
    prohibited_paths: list[str] = field(default_factory=list)
    auto_extend_favicon: bool = False
    auto_extend_jarm: bool = False
    max_recursion_depth: int = 1


class ScopeGuard:
    """授权范围守卫器 — 只读 scope 数据，线程安全。"""

    def __init__(
        self,
        targets: Iterable[TargetScope],
        rules: ScopeRules | None = None,
    ):
        self._targets: list[TargetScope] = list(targets)
        self._rules = rules or ScopeRules()
        self._loaded_from: str | None = None

    @classmethod
    def from_file(cls, path: str | None) -> "ScopeGuard":
        if path is None:
            return cls(targets=[], rules=ScopeRules())
        p = Path(path)
        if not p.is_file():
            return cls(targets=[], rules=ScopeRules())
        raw = json.loads(p.read_text(encoding="utf-8"))
        return cls._from_dict(raw, str(p))

    @classmethod
    def from_dict(cls, data: dict) -> "ScopeGuard":
        return cls._from_dict(data, None)

    @classmethod
    def _from_dict(cls, data: dict, loaded_from: str | None) -> "ScopeGuard":
        targets_raw = data.get("targets", [])
        targets = [
            TargetScope(
                name=t.get("name", ""),
                domains=list(t.get("domains", t.get("scope", []))),
                cidrs=list(t.get("cidrs", [])),
                ips=list(t.get("ips", t.get("allowed_ips", []))),
            )
            for t in targets_raw
        ]
        rules_raw = data.get("rules", {})
        rules = ScopeRules(
            out_of_scope_domains=list(rules_raw.get("out_of_scope_domains", [])),
            prohibited_paths=list(rules_raw.get("prohibited_paths", [])),
            auto_extend_favicon=bool(rules_raw.get("auto_extend_favicon", False)),
            auto_extend_jarm=bool(rules_raw.get("auto_extend_jarm", False)),
            max_recursion_depth=int(rules_raw.get("max_recursion_depth", 1)),
        )
        guard = cls(targets=targets, rules=rules)
        guard._loaded_from = loaded_from
        return guard

    @property
    def is_configured(self) -> bool:
        return len(self._targets) > 0

    @property
    def rules(self) -> ScopeRules:
        return self._rules

    def check(self, target: str, *, resolve_dns: bool = True) -> tuple[bool, str]:
        """检查目标是否在授权范围内。返回 (in_scope, reason)。"""
        if not self._targets:
            return False, "no scope configured — all targets denied by default"

        parsed = self._parse_target(target)
        hostname = parsed["hostname"]
        url_path = parsed["path"]

        if not hostname:
            return False, f"cannot parse target: {target}"

        # 黑名单优先
        for excl in self._rules.out_of_scope_domains:
            if TargetScope._domain_match(hostname, excl):
                return False, f"domain '{hostname}' matches out_of_scope pattern '{excl}'"

        if self._rules.prohibited_paths:
            for pattern in self._rules.prohibited_paths:
                if fnmatch.fnmatch(url_path, pattern):
                    return False, f"path '{url_path}' matches prohibited pattern '{pattern}'"
                if url_path.rstrip("/") == pattern.rstrip("/"):
                    return False, f"path '{url_path}' equals prohibited path '{pattern}'"

        # 白名单
        for t in self._targets:
            if t.domain_matches(hostname):
                return True, f"hostname '{hostname}' matches target '{t.name}' domain pattern"
            if t.ip_matches(hostname, resolve_dns=resolve_dns):
                return True, f"hostname/IP '{hostname}' matches target '{t.name}' IP/CIDR range"

        return False, f"'{hostname}' does not match any authorized target"

    def check_domain(self, hostname: str) -> tuple[bool, str]:
        """Check explicit domain authorization without DNS or IP fallback."""
        hostname = hostname.lower().rstrip(".")
        if not hostname or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-." for c in hostname):
            return False, "invalid domain name"
        if len(hostname) > 253 or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            for label in hostname.split(".")
        ):
            return False, "invalid domain name"
        try:
            ipaddress.ip_address(hostname)
            return False, "domain authorization requires a domain, not an IP"
        except ValueError:
            pass
        for pattern in self._rules.out_of_scope_domains:
            if TargetScope._domain_match(hostname, pattern.lower().rstrip(".")):
                return False, "domain matches out_of_scope pattern"
        if any(TargetScope._domain_match(hostname, pattern.lower().rstrip("."))
               for target in self._targets for pattern in target.domains):
            return True, "explicit domain authorization"
        return False, "domain does not match explicit authorization"

    def check_ip(self, address: str) -> tuple[bool, str]:
        """Check literal IP/CIDR authorization, never resolving names."""
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError:
            return False, "not a literal IP address"
        for pattern in self._rules.out_of_scope_domains:
            if TargetScope._domain_match(address, pattern):
                return False, "IP matches out_of_scope pattern"
        if any(target.ip_matches(address, resolve_dns=False) for target in self._targets):
            return True, "explicit IP/CIDR authorization"
        return False, "IP does not match explicit IP/CIDR authorization"

    def assert_active_address(self, hostname: str, address: str, *, collision: bool = False) -> None:
        allowed, reason = self.check_domain(hostname)
        if not allowed:
            raise PermissionError(reason)
        addr = ipaddress.ip_address(address)
        explicit, reason = self.check_ip(str(addr))
        restricted = any(t.ips or t.cidrs for t in self._targets)
        if (collision or restricted or not addr.is_global or addr.is_multicast) and not explicit:
            raise PermissionError(f"connection IP requires explicit authorization: {reason}")
        allowed, reason = self.check(f"http://{hostname}/", resolve_dns=False)
        if not allowed:
            raise PermissionError(reason)

    def assert_in_scope(self, target: str, *, resolve_dns: bool = True) -> None:
        ok, reason = self.check(target, resolve_dns=resolve_dns)
        if not ok:
            raise PermissionError(f"Scope check failed for '{target}': {reason}")

    @staticmethod
    def _parse_target(target: str) -> dict[str, str]:
        target = target.strip()
        if not target:
            return {"hostname": "", "path": "/"}
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            return {"hostname": parsed.hostname or "", "path": parsed.path or "/"}
        try:
            return {"hostname": str(ipaddress.ip_address(target)), "path": "/"}
        except ValueError:
            pass
        host_part = target
        if host_part.startswith("["):
            closing = host_part.find("]")
            if closing == -1:
                return {"hostname": "", "path": "/"}
            host_part = host_part[1:closing]
        elif ":" in host_part:
            host_part = host_part.rsplit(":", 1)[0]
        if "/" in host_part:
            host_part = host_part.split("/", 1)[0]
        return {"hostname": host_part, "path": "/"}

    def summary(self) -> dict:
        return {
            "configured_from": self._loaded_from,
            "num_targets": len(self._targets),
            "targets": [
                {"name": t.name, "domains": t.domains, "cidrs": t.cidrs, "ips": t.ips}
                for t in self._targets
            ],
            "rules": {
                "out_of_scope_domains": self._rules.out_of_scope_domains,
                "prohibited_paths": self._rules.prohibited_paths,
                "auto_extend_favicon": self._rules.auto_extend_favicon,
                "auto_extend_jarm": self._rules.auto_extend_jarm,
                "max_recursion_depth": self._rules.max_recursion_depth,
            },
        }
