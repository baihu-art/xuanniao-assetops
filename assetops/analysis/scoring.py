"""英招实际评分分支的离线、当前 Run 证据版本。"""

from __future__ import annotations

from urllib.parse import urlsplit

from assetops.models.asset import Asset

RULE_VERSION = "yingzhao-v1"
SENSITIVE_PORTS = {"22", "3389", "6379", "9200", "3306", "5432", "1433", "27017", "11211", "21", "2375", "4243", "10250", "6443"}
_ACTIVE_SOURCES = {"httpx", "favicon", "jarm", "host_collision", "subdomain_brute", "active_httpx"}
_DEV = ("test", "pre", "staging", "uat", "dev")


def priority_for_score(score: int) -> str:
    return "high" if score >= 60 else "medium" if score >= 35 else "low"


def score_asset(asset: Asset, run_id: str) -> dict:
    """不读取可跨 Run 漂移的 Asset 快照字段，只使用该 Run 的原始观测。"""
    observations = sorted(
        (o for o in asset.observations if o.run_id == run_id and o.source != "analysis"),
        key=lambda o: (o.source in _ACTIVE_SOURCES, o.last_seen_at, o.id), reverse=True,
    )
    fields = {}
    used = []
    for obs in observations:
        evidence = obs.evidence
        candidates = {key: evidence.get(key) for key in ("host", "ip", "port", "title", "tech", "status_code", "url")}
        candidates["webserver"] = evidence.get("webserver") or evidence.get("server")
        raw_url = evidence.get("url") or evidence.get("input") or evidence.get("raw_host") or ""
        if isinstance(raw_url, str) and raw_url:
            try:
                parsed = urlsplit(raw_url if "://" in raw_url else "//" + raw_url)
                candidates["host"] = candidates["host"] or parsed.hostname
                candidates["port"] = candidates["port"] or parsed.port or ({"http": 80, "https": 443}.get(parsed.scheme))
            except ValueError:
                pass
        contributed = False
        for key, value in candidates.items():
            if key not in fields and value is not None and value != "" and value != []:
                fields[key] = value
                contributed = True
        if contributed:
            used.append(obs.id)
    host = str(fields.get("host", "")).lower()
    port = str(fields.get("port", ""))
    title = str(fields.get("title", ""))
    server = str(fields.get("webserver", ""))
    tech = fields.get("tech", [])
    tech = [str(t) for t in tech] if isinstance(tech, list) else []
    status = fields.get("status_code")
    if isinstance(status, str) and status.isdigit():
        status = int(status)
    lower_title, lower_server = title.lower(), server.lower()
    category = "web"
    if any(k in lower_title for k in ("admin", "管理", "后台", "dashboard", "console")):
        category = "admin"
    elif any(k in host for k in _DEV):
        category = "dev"
    elif any(k in host for k in ("api", "gateway")) or any(k in lower_title for k in ("swagger", "graphql")):
        category = "api"
    elif any(k in host for k in ("mail", "smtp", "imap", "pop3")):
        category = "mail"
    elif any(k in host for k in ("obs", "static", "download", "resource")):
        category = "storage"
    elif any(k in host for k in ("media", "webrtc", "stream")):
        category = "media"
    elif port in SENSITIVE_PORTS:
        category = "infra" if port in ("22", "3389", "21") else "database"
    elif "ZLMediaKit" in server:
        category = "media"
    elif "tencent-cos" in lower_server or "TosServer" in server:
        category = "storage"
    elif "stgw" in lower_server:
        category = "waf"

    exposure = {200: 20 if "WAF拦截" in title else 30, 301: 25, 302: 25, 401: 20, 403: 15, 503: 10}.get(status, 0)
    if port in SENSITIVE_PORTS:
        risk, risk_reason = 25, f"敏感端口:{port}"
    elif "nginx" in lower_server and "welcome to nginx" in lower_title:
        risk, risk_reason = 22, "Nginx默认页面线索"
    elif "ZLMediaKit" in server:
        risk, risk_reason = 25, "ZLMediaKit产品线索（不证明存在漏洞）"
    elif "openresty" in lower_server:
        risk, risk_reason = 20, "OpenResty产品线索（不证明存在漏洞）"
    elif "Tengine" in server:
        risk, risk_reason = 18, "Tengine引擎"
    elif "tencent-cos" in lower_server or "TosServer" in server:
        risk, risk_reason = 10, "对象存储服务"
    elif "stgw" in lower_server:
        risk, risk_reason = 8, "STGW WAF网关"
    elif tech:
        risk, risk_reason = 15, "技术栈:" + ",".join(tech)
    else:
        risk, risk_reason = 5, "未知技术栈；未知不代表安全"
    value = {"admin": 20, "database": 20, "api": 18, "dev": 18, "mail": 15, "infra": 15, "media": 12, "storage": 10, "waf": 8, "web": 5}[category]
    width = 12 if port and port not in ("80", "443", "8080", "8443", "8000", "3000") else 8 if port in ("8080", "8443") else 5
    uniqueness = 10 if any(k in host for k in _DEV) else 8 if any(k in host for k in ("admin", "manage", "console")) else 3
    dimensions = {"exposure": exposure, "technical_risk": risk, "data_value": value, "attack_surface": width, "uniqueness": uniqueness}
    score = sum(dimensions.values())
    reasons = [f"HTTP {status if status is not None else '未知'}" + (" WAF拦截" if status == 200 and "WAF拦截" in title else ""), risk_reason, f"{category}服务", f"端口:{port or '未知'}", "测试/预发环境" if uniqueness == 10 else "管理接口" if uniqueness == 8 else "独特性默认分"]
    return {
        "asset_id": asset.id, "run_id": run_id, "rule_version": RULE_VERSION,
        "host": host, "port": port, "ip": str(fields.get("ip", "")),
        "url": fields.get("url", ""), "title": title, "webserver": server, "tech": tech,
        "category": category, "dimensions": dimensions, "score": score,
        "priority": priority_for_score(score), "reasons": reasons,
        "input_observation_ids": sorted(used),
        "missing_information": [key for key in ("host", "port", "status_code", "title", "webserver", "tech") if key not in fields],
        "theoretical_max": 100, "rule_max": 97,
    }


def top_targets(scores: list[dict], limit: int = 20) -> list[dict]:
    if limit < 0:
        raise ValueError("limit must be non-negative")
    hosts = {}
    for entry in scores:
        key = entry.get("host") or entry.get("ip") or entry["asset_id"]
        if key not in hosts or entry["score"] > hosts[key]["score"]:
            hosts[key] = entry
    return sorted(hosts.values(), key=lambda entry: (-entry["score"], entry["asset_id"]))[:limit]
