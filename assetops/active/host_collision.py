"""Bounded Host-header comparison; differences are evidence, not bypass claims."""
from __future__ import annotations

import http.client
import ipaddress
import secrets
from itertools import islice

from assetops.active.transport import ActiveStepStopped, BudgetExceeded


def response_signature(row):
    return row["status_code"], row["content_length"], row["body_hash"], row["title"]


def run_host_collision(scope, ips, hosts, *, transport, ports=None, max_candidates=100,
                       random_label=None):
    if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or max_candidates <= 0:
        raise ValueError("max_candidates must be a positive integer")
    random_label = random_label or (lambda: "assetops-" + secrets.token_hex(8))
    result = {"summary": {"attempted": 0, "baselines": 0, "candidates": 0},
              "results": [], "errors": [], "limited": False}
    raw_ips = list(islice(iter(ips), max_candidates + 1))
    raw_hosts = list(islice(iter(hosts), max_candidates + 1))
    endpoints = list(islice(iter(ports if ports is not None else [("http", 80), ("https", 443)]), max_candidates + 1))
    if any(len(items) > max_candidates for items in (raw_ips, raw_hosts, endpoints)):
        result["limited"] = True
    addresses, domains = [], []
    for value in raw_ips[:max_candidates]:
        try:
            address = str(ipaddress.ip_address(value))
            allowed, reason = scope.check_ip(address)
            if not allowed:
                raise PermissionError(reason)
            if address not in addresses:
                addresses.append(address)
        except (ValueError, PermissionError) as exc:
            result["errors"].append({"connect_ip": str(value), "error": str(exc)})
    for value in raw_hosts[:max_candidates]:
        host = str(value).lower().rstrip(".")
        allowed, reason = scope.check_domain(host)
        if not allowed:
            result["errors"].append({"host": host, "error": reason})
        elif host not in domains:
            domains.append(host)
    if not addresses or not domains:
        return result
    combinations = len(addresses) * len(domains) * len(endpoints)
    result["summary"]["candidate_combinations"] = combinations
    result["limited"] |= combinations > max_candidates
    for address in addresses:
        for scheme, port in endpoints[:max_candidates]:
            if result["summary"]["attempted"] >= max_candidates:
                return result
            random_host = random_label() + "." + domains[0].split(".", 1)[-1]
            random_allowed = scope.check_domain(random_host)[0]
            baseline_host = random_host if random_allowed else domains[0]
            baseline = None
            try:
                baseline = transport.request(baseline_host, connect_ip=address, scheme=scheme,
                                             port=port, collision=True)
                result["summary"]["baselines"] += 1
                result["results"].append({**baseline, "classification": "baseline",
                                           "baseline_kind": "random" if random_allowed else "authorized_default_host",
                                           "confidence_limited": not random_allowed})
                if baseline.get("stopped") or baseline["status_code"] in {429, 503}:
                    result["limited"] = True
                    return result
            except (BudgetExceeded, ActiveStepStopped) as exc:
                result["errors"].append({"error": str(exc)})
                result["limited"] = True
                return result
            except (OSError, ValueError, PermissionError, http.client.HTTPException) as exc:
                result["errors"].append({"connect_ip": address, "host": baseline_host,
                                           "scheme": scheme, "port": port, "phase": "baseline", "error": str(exc)})
            for host in domains:
                if result["summary"]["attempted"] >= max_candidates:
                    return result
                result["summary"]["attempted"] += 1
                try:
                    row = transport.request(host, connect_ip=address, scheme=scheme, port=port, collision=True)
                    different = baseline is not None and response_signature(row) != response_signature(baseline)
                    classification = "differential" if different and row["status_code"] < 400 else "unconfirmed"
                    if baseline is None and row["status_code"] < 400:
                        classification = "candidate"
                    row = {**row, "classification": classification, "baseline_different": different,
                           "confidence_limited": not random_allowed or baseline is None}
                    result["results"].append(row)
                    if classification in {"candidate", "differential"}:
                        result["summary"]["candidates"] += 1
                    if row.get("stopped") or row["status_code"] in {429, 503}:
                        result["limited"] = True
                        return result
                except (BudgetExceeded, ActiveStepStopped) as exc:
                    result["errors"].append({"error": str(exc)})
                    result["limited"] = True
                    return result
                except (OSError, ValueError, PermissionError, http.client.HTTPException) as exc:
                    result["errors"].append({"connect_ip": address, "host": host,
                                               "scheme": scheme, "port": port, "error": str(exc)})
    return result
