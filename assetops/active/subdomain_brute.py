"""Non-recursive, bounded, explicitly scoped DNS enumeration."""
from __future__ import annotations

import http.client
import ipaddress
import re
import secrets
import time
from itertools import islice
from pathlib import Path

from assetops.active.host_collision import response_signature
from assetops.active.transport import (ActiveStepStopped, BudgetExceeded, consume_budget,
                                      resolve_addresses)


def run_subdomain_brute(scope, root_domain, *, labels=None, wordlist_path=None,
                        resolver=None, transport=None, verify_http=False, consume=None,
                        max_candidates=100, max_wordlist_bytes=65536, max_requests=100,
                        random_label=None, clock=time.monotonic, sleep=time.sleep,
                        rate_limit=2, scheme="https", port=None):
    for name, value in (("max_candidates", max_candidates), ("max_wordlist_bytes", max_wordlist_bytes),
                        ("max_requests", max_requests)):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if rate_limit <= 0 or not rate_limit < float("inf"):
        raise ValueError("rate_limit must be positive and finite")
    if verify_http and transport is None:
        raise ValueError("HTTP verification requires a controlled transport")
    if (labels is None) == (wordlist_path is None):
        raise ValueError("provide exactly one of labels or wordlist_path")
    root_domain = root_domain.lower().rstrip(".")
    allowed, reason = scope.check_domain(root_domain)
    if not allowed:
        raise PermissionError(reason)
    if wordlist_path is not None:
        with Path(wordlist_path).open("rb") as stream:
            raw = stream.read(max_wordlist_bytes + 1)
        if len(raw) > max_wordlist_bytes:
            raise ValueError("wordlist exceeds maximum byte size")
        labels = raw.decode("utf-8").splitlines()
    raw_labels = list(islice(iter(labels), max_candidates + 1))
    result = {"summary": {"dns_attempted": 0, "baselines": 0, "dns_found": 0,
                           "wildcard": False, "wildcard_baseline_complete": False},
              "results": [], "errors": [], "limited": len(raw_labels) > max_candidates}
    candidates = []
    for label in raw_labels[:max_candidates]:
        if not isinstance(label, str) or not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label):
            result["errors"].append({"label": str(label)[:64], "error": "invalid non-recursive DNS label"})
            continue
        host = label.lower() + "." + root_domain
        allowed, reason = scope.check_domain(host)
        if not allowed:
            result["errors"].append({"host": host, "error": reason})
        elif host not in candidates:
            candidates.append(host)
    if not candidates:
        return result
    resolver = resolver or resolve_addresses
    random_label = random_label or (lambda: "assetops-" + secrets.token_hex(8))
    last = None

    def resolve(host):
        nonlocal last
        allowed, reason = scope.check_domain(host)
        if not allowed:
            raise PermissionError(reason)
        if result["summary"]["dns_attempted"] >= max_requests:
            raise BudgetExceeded("DNS request budget exhausted")
        if last is not None:
            sleep(max(0, 1 / rate_limit - (clock() - last)))
        consume_budget(consume)
        result["summary"]["dns_attempted"] += 1
        last = clock()
        addresses = sorted(set(str(ipaddress.ip_address(a)) for a in resolver(host)))
        for address in addresses:
            scope.assert_active_address(host, address)
        return addresses

    baseline_sets, baseline_http = [], []
    for _ in range(3):
        host = random_label() + "." + root_domain
        try:
            addresses = resolve(host)
            baseline_sets.append(set(addresses))
            result["summary"]["baselines"] += 1
            result["results"].append({"host": host, "addresses": addresses, "classification": "dns_baseline"})
            if verify_http and addresses:
                row = transport.request(host, connect_ip=addresses[0], scheme=scheme, port=port)
                baseline_http.append(response_signature(row))
                result["results"].append({**row, "classification": "http_baseline"})
                if row.get("stopped") or row["status_code"] in {429, 503}:
                    result["limited"] = True
                    return result
        except (BudgetExceeded, ActiveStepStopped) as exc:
            result["errors"].append({"error": str(exc)})
            result["limited"] = True
            return result
        except (OSError, PermissionError, ValueError, http.client.HTTPException) as exc:
            result["errors"].append({"host": host, "phase": "baseline", "error": str(exc)})
    complete = len(baseline_sets) == 3
    wildcard = any(baseline_sets)
    result["summary"]["wildcard_baseline_complete"] = complete
    result["summary"]["wildcard"] = wildcard
    wildcard_addresses = set().union(*baseline_sets)
    for host in candidates:
        try:
            addresses = resolve(host)
            if not addresses:
                continue
            result["summary"]["dns_found"] += 1
            wildcard_match = bool(set(addresses) & wildcard_addresses)
            row = {"host": host, "addresses": addresses, "wildcard_match": wildcard_match,
                   "confidence_limited": not complete or wildcard,
                   "classification": "candidate" if wildcard or not complete else "dns_discovered"}
            result["results"].append(row)
            if verify_http:
                http_result = transport.request(host, connect_ip=addresses[0], scheme=scheme, port=port)
                different = bool(baseline_http) and all(response_signature(http_result) != sig for sig in baseline_http)
                classification = "http_differential" if different and http_result["status_code"] < 400 else "http_reachable"
                if wildcard and not different:
                    classification = "candidate"
                row["http"] = {**http_result, "classification": classification}
                if http_result.get("stopped") or http_result["status_code"] in {429, 503}:
                    result["limited"] = True
                    return result
        except (BudgetExceeded, ActiveStepStopped) as exc:
            result["errors"].append({"error": str(exc)})
            result["limited"] = True
            return result
        except (OSError, PermissionError, ValueError, http.client.HTTPException) as exc:
            result["errors"].append({"host": host, "error": str(exc)})
    return result
