"""指纹规范化与可注入受控传输的固定路径 favicon 采集。"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from assetops.core.scope_guard import ScopeGuard


def normalize_fingerprints(row: dict) -> dict[str, str]:
    result = {}
    for key in ("favicon_hash", "favicon"):
        value = row.get(key)
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            continue
        if re.fullmatch(r"[+-]?\d{1,11}", str(value).strip()):
            number = int(str(value).strip())
            if -(2 ** 31) <= number < 2 ** 31:
                result["favicon_hash"] = str(number)
                break
    for key in ("jarm_hash", "jarm"):
        value = row.get(key)
        if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{62}", value) and set(value) != {"0"}:
            result["jarm_hash"] = value.lower()
            break
    return result


def favicon_mmh3(body: bytes) -> str:
    """FOFA/httpx 使用带换行 Base64 的有符号 MurmurHash3 x86_32。"""
    data = base64.encodebytes(body)
    mask = 0xffffffff
    h = 0
    def rotate(value, bits):
        return ((value << bits) | (value >> (32 - bits))) & mask
    for offset in range(0, len(data) - len(data) % 4, 4):
        k = int.from_bytes(data[offset:offset + 4], "little")
        k = rotate((k * 0xcc9e2d51) & mask, 15) * 0x1b873593 & mask
        h ^= k
        h = (rotate(h, 13) * 5 + 0xe6546b64) & mask
    tail = data[len(data) - len(data) % 4:]
    if tail:
        k = int.from_bytes(tail, "little")
        h ^= rotate((k * 0xcc9e2d51) & mask, 15) * 0x1b873593 & mask
    h ^= len(data)
    h ^= h >> 16
    h = h * 0x85ebca6b & mask
    h ^= h >> 13
    h = h * 0xc2b2ae35 & mask
    h ^= h >> 16
    return str(h if h < 2 ** 31 else h - 2 ** 32)


@dataclass(frozen=True)
class FaviconResponse:
    url: str
    status_code: int
    body: bytes
    truncated: bool = False


def collect_favicon(
    target: str, *, scope_guard: ScopeGuard,
    fetch: Callable[..., FaviconResponse] | None = None,
    transport=None,
    max_bytes: int = 256 * 1024,
) -> dict:
    """fetch 必须由受控传输适配：固定DNS/IP、预留预算、禁重定向并限制读取。

    调用契约为 fetch(url, max_bytes=..., follow_redirects=False)。此模块不使用
    网络默认实现，也不解析 HTML link。响应正文不返回给持久化层。
    """
    if not 0 < max_bytes <= 256 * 1024:
        raise ValueError("max_bytes must be between 1 and 262144")
    parsed = urlsplit(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("favicon target must be an HTTP(S) URL without credentials")
    parsed.port  # Validate malformed ports before calling the transport.
    scope_guard.assert_in_scope(target, resolve_dns=False)
    url = urlunsplit((parsed.scheme, parsed.netloc, "/favicon.ico", "", ""))
    scope_guard.assert_in_scope(url, resolve_dns=False)
    if fetch is not None and transport is not None:
        raise ValueError("provide fetch or transport, not both")
    if transport is not None:
        method = getattr(transport, "request_favicon", None)
        if method is None:
            return {"status": "unsupported", "error": "controlled transport lacks fixed favicon path support"}
        result = method(parsed.hostname, port=parsed.port, scheme=parsed.scheme)
        response = FaviconResponse(url, result["status_code"], result.get("body", b""), result.get("truncated", False))
    elif fetch is not None:
        response = fetch(url, max_bytes=max_bytes, follow_redirects=False)
    else:
        return {"status": "unsupported", "error": "controlled favicon transport is not configured"}
    if response.url != url:
        return {"status": "failed", "error": "favicon output URL does not match fixed input"}
    if response.status_code in (429, 503):
        return {"status": "stopped", "status_code": response.status_code, "url": url}
    if response.status_code != 200:
        return {"status": "no_fingerprint", "status_code": response.status_code, "url": url}
    if response.truncated or not isinstance(response.body, bytes) or len(response.body) > max_bytes:
        return {"status": "failed", "error": "favicon response exceeded read limit"}
    if not response.body:
        return {"status": "no_fingerprint", "status_code": 200, "url": url}
    return {"status": "done", "input": target, "url": url, "status_code": 200,
            "favicon_hash": favicon_mmh3(response.body), "content_length": len(response.body)}
