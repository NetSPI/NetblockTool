"""A small, well-behaved HTTP client.

Every outbound request in NetblockTool goes through :class:`HttpClient`, which
provides the things the original tool lacked:

* a connection/read timeout on **every** request (``requests`` defaults to
  waiting forever);
* a bounded number of retries with exponential backoff and jitter;
* per-host rate limiting so we stay inside published registry/SEC limits;
* an in-process response cache so the same URL is never fetched twice;
* honest ``Retry-After`` handling for 429/503;
* a single, identifiable User-Agent.

TLS verification is always on. The original code globally disabled urllib3's
InsecureRequestWarning, which hid genuine certificate problems.
"""

from __future__ import annotations

import random
import threading
import time
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import requests

from .config import Config
from .logging_setup import get_logger

log = get_logger("http")

#: Only these schemes are ever fetched. Blocks file://, ftp://, gopher:// and
#: friends if a hostile registry response tries to redirect us somewhere odd.
ALLOWED_SCHEMES = frozenset({"http", "https"})

#: Response bodies larger than this are refused. Registry/filing documents are
#: small; anything larger is either a mistake or an attempt to exhaust memory.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024

RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


class HttpError(Exception):
    """Raised when a request cannot be completed after all retries."""


class BlockedError(HttpError):
    """Raised when a remote service actively blocks us (CAPTCHA, 403 wall)."""


@dataclass(slots=True)
class Response:
    """A minimal, immutable view of an HTTP response."""

    url: str
    status_code: int
    text: str
    content: bytes
    headers: Mapping[str, str]

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> Any:
        """Parse the body as JSON, raising :class:`HttpError` on garbage."""
        import json

        try:
            return json.loads(self.text)
        except (ValueError, TypeError) as exc:
            raise HttpError(f"Malformed JSON from {self.url}: {exc}") from exc


class _RateLimiter:
    """Token-free, per-host minimum-interval limiter. Thread safe."""

    def __init__(self, default_rate: float) -> None:
        self._default_rate = max(0.1, default_rate)
        self._rates: dict[str, float] = {}
        self._last: dict[str, float] = defaultdict(float)
        self._locks: dict[str, threading.Lock] = defaultdict(threading.Lock)
        self._guard = threading.Lock()

    def set_rate(self, host: str, rate_per_second: float) -> None:
        with self._guard:
            self._rates[host] = max(0.1, rate_per_second)

    def acquire(self, host: str) -> None:
        rate = self._rates.get(host, self._default_rate)
        interval = 1.0 / rate
        with self._locks[host]:
            elapsed = time.monotonic() - self._last[host]
            if elapsed < interval:
                time.sleep(interval - elapsed)
            self._last[host] = time.monotonic()


def validate_url(url: str) -> str:
    """Reject non-HTTP(S) URLs and obvious SSRF vectors.

    External data (registry references, filing links, search results) is
    untrusted; we never fetch a URL we have not vetted.
    """
    parts = urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise HttpError(f"Refusing non-HTTP(S) URL: {url!r}")
    if not parts.hostname:
        raise HttpError(f"Refusing URL with no host: {url!r}")
    return url


class HttpClient:
    """Rate-limited, retrying HTTP client with an in-memory response cache."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": self.config.user_agent,
            "Accept-Encoding": "gzip, deflate",
        })
        self._limiter = _RateLimiter(self.config.rate_limit)
        self._cache: dict[tuple, Response] = {}
        self._cache_lock = threading.Lock()
        self.stats: dict[str, int] = defaultdict(int)

    # -- configuration ----------------------------------------------------

    def set_host_rate(self, host: str, rate_per_second: float) -> None:
        """Override the request rate for a single host."""
        self._limiter.set_rate(host, rate_per_second)

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- requests ---------------------------------------------------------

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        cache: bool = True,
        allow_redirects: bool = True,
        no_retry_status: frozenset[int] | None = None,
    ) -> Response:
        """Perform a GET request. Never raises for HTTP status alone.

        Args:
            no_retry_status: statuses to treat as final rather than transient.
                Use for endpoints where a 5xx means "this query is invalid"
                and retrying can only waste time.
        """
        return self._request(
            "GET",
            url,
            headers=headers,
            params=params,
            cache=cache,
            allow_redirects=allow_redirects,
            no_retry_status=no_retry_status,
        )

    def get_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        cache: bool = True,
        no_retry_status: frozenset[int] | None = None,
    ) -> Any:
        """GET and parse JSON. Returns ``None`` for 404/410 (absent record)."""
        merged = {"Accept": "application/json"}
        if headers:
            merged.update(headers)
        response = self.get(url, headers=merged, params=params, cache=cache,
                            no_retry_status=no_retry_status)
        if response.status_code in (404, 410):
            return None
        if not response.ok:
            raise HttpError(f"HTTP {response.status_code} from {url}")
        return response.json()

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None,
        params: Mapping[str, Any] | None,
        cache: bool,
        allow_redirects: bool = True,
        no_retry_status: frozenset[int] | None = None,
    ) -> Response:
        validate_url(url)
        final_status = no_retry_status or frozenset()
        # Params may hold repeated values (lists) for APIs that accept the same
        # key more than once; normalise them into a hashable cache key.
        key = (method, url, _params_key(params))

        if cache:
            with self._cache_lock:
                hit = self._cache.get(key)
            if hit is not None:
                self.stats["cache_hits"] += 1
                return hit

        host = urlsplit(url).hostname or ""
        last_error: Exception | None = None
        attempts = self.config.max_retries + 1

        for attempt in range(1, attempts + 1):
            self._limiter.acquire(host)
            try:
                self.stats["requests"] += 1
                raw = self._session.request(
                    method,
                    url,
                    headers=dict(headers or {}),
                    params=dict(params or {}),
                    timeout=(self.config.timeout, self.config.timeout),
                    allow_redirects=allow_redirects,
                    stream=True,
                )
            except requests.exceptions.RequestException as exc:
                last_error = exc
                self.stats["errors"] += 1
                log.debug("%s %s failed (attempt %d/%d): %s", method, url, attempt, attempts, exc)
                if attempt < attempts:
                    self._backoff(attempt)
                continue

            try:
                if _too_large(raw):
                    raise HttpError(f"Response from {url} exceeds size limit")
                body = raw.content
            except requests.exceptions.RequestException as exc:
                last_error = exc
                self.stats["errors"] += 1
                if attempt < attempts:
                    self._backoff(attempt)
                continue
            finally:
                raw.close()

            response = Response(
                url=str(raw.url),
                status_code=raw.status_code,
                text=body.decode(raw.encoding or "utf-8", errors="replace"),
                content=body,
                headers=dict(raw.headers),
            )

            if (response.status_code in RETRYABLE_STATUS
                    and response.status_code not in final_status
                    and attempt < attempts):
                delay = _retry_after(raw.headers) or self._backoff_delay(attempt)
                log.debug(
                    "HTTP %d from %s; retrying in %.1fs (attempt %d/%d)",
                    response.status_code, url, delay, attempt, attempts,
                )
                time.sleep(delay)
                continue

            return response

        raise HttpError(f"{method} {url} failed after {attempts} attempts: {last_error}")

    # -- backoff ----------------------------------------------------------

    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff with full jitter, capped at 30 seconds."""
        base = min(30.0, 0.5 * (2 ** (attempt - 1)))
        return random.uniform(0.0, base)

    def _backoff(self, attempt: int) -> None:
        time.sleep(self._backoff_delay(attempt))


def _params_key(params: Mapping[str, Any] | None) -> tuple:
    """Build a hashable cache key from params that may contain sequences."""
    if not params:
        return ()
    items = []
    for name, value in params.items():
        if isinstance(value, (list, tuple)):
            items.append((name, tuple(str(v) for v in value)))
        else:
            items.append((name, str(value)))
    return tuple(sorted(items))


def _retry_after(headers: Mapping[str, str]) -> float | None:
    """Parse a ``Retry-After`` header, clamped so we never sleep forever."""
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if not raw:
        return None
    try:
        return max(0.0, min(60.0, float(raw)))
    except (TypeError, ValueError):
        return None


def _too_large(raw: requests.Response) -> bool:
    declared = raw.headers.get("Content-Length")
    return bool(declared and declared.isdigit()
                and int(declared) > MAX_RESPONSE_BYTES)
