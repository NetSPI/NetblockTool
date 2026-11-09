"""Shared test fixtures.

No test in this suite touches a live service. All HTTP traffic goes through
:class:`FakeHttpClient`, a drop-in stand-in for
:class:`netblocktool.http.HttpClient` that serves canned responses and can be
told to fail, time out or return garbage.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netblocktool.config import Config
from netblocktool.http import HttpError, Response


class FakeHttpClient:
    """A scripted replacement for :class:`~netblocktool.http.HttpClient`."""

    def __init__(self, routes: Mapping[str, Any] | None = None,
                 config: Config | None = None) -> None:
        #: URL substring -> payload. Payload may be a dict/list (served as
        #: JSON), a string (served as the body), a :class:`Response`, an
        #: exception instance (raised), or a callable taking (url, params).
        self.routes: dict[str, Any] = dict(routes or {})
        self.config = config or Config(user_agent="pytest/1.0 test@example.com")
        self.calls: list[tuple[str, dict]] = []
        self.host_rates: dict[str, float] = {}

    # -- test helpers -----------------------------------------------------

    def add(self, url_fragment: str, payload: Any) -> FakeHttpClient:
        self.routes[url_fragment] = payload
        return self

    def call_count(self, fragment: str) -> int:
        return sum(1 for url, _ in self.calls if fragment in url)

    # -- HttpClient interface --------------------------------------------

    def set_host_rate(self, host: str, rate: float) -> None:
        self.host_rates[host] = rate

    def close(self) -> None:
        pass

    def _match(self, url: str) -> Any:
        # Longest matching fragment wins, so "/org/GOGL/nets" beats "/org/".
        candidates = [(len(fragment), payload)
                      for fragment, payload in self.routes.items() if fragment in url]
        if not candidates:
            return None
        candidates.sort(key=lambda pair: pair[0], reverse=True)
        return candidates[0][1]

    def get(self, url: str, *, headers=None, params=None, cache=True,
            allow_redirects=True, no_retry_status=None) -> Response:
        self.calls.append((url, dict(params or {})))
        payload = self._match(url)

        if payload is None:
            return Response(url=url, status_code=404, text="", content=b"", headers={})
        if isinstance(payload, Exception):
            raise payload
        if callable(payload):
            payload = payload(url, dict(params or {}))
        if isinstance(payload, Response):
            return payload
        if isinstance(payload, (dict, list)):
            body = json.dumps(payload)
            return Response(url=url, status_code=200, text=body,
                            content=body.encode(), headers={
                                "Content-Type": "application/json"})
        body = str(payload)
        return Response(url=url, status_code=200, text=body, content=body.encode(),
                        headers={"Content-Type": "text/html"})

    def get_json(self, url: str, *, headers=None, params=None, cache=True,
                 no_retry_status=None) -> Any:
        response = self.get(url, headers=headers, params=params, cache=cache,
                            no_retry_status=no_retry_status)
        if response.status_code in (404, 410):
            return None
        if not response.ok:
            raise HttpError(f"HTTP {response.status_code} from {url}")
        return response.json()


@pytest.fixture
def config() -> Config:
    return Config(user_agent="pytest/1.0 test@example.com", timeout=5.0,
                  max_retries=1, rate_limit=100.0)


@pytest.fixture
def fake_client(config: Config) -> FakeHttpClient:
    return FakeHttpClient(config=config)


@pytest.fixture
def make_client(config: Config) -> Callable[..., FakeHttpClient]:
    def factory(routes: Mapping[str, Any] | None = None) -> FakeHttpClient:
        return FakeHttpClient(routes=routes, config=config)
    return factory


@pytest.fixture
def tmp_output(tmp_path: Path) -> Path:
    directory = tmp_path / "out"
    directory.mkdir()
    return directory
