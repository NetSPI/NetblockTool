"""Pluggable passive search providers.

Search-engine discovery is inherently unreliable: engines actively block
automated queries. The tool treats it as an **optional enrichment source**, not
a requirement. Authoritative registry data is always preferred, and a blocked
or missing search provider never stops a run.

To add a provider, subclass :class:`SearchProvider` and register it in
:data:`PROVIDERS`.
"""

from __future__ import annotations

import abc
from collections.abc import Sequence
from dataclasses import dataclass, field

from ..config import Config
from ..http import HttpClient
from ..logging_setup import get_logger
from ..models import Netblock

log = get_logger("search")


class SearchBlocked(Exception):
    """Raised internally when a provider detects anti-bot enforcement."""


@dataclass(slots=True)
class SearchOutcome:
    """What a search provider managed to produce."""

    provider: str
    netblocks: list[Netblock] = field(default_factory=list)
    #: True when the provider was actively blocked (CAPTCHA, 429 wall).
    blocked: bool = False
    #: True when the provider ran and completed, whether or not it found data.
    completed: bool = False
    pages_fetched: int = 0
    diagnostics: list[str] = field(default_factory=list)

    def note(self, message: str) -> None:
        self.diagnostics.append(message)


class SearchProvider(abc.ABC):
    """Interface for a passive search backend."""

    #: Identifier used with ``--search-provider``.
    name: str = "provider"

    def __init__(self, client: HttpClient, config: Config | None = None) -> None:
        self.client = client
        self.config = config or client.config

    @abc.abstractmethod
    def find_netblocks(self, company: str, *, max_pages: int = 10) -> SearchOutcome:
        """Search for netblocks associated with a company name."""

    def describe(self) -> str:
        return self.name


class NullSearchProvider(SearchProvider):
    """A provider that does nothing. Used when ``--no-google``/``-ng`` is set."""

    name = "none"

    def find_netblocks(self, company: str, *, max_pages: int = 10) -> SearchOutcome:
        outcome = SearchOutcome(provider=self.name, completed=True)
        outcome.note("Search-engine discovery disabled")
        return outcome


def get_provider(name: str | None, client: HttpClient,
                 config: Config | None = None) -> SearchProvider:
    """Instantiate a provider by name, falling back to the null provider."""
    from .google import GoogleSearchProvider  # local import avoids a cycle

    providers: dict[str, type[SearchProvider]] = {
        "none": NullSearchProvider,
        "google": GoogleSearchProvider,
    }
    key = (name or "none").lower()
    provider_class = providers.get(key)
    if provider_class is None:
        log.warning("Unknown search provider %r; disabling search-engine discovery", name)
        provider_class = NullSearchProvider
    return provider_class(client, config)


def available_providers() -> Sequence[str]:
    return ("none", "google")


__all__ = [
    "NullSearchProvider",
    "SearchBlocked",
    "SearchOutcome",
    "SearchProvider",
    "available_providers",
    "get_provider",
]
