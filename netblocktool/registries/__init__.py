"""Regional Internet Registry clients.

The aggregate entry point is :func:`query_registries`, which runs every
configured registry, tolerates individual failures and merges the results.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..config import Config
from ..http import HttpClient
from ..logging_setup import get_logger
from .arin import ArinClient
from .base import RegistryClient, RegistryResult, dedupe_contacts
from .bgp import BgpClient, parse_asn
from .rdap import RDAP_ENDPOINTS, RdapClient, build_rdap_clients

__all__ = [
    "RDAP_ENDPOINTS",
    "ArinClient",
    "BgpClient",
    "RdapClient",
    "RegistryClient",
    "RegistryResult",
    "build_clients",
    "parse_asn",
    "query_registries",
]

log = get_logger("registries")


def build_clients(registries: Iterable[str], client: HttpClient,
                  config: Config) -> list[RegistryClient]:
    """Instantiate a client for each requested registry."""
    names = [str(r).lower() for r in registries]
    clients: list[RegistryClient] = []
    if "arin" in names:
        clients.append(ArinClient(client, config))
    clients.extend(build_rdap_clients(names, client, config))
    return clients


def query_registries(
    query: str,
    clients: Sequence[RegistryClient],
    *,
    fetch_pocs: bool = False,
    max_workers: int = 4,
) -> RegistryResult:
    """Query every registry concurrently and merge the results.

    A registry that raises, times out or returns nonsense contributes an entry
    to ``errors`` and nothing else; the others are unaffected.
    """
    merged = RegistryResult(registry="+".join(c.name for c in clients))
    if not clients:
        return merged

    workers = max(1, min(len(clients), max_workers))
    with ThreadPoolExecutor(max_workers=workers,
                            thread_name_prefix="registry") as executor:
        futures = {
            executor.submit(_safe_search, registry_client, query, fetch_pocs): registry_client
            for registry_client in clients
        }
        for future in as_completed(futures):
            registry_client = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                message = f"{registry_client.name.upper()} lookup failed: {exc}"
                log.warning(message)
                merged.errors.append(message)
                continue
            merged.extend(result)

    merged.contacts = dedupe_contacts(merged.contacts)
    merged.asns = sorted({asn for asn in (parse_asn(a) for a in merged.asns) if asn})
    return merged


def _safe_search(registry_client: RegistryClient, query: str,
                 fetch_pocs: bool) -> RegistryResult:
    log.info("Querying %s for %r", registry_client.name.upper(), query)
    effective = query
    if "*" in query and not registry_client.supports_wildcards():
        # RDAP treats '*' as a wildcard too, but strip trailing-only wildcards
        # for registries that reject them outright.
        effective = query
    return registry_client.search(effective, fetch_pocs=fetch_pocs)
