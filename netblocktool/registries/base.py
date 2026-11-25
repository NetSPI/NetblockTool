"""Shared plumbing for Regional Internet Registry clients."""

from __future__ import annotations

import abc
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from ..http import HttpClient
from ..models import Contact, Netblock, Organization


@dataclass(slots=True)
class RegistryResult:
    """Everything one registry produced for one company query."""

    registry: str
    organizations: list[Organization] = field(default_factory=list)
    netblocks: list[Netblock] = field(default_factory=list)
    contacts: list[Contact] = field(default_factory=list)
    asns: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def extend(self, other: RegistryResult) -> None:
        self.organizations.extend(other.organizations)
        self.netblocks.extend(other.netblocks)
        self.contacts.extend(other.contacts)
        self.asns.extend(other.asns)
        self.errors.extend(other.errors)


class RegistryClient(abc.ABC):
    """Interface implemented by every RIR client.

    Implementations must never raise for network or parsing problems: they
    record the failure in :attr:`RegistryResult.errors` and return whatever
    they managed to gather, so one dead registry cannot abort a run.
    """

    #: Short registry identifier, e.g. ``"arin"``.
    name: str = "registry"

    def __init__(self, client: HttpClient, config: Config | None = None) -> None:
        self.client = client
        self.config = config or client.config

    @abc.abstractmethod
    def search(self, query: str, *, fetch_pocs: bool = False) -> RegistryResult:
        """Find organisations and netblocks matching a company-name query."""

    def supports_wildcards(self) -> bool:
        """Whether ``*`` in a query means anything to this registry."""
        return False


# -- ARIN-style JSON helpers ------------------------------------------------
#
# ARIN's Whois-RWS returns JSON transliterated from XML, so scalars are wrapped
# as ``{"$": "value"}`` and repeated elements collapse to a single object when
# there is exactly one of them. Both shapes have to be handled everywhere.


def text_value(node: Any) -> str:
    """Extract a scalar from an ARIN ``{"$": ...}`` wrapper.

    Returns an empty string for anything unusable, so callers never need a
    try/except around routine field access.
    """
    if node is None:
        return ""
    if isinstance(node, str):
        return node.strip()
    if isinstance(node, (int, float)):
        return str(node)
    if isinstance(node, dict):
        if "$" in node:
            return text_value(node["$"])
        return ""
    if isinstance(node, list):
        for item in node:
            value = text_value(item)
            if value:
                return value
    return ""


def as_list(node: Any) -> list[Any]:
    """Normalise a field that may be a single object or a list of objects."""
    if node is None:
        return []
    if isinstance(node, list):
        return node
    return [node]


def dig(node: Any, *keys: str) -> Any:
    """Safely walk nested dictionaries; returns ``None`` if any key is missing."""
    current = node
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def join_address(lines: Iterable[str], *parts: str) -> str:
    """Build a single address string from street lines plus city/state/etc."""
    chunks = [str(line).strip() for line in lines if str(line).strip()]
    chunks.extend(str(part).strip() for part in parts if part and str(part).strip())
    # De-duplicate while preserving order; registries often repeat the city.
    seen: set[str] = set()
    unique: list[str] = []
    for chunk in chunks:
        lowered = chunk.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        unique.append(chunk)
    return ", ".join(unique)


def dedupe_contacts(contacts: Sequence[Contact]) -> list[Contact]:
    """Remove duplicate points of contact, preserving order."""
    seen: set[tuple] = set()
    result: list[Contact] = []
    for contact in contacts:
        key = contact.key()
        if key in seen:
            continue
        seen.add(key)
        result.append(contact)
    return result
