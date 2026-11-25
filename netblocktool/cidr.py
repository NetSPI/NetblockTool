"""CIDR handling built on the standard library :mod:`ipaddress` module.

The original tool used ``netaddr`` plus a hand-rolled O(n^2) duplicate check
whose IPv4 sort key was ``socket.inet_aton(network.split('/')[1])`` - that is,
it sorted by *prefix length* interpreted as a dotted-quad. This module replaces
all of it with correct, tested logic and drops the third-party dependency.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Iterator, Sequence

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

#: Ranges that are never a company's public netblock. Reporting these as
#: "owned" is noise at best and misleading at worst.
_NON_PUBLIC_CHECKS = ("is_private", "is_loopback", "is_link_local",
                      "is_multicast", "is_reserved", "is_unspecified")


def parse_cidr(value: str | None) -> IPNetwork | None:
    """Parse a CIDR string into an :mod:`ipaddress` network.

    Accepts ``10.0.0.0/8``, a bare address (treated as a /32 or /128), and
    tolerates surrounding whitespace. Returns ``None`` for anything that is not
    a valid network rather than raising, because registry data is untrusted and
    frequently contains placeholder strings.
    """
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        # strict=False so that 10.0.0.5/24 is accepted and normalised to
        # 10.0.0.0/24 rather than raising on host bits being set.
        return ipaddress.ip_network(text, strict=False)
    except (ValueError, TypeError):
        return None


def range_to_cidrs(start: str, end: str) -> list[IPNetwork]:
    """Convert an inclusive start/end address pair into minimal CIDR blocks."""
    try:
        first = ipaddress.ip_address(str(start).strip())
        last = ipaddress.ip_address(str(end).strip())
    except (ValueError, TypeError):
        return []
    if first.version != last.version or int(first) > int(last):
        return []
    try:
        return list(ipaddress.summarize_address_range(first, last))
    except (ValueError, TypeError):
        return []


def ip_version(value: str | None) -> int | None:
    """Return 4, 6 or ``None`` for the given CIDR string."""
    network = parse_cidr(value)
    return network.version if network else None


def is_public(network: IPNetwork | str | None) -> bool:
    """True when the network is globally routable address space."""
    net = parse_cidr(network) if isinstance(network, str) or network is None else network
    if net is None:
        return False
    return not any(getattr(net, check, False) for check in _NON_PUBLIC_CHECKS)


def normalize_cidr(value: str | None) -> str | None:
    """Return the canonical string form of a CIDR, or ``None`` if invalid."""
    network = parse_cidr(value)
    return str(network) if network else None


def filter_by_version(cidrs: Iterable[str], version: int | None) -> list[str]:
    """Keep only CIDRs of the requested IP version.

    ``version=None`` keeps everything valid. Invalid entries are always dropped.
    """
    result: list[str] = []
    for item in cidrs:
        network = parse_cidr(item)
        if network is None:
            continue
        if version is None or network.version == version:
            result.append(str(network))
    return result


def dedupe_cidrs(cidrs: Iterable[str]) -> list[str]:
    """Remove exact duplicates, preserving first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in cidrs:
        normalized = normalize_cidr(item)
        if normalized is None or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def collapse_cidrs(cidrs: Iterable[str]) -> list[str]:
    """Merge adjacent and overlapping networks into the smallest equivalent set."""
    v4: list[ipaddress.IPv4Network] = []
    v6: list[ipaddress.IPv6Network] = []
    for item in cidrs:
        network = parse_cidr(item)
        if isinstance(network, ipaddress.IPv4Network):
            v4.append(network)
        elif isinstance(network, ipaddress.IPv6Network):
            v6.append(network)
    merged: list[str] = [str(n) for n in ipaddress.collapse_addresses(v4)]
    merged.extend(str(n) for n in ipaddress.collapse_addresses(v6))
    return merged


def find_subsumed(cidrs: Sequence[str]) -> set[str]:
    """Return the CIDRs that are fully contained inside another CIDR in the set.

    Runs in O(n log n) by sorting on (version, network address, prefix length)
    and sweeping, rather than the original O(n^2) pairwise comparison. A network
    equal to another is *not* reported here; exact duplicates are handled by
    :func:`dedupe_cidrs`.
    """
    parsed: list[tuple[IPNetwork, str]] = []
    for item in cidrs:
        network = parse_cidr(item)
        if network is not None:
            parsed.append((network, item))
    if not parsed:
        return set()

    # Sort so that any container always appears before the networks it covers.
    parsed.sort(key=lambda pair: (pair[0].version,
                                  int(pair[0].network_address),
                                  pair[0].prefixlen))

    subsumed: set[str] = set()
    # Stack of currently open containers (still covering the sweep position).
    stack: list[IPNetwork] = []
    for network, original in parsed:
        while stack and (stack[-1].version != network.version
                         or int(stack[-1].broadcast_address) < int(network.network_address)):
            stack.pop()
        for container in stack:
            if container.version == network.version and container.supernet_of(network) \
                    and container != network:
                subsumed.add(original)
                break
        stack.append(network)
    return subsumed


def count_addresses(cidrs: Iterable[str], version: int) -> int:
    """Total number of addresses covered by the non-overlapping union of CIDRs."""
    collapsed = collapse_cidrs(c for c in cidrs if ip_version(c) == version)
    total = 0
    for item in collapsed:
        network = parse_cidr(item)
        if network is not None:
            total += network.num_addresses
    return total


def iter_valid(cidrs: Iterable[str]) -> Iterator[str]:
    """Yield only the syntactically valid CIDRs from an iterable."""
    for item in cidrs:
        normalized = normalize_cidr(item)
        if normalized:
            yield normalized
