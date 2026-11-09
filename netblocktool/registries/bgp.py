"""ASN to announced-prefix expansion.

The original tool got an ASN's networks by fetching ``https://ipinfo.io/AS15169``
and scraping every ``<a>`` tag whose text contained the ASN. That page now
requires a token, its markup has changed, and the scrape returned nothing.

This module uses RIPEstat's ``announced-prefixes`` API instead: a public,
key-free, documented JSON endpoint backed by RIPE's global BGP collection. It
covers every RIR's address space, not just RIPE's, so it works for ARIN-region
ASNs too.

Note the semantic difference from a registry allocation: an announced prefix is
what an AS is *routing*, which may include address space allocated to someone
else (transit customers, leased space). Netblocks derived this way therefore
receive the lower ``BASE_ASN`` baseline in the scoring model.
"""

from __future__ import annotations

import re

from ..cidr import normalize_cidr
from ..http import HttpClient, HttpError
from ..logging_setup import get_logger
from ..models import Netblock, ObjectType

log = get_logger("bgp")

RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
RIPESTAT_PREFIX_OVERVIEW_URL = "https://stat.ripe.net/data/prefix-overview/data.json"
RIPESTAT_HOST = "stat.ripe.net"

_ASN_PATTERN = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)

#: A single AS announcing more than this is a transit provider, not a company
#: whose netblocks we can meaningfully attribute. Expanding it would flood the
#: output with third-party space.
MAX_PREFIXES_PER_ASN = 2000


def parse_asn(value: str) -> str | None:
    """Normalise ``15169``/``AS15169``/``as15169`` to ``AS15169``."""
    if not value:
        return None
    match = _ASN_PATTERN.match(str(value).strip())
    if not match:
        return None
    number = int(match.group(1))
    if number <= 0 or number > 4294967295:
        return None
    return f"AS{number}"


class BgpClient:
    """Expand ASNs into the prefixes they announce."""

    def __init__(self, client: HttpClient) -> None:
        self.client = client
        self.client.set_host_rate(RIPESTAT_HOST, min(4.0, client.config.rate_limit))
        self._cache: dict[str, list[str]] = {}
        self._origin_cache: dict[str, list[tuple[str, str]]] = {}

    def announced_prefixes(self, asn: str) -> list[str]:
        """Return the CIDRs currently announced by an ASN.

        Returns an empty list on any failure; callers continue without ASN data.
        """
        normalized = parse_asn(asn)
        if not normalized:
            log.debug("Ignoring malformed ASN %r", asn)
            return []
        if normalized in self._cache:
            return self._cache[normalized]

        try:
            payload = self.client.get_json(RIPESTAT_URL, params={"resource": normalized})
        except HttpError as exc:
            log.warning("BGP prefix lookup failed for %s: %s", normalized, exc)
            self._cache[normalized] = []
            return []

        prefixes = _extract_prefixes(payload)
        if len(prefixes) > MAX_PREFIXES_PER_ASN:
            log.warning(
                "%s announces %d prefixes (likely a transit provider); "
                "keeping the first %d", normalized, len(prefixes), MAX_PREFIXES_PER_ASN,
            )
            prefixes = prefixes[:MAX_PREFIXES_PER_ASN]

        log.debug("%s announces %d prefixes", normalized, len(prefixes))
        self._cache[normalized] = prefixes
        return prefixes

    def origin_asns(self, cidr: str) -> list[tuple[str, str]]:
        """Return the ASN(s) currently originating a prefix in BGP.

        Registry organisation records do not always hold a company's ASNs -
        they are frequently registered to a former parent or an acquiring
        entity. Asking which AS actually announces a discovered prefix finds
        them regardless of how the registry records ownership.

        Returns a list of ``(ASN, holder)`` pairs, or an empty list on any
        failure.
        """
        if not cidr:
            return []
        if cidr in self._origin_cache:
            return self._origin_cache[cidr]
        try:
            payload = self.client.get_json(RIPESTAT_PREFIX_OVERVIEW_URL,
                                           params={"resource": cidr})
        except HttpError as exc:
            log.debug("Origin ASN lookup failed for %s: %s", cidr, exc)
            self._origin_cache[cidr] = []
            return []
        asns = _extract_origin_asns(payload)
        self._origin_cache[cidr] = asns
        return asns

    def netblocks_for_asn(self, asn: str, organization: str,
                          registry: str = "") -> list[Netblock]:
        """Build :class:`Netblock` records for everything an ASN announces."""
        normalized = parse_asn(asn)
        if not normalized:
            return []
        source = f"{RIPESTAT_URL}?resource={normalized}"
        return [
            Netblock(
                cidr=cidr,
                name=organization,
                handle=normalized,
                object_type=ObjectType.ASN,
                registry=registry,
                asn=normalized,
                organization=organization,
                source_url=source,
            )
            for cidr in self.announced_prefixes(normalized)
        ]


def _extract_origin_asns(payload) -> list[tuple[str, str]]:
    """Pull (ASN, holder) pairs from a RIPEstat prefix-overview response.

    The holder matters: for a downstream reassignment the originating AS
    belongs to the *upstream provider*, not to the target company. Dropping it
    would present an ISP's ASN as though it were the company's.
    """
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, dict):
        return []
    entries = data.get("asns")
    if not isinstance(entries, list):
        return []
    asns: list[tuple[str, str]] = []
    seen: set[str] = set()
    for entry in entries:
        if isinstance(entry, dict):
            raw, holder = entry.get("asn"), entry.get("holder")
        else:
            raw, holder = entry, None
        normalized = parse_asn(str(raw)) if raw is not None else None
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        asns.append((normalized, str(holder or "").strip()))
    return asns


def _extract_prefixes(payload) -> list[str]:
    """Pull the prefix list out of a RIPEstat response, tolerating changes."""
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, dict):
        return []
    entries = data.get("prefixes")
    if not isinstance(entries, list):
        return []
    prefixes: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        raw = entry.get("prefix") if isinstance(entry, dict) else entry
        normalized = normalize_cidr(raw if isinstance(raw, str) else None)
        if normalized and normalized not in seen:
            seen.add(normalized)
            prefixes.append(normalized)
    return prefixes
