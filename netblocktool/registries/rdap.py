"""Generic RDAP client for the non-ARIN Regional Internet Registries.

RDAP (RFC 7480-7484, RFC 9082/9083) is the modern, standardised replacement for
port-43 WHOIS and every RIR serves it. Entity search by formatted name
(``/entities?fn=``) is an optional part of the standard, so support varies:

===========  ===========================================  =========================
Registry     Base URL                                     Entity search by name
===========  ===========================================  =========================
RIPE NCC     ``https://rdap.db.ripe.net``                 supported
APNIC        ``https://rdap.apnic.net``                   supported
AFRINIC      ``https://rdap.afrinic.net/rdap``            supported
LACNIC       ``https://rdap.lacnic.net/rdap``             usually rejected (501)
ARIN         ``https://rdap.arin.net/registry``           supported (see arin.py)
===========  ===========================================  =========================

When a registry declines entity search we record the reason and move on rather
than failing the run. Registries that do answer give us organisation records,
and where the response embeds ``networks`` we harvest CIDRs directly.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from ..cidr import normalize_cidr, range_to_cidrs
from ..http import HttpError
from ..logging_setup import get_logger
from ..models import Netblock, ObjectType, Organization
from .base import RegistryClient, RegistryResult, join_address

log = get_logger("rdap")

#: Registry identifier -> RDAP service base URL.
RDAP_ENDPOINTS: dict[str, str] = {
    "arin": "https://rdap.arin.net/registry",
    "ripe": "https://rdap.db.ripe.net",
    "apnic": "https://rdap.apnic.net",
    "afrinic": "https://rdap.afrinic.net/rdap",
    "lacnic": "https://rdap.lacnic.net/rdap",
}

#: Registries known not to implement ``/entities?fn=``. Queried anyway (cheaply)
#: but a failure is logged at debug level rather than as a warning.
NO_ENTITY_SEARCH = frozenset({"lacnic"})

#: Registries that reject wildcard ``fn`` patterns outright. RIPE answers
#: HTTP 500 to ``fn=Paypal*``, so sending it is a guaranteed wasted request.
#: These registries are queried with the plain name first.
NO_WILDCARD_SEARCH = frozenset({"ripe"})

MAX_ENTITIES = 100

#: RFC 7480 section 4.2 registers application/rdap+json as RDAP's media type.
#: LACNIC enforces this strictly and answers 406 to a plain application/json
#: Accept header; others are lenient. Send both, most specific first.
RDAP_ACCEPT = "application/rdap+json, application/json;q=0.9"


class RdapClient(RegistryClient):
    """Query one RIR's RDAP service."""

    def __init__(self, registry: str, client, config=None) -> None:
        super().__init__(client, config)
        self.name = registry
        self.base_url = RDAP_ENDPOINTS[registry]
        host = urlsplit(self.base_url).hostname or ""
        if host:
            self.client.set_host_rate(host, min(5.0, self.config.rate_limit))
        # RIPE's RDAP entity search does not embed a `networks` array, so
        # organisations it finds must be resolved through the RIPE database.
        self._ripe_db = None
        if registry == "ripe":
            from .ripe import RipeDbClient
            self._ripe_db = RipeDbClient(client)

    def search(self, query: str, *, fetch_pocs: bool = False) -> RegistryResult:
        """Search RDAP entities by formatted name.

        Wildcard handling varies: some servers answer 5xx rather than a clean
        error when a pattern is too broad, so a wildcard query that fails is
        retried once with the wildcards stripped before giving up.
        """
        result = RegistryResult(registry=self.name)
        payload = None
        stripped = query.replace("*", "").strip()
        if stripped and stripped != query:
            if self.name in NO_WILDCARD_SEARCH:
                # Known to reject wildcards; try the plain name first and keep
                # the wildcard form only as a fallback in case that changes.
                attempts = [stripped, query]
            else:
                attempts = [query, stripped]
        else:
            attempts = [query]

        for index, candidate in enumerate(attempts):
            try:
                payload = self._entity_request(candidate)
                break
            except HttpError as exc:
                is_last = index == len(attempts) - 1
                if not is_last:
                    log.debug("%s RDAP rejected %r (%s); trying %r",
                              self.name.upper(), candidate, exc, attempts[index + 1])
                    continue
                message = f"{self.name.upper()} RDAP entity search failed: {exc}"
                if self.name in NO_ENTITY_SEARCH:
                    log.debug(message)
                else:
                    log.warning(message)
                result.errors.append(message)
                return result

        if not isinstance(payload, dict):
            if payload is not None:
                result.errors.append(f"{self.name.upper()} RDAP returned unexpected JSON")
            return result

        entities = payload.get("entitySearchResults")
        if not isinstance(entities, list):
            log.debug("%s RDAP returned no entitySearchResults", self.name.upper())
            return result

        for entity in entities[:MAX_ENTITIES]:
            if not isinstance(entity, dict):
                continue
            organization = self._parse_entity(entity)
            if organization:
                result.organizations.append(organization)
            result.netblocks.extend(self._networks_from_entity(entity, organization))
            result.asns.extend(self._autnums_from_entity(entity))

        if self._ripe_db is not None and result.organizations and not result.netblocks:
            log.debug("RIPE RDAP embedded no networks; resolving %d organisation(s) "
                      "through the RIPE database", len(result.organizations))
            for organization in result.organizations:
                result.netblocks.extend(
                    self._ripe_db.netblocks_for_org(organization))

        log.debug("%s RDAP returned %d entities, %d netblocks",
                  self.name.upper(), len(result.organizations), len(result.netblocks))
        return result

    #: A 5xx from an entity *search* means the server rejected the query
    #: (RIPE answers 500 to wildcard `fn` patterns). Retrying is pointless and
    #: delays the wildcard-stripped fallback, so these are treated as final.
    SEARCH_FINAL_STATUS = frozenset({500, 501, 502, 503, 400, 422})

    def _entity_request(self, query: str) -> Any:
        """Issue one RDAP entity search. Raises HttpError on failure."""
        return self.client.get_json(
            f"{self.base_url}/entities",
            params={"fn": query},
            headers={"Accept": RDAP_ACCEPT},
            no_retry_status=self.SEARCH_FINAL_STATUS,
        )

    def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        """Look up a single IP's RDAP record. Used for country/address enrichment."""
        url = f"{self.base_url}/ip/{ip}"
        try:
            payload = self.client.get_json(url, headers={"Accept": RDAP_ACCEPT})
        except HttpError as exc:
            log.debug("%s RDAP IP lookup failed for %s: %s", self.name.upper(), ip, exc)
            return None
        return payload if isinstance(payload, dict) else None

    # -- parsing ----------------------------------------------------------

    def _parse_entity(self, entity: dict) -> Organization | None:
        handle = str(entity.get("handle") or "").strip()
        vcard = _parse_vcard(entity.get("vcardArray"))
        name = vcard.get("fn", "")
        if not handle and not name:
            return None
        address = vcard.get("adr", "")
        return Organization(
            handle=handle,
            name=name,
            registry=self.name,
            source_url=_self_link(entity) or f"{self.base_url}/entity/{handle}",
            address=address,
            country=vcard.get("country", ""),
            city=vcard.get("city", ""),
            state=vcard.get("state", ""),
        )

    def _networks_from_entity(self, entity: dict,
                              organization: Organization | None) -> list[Netblock]:
        netblocks: list[Netblock] = []
        for network in entity.get("networks") or []:
            if not isinstance(network, dict):
                continue
            netblocks.extend(self._parse_network(network, organization))
        return netblocks

    def _parse_network(self, network: dict,
                       organization: Organization | None) -> list[Netblock]:
        handle = str(network.get("handle") or "").strip()
        name = str(network.get("name") or "").strip()
        cidrs = _extract_cidrs(network)
        source = _self_link(network) or (f"{self.base_url}/ip/{handle}" if handle else "")
        results: list[Netblock] = []
        for cidr in cidrs:
            results.append(Netblock(
                cidr=cidr,
                name=name or (organization.name if organization else ""),
                handle=handle,
                object_type=ObjectType.NETWORK,
                registry=self.name,
                source_url=source,
                organization=organization.name if organization else "",
                address=organization.full_address() if organization else "",
                country=str(network.get("country") or "")
                or (organization.country if organization else ""),
            ))
        return results

    def _autnums_from_entity(self, entity: dict) -> list[str]:
        asns: list[str] = []
        for autnum in entity.get("autnums") or []:
            if not isinstance(autnum, dict):
                continue
            start = autnum.get("startAutnum")
            end = autnum.get("endAutnum", start)
            try:
                first, last = int(start), int(end)
            except (TypeError, ValueError):
                continue
            if last < first or last - first > 1024:
                last = first
            asns.extend(f"AS{number}" for number in range(first, last + 1))
        return asns


def _extract_cidrs(network: dict) -> list[str]:
    """Pull CIDRs out of an RDAP IP network object.

    RDAP gives ``startAddress``/``endAddress`` and, optionally, a
    ``cidr0_cidrs`` extension array. Prefer the explicit CIDR extension.
    """
    cidrs: list[str] = []
    for entry in network.get("cidr0_cidrs") or []:
        if not isinstance(entry, dict):
            continue
        prefix = entry.get("v4prefix") or entry.get("v6prefix")
        length = entry.get("length")
        if prefix is None or length is None:
            continue
        normalized = normalize_cidr(f"{prefix}/{length}")
        if normalized:
            cidrs.append(normalized)
    if cidrs:
        return cidrs

    start = network.get("startAddress")
    end = network.get("endAddress")
    if start and end:
        return [str(c) for c in range_to_cidrs(str(start), str(end))]
    if start:
        normalized = normalize_cidr(str(start))
        if normalized:
            return [normalized]
    return []


def _self_link(node: dict) -> str:
    """Return the ``self`` link from an RDAP object's links array."""
    for link in node.get("links") or []:
        if isinstance(link, dict) and link.get("rel") == "self":
            href = link.get("href")
            if isinstance(href, str) and href.startswith("http"):
                return href
    return ""


def _parse_vcard(vcard_array: Any) -> dict[str, str]:
    """Extract useful fields from an RDAP jCard (RFC 7095) structure.

    jCard is ``["vcard", [[name, params, type, value], ...]]``. The address
    entry's value is a seven-element array: PO box, extended, street, locality,
    region, postal code, country.
    """
    result: dict[str, str] = {}
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return result
    entries = vcard_array[1]
    if not isinstance(entries, list):
        return result

    for entry in entries:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        field, params, _kind, value = entry[0], entry[1], entry[2], entry[3]
        if field == "fn" and isinstance(value, str):
            result.setdefault("fn", value.strip())
        elif field == "adr":
            label = params.get("label") if isinstance(params, dict) else None
            if isinstance(label, str) and label.strip():
                result.setdefault("adr", ", ".join(
                    part.strip() for part in label.splitlines() if part.strip()))
            elif isinstance(value, list):
                parts = [str(p).strip() for p in value if isinstance(p, str) and p.strip()]
                if parts:
                    result.setdefault("adr", join_address(parts))
                # locality / region / country sit at fixed indices.
                if len(value) > 3 and isinstance(value[3], str):
                    result.setdefault("city", value[3].strip())
                if len(value) > 4 and isinstance(value[4], str):
                    result.setdefault("state", value[4].strip())
                if len(value) > 6 and isinstance(value[6], str):
                    result.setdefault("country", value[6].strip())
    return result


def build_rdap_clients(registries: Iterable[str], client, config) -> list[RdapClient]:
    """Instantiate RDAP clients for the requested registries."""
    clients: list[RdapClient] = []
    for registry in registries:
        key = registry.lower()
        if key == "arin":
            continue  # ARIN is served by the richer Whois-RWS client.
        if key not in RDAP_ENDPOINTS:
            log.warning("Unknown registry %r, skipping", registry)
            continue
        clients.append(RdapClient(key, client, config))
    return clients
