"""ARIN client built on the Whois-RWS REST API.

The original tool POSTed a form to ``https://whois.arin.net/ui/query.do`` and
regex-scraped ARIN resource URLs out of the returned HTML. That web UI was
retired and the endpoint no longer serves the results the regex expected, which
is the single biggest reason the tool stopped finding anything.

This client instead uses the documented, authoritative Whois-RWS endpoints:

* ``/rest/orgs;name=<q>``      - organisation name search
* ``/rest/customers;name=<q>`` - customer (reassignment) name search
* ``/rest/nets;name=<q>``      - network name search
* ``/rest/org/{handle}/nets``  - networks registered to an organisation
* ``/rest/org/{handle}/asns``  - ASNs registered to an organisation
* ``/rest/net/{handle}``       - full network record
* ``/rest/org/{handle}/pocs``  - points of contact

See https://www.arin.net/resources/registry/whois/rws/api/
"""

from __future__ import annotations

from urllib.parse import quote

from ..cidr import normalize_cidr, range_to_cidrs
from ..http import HttpError
from ..logging_setup import get_logger
from ..models import Contact, Netblock, ObjectType, Organization
from .base import (
    RegistryClient,
    RegistryResult,
    as_list,
    dedupe_contacts,
    dig,
    join_address,
    text_value,
)

log = get_logger("arin")


def _same_host_ref(url: str) -> str:
    """Accept a URL from an ARIN response only if it targets the same host.

    Registry responses are untrusted input; following an arbitrary embedded
    URL would let a malicious or compromised record redirect the tool at any
    host of its choosing.
    """
    if not url or not url.startswith(("http://", "https://")):
        return ""
    from urllib.parse import urlsplit

    if urlsplit(url).hostname == urlsplit(BASE_URL).hostname:
        return url
    log.debug("Ignoring off-host reference in ARIN response: %s", url)
    return ""

BASE_URL = "https://whois.arin.net/rest"
ARIN_HOST = "whois.arin.net"

#: ARIN caps name-search collections; requesting more just returns the cap.
MAX_SEARCH_RESULTS = 256


class ArinClient(RegistryClient):
    """Query ARIN's Whois-RWS REST API."""

    name = "arin"

    def __init__(self, client, config=None) -> None:
        super().__init__(client, config)
        # ARIN asks automated clients to be gentle; 8 req/s with retries is
        # comfortably inside their published tolerance.
        self.client.set_host_rate(ARIN_HOST, min(8.0, self.config.rate_limit))

    def supports_wildcards(self) -> bool:
        return True

    # -- public API -------------------------------------------------------

    def search(self, query: str, *, fetch_pocs: bool = False) -> RegistryResult:
        """Resolve a company name to ARIN organisations, netblocks and contacts."""
        result = RegistryResult(registry=self.name)
        encoded = quote(query, safe="*")

        organizations = self._search_orgs(encoded, result)
        result.organizations.extend(organizations)

        seen_nets: set[str] = set()
        budget = self.config.max_objects

        # 1. Networks and ASNs registered directly to each matching org. This
        #    is the strongest evidence ARIN can give us.
        for org in organizations:
            if budget <= 0:
                log.debug("Object budget exhausted; stopping ARIN org expansion")
                break
            for netblock in self._org_nets(org, result):
                if netblock.cidr in seen_nets:
                    continue
                seen_nets.add(netblock.cidr)
                result.netblocks.append(netblock)
                budget -= 1
            for asn in self._org_asns(org, result):
                if asn not in result.asns:
                    result.asns.append(asn)
            if fetch_pocs:
                result.contacts.extend(self._org_pocs(org, result))

        # 2. Customer records: downstream reassignments carrying the name.
        for netblock in self._search_customers(encoded, result):
            if netblock.cidr in seen_nets or budget <= 0:
                continue
            seen_nets.add(netblock.cidr)
            result.netblocks.append(netblock)
            budget -= 1

        # 3. Networks whose *network name* matches, even when the registrant
        #    org name does not (common for acquired address space).
        for netblock in self._search_nets(encoded, result):
            if netblock.cidr in seen_nets or budget <= 0:
                continue
            seen_nets.add(netblock.cidr)
            result.netblocks.append(netblock)
            budget -= 1

        result.contacts = dedupe_contacts(result.contacts)
        return result

    # -- searches ---------------------------------------------------------

    def _get(self, url: str, result: RegistryResult) -> dict | None:
        """GET JSON, recording failures instead of raising."""
        try:
            payload = self.client.get_json(url)
        except HttpError as exc:
            message = f"ARIN request failed: {exc}"
            log.warning(message)
            result.errors.append(message)
            return None
        if payload is None:
            return None
        if not isinstance(payload, dict):
            message = f"ARIN returned unexpected JSON shape for {url}"
            log.warning(message)
            result.errors.append(message)
            return None
        return payload

    def _search_orgs(self, encoded_query: str, result: RegistryResult) -> list[Organization]:
        url = f"{BASE_URL}/orgs;name={encoded_query}"
        payload = self._get(url, result)
        if not payload:
            return []
        organizations: list[Organization] = []
        for node in as_list(dig(payload, "orgs", "orgRef")):
            handle = text_value(node.get("@handle")) if isinstance(node, dict) else ""
            name = text_value(node.get("@name")) if isinstance(node, dict) else ""
            ref = text_value(node) if isinstance(node, dict) else ""
            if not handle:
                continue
            organizations.append(Organization(
                handle=handle,
                name=name,
                registry=self.name,
                source_url=ref or f"{BASE_URL}/org/{quote(handle, safe='')}",
            ))
        # Some responses embed full org objects rather than refs.
        for node in as_list(dig(payload, "orgs", "org")):
            org = self._parse_org(node)
            if org and all(existing.handle != org.handle for existing in organizations):
                organizations.append(org)

        log.debug("ARIN org search returned %d organisations", len(organizations))
        enriched: list[Organization] = []
        for org in organizations[:MAX_SEARCH_RESULTS]:
            enriched.append(self._org_detail(org, result))
        return enriched

    def _org_detail(self, org: Organization, result: RegistryResult) -> Organization:
        """Fetch the full org record to obtain its registered address."""
        url = f"{BASE_URL}/org/{quote(org.handle, safe='')}"
        payload = self._get(url, result)
        if not payload:
            return org
        parsed = self._parse_org(dig(payload, "org"))
        if parsed:
            parsed.name = parsed.name or org.name
            parsed.source_url = url
            return parsed
        return org

    def _parse_org(self, node) -> Organization | None:
        if not isinstance(node, dict):
            return None
        handle = text_value(node.get("handle"))
        if not handle:
            return None
        lines = [text_value(line) for line in as_list(dig(node, "streetAddress", "line"))]
        return Organization(
            handle=handle,
            name=text_value(node.get("name")),
            registry=self.name,
            address=join_address(lines),
            city=text_value(node.get("city")),
            state=text_value(node.get("iso3166-2")),
            country=text_value(dig(node, "iso3166-1", "name")),
            postal_code=text_value(node.get("postalCode")),
        )

    def _org_nets(self, org: Organization, result: RegistryResult) -> list[Netblock]:
        url = f"{BASE_URL}/org/{quote(org.handle, safe='')}/nets"
        payload = self._get(url, result)
        if not payload:
            return []
        netblocks: list[Netblock] = []
        for node in as_list(dig(payload, "nets", "netRef")):
            netblocks.extend(self._netblocks_from_ref(node, org))
        log.debug("Org %s (%s) yielded %d netblocks",
                  org.handle, org.name, len(netblocks))
        return netblocks

    def _netblocks_from_ref(self, node, org: Organization | None) -> list[Netblock]:
        """Build netblocks from a ``netRef`` element (start/end address pair)."""
        if not isinstance(node, dict):
            return []
        start = text_value(node.get("@startAddress"))
        end = text_value(node.get("@endAddress"))
        handle = text_value(node.get("@handle"))
        name = text_value(node.get("@name"))
        ref = text_value(node)
        cidrs = [str(c) for c in range_to_cidrs(start, end)] if start and end else []
        results: list[Netblock] = []
        for cidr in cidrs:
            results.append(Netblock(
                cidr=cidr,
                name=name,
                handle=handle,
                org_handle=org.handle if org else "",
                object_type=ObjectType.NETWORK,
                registry=self.name,
                source_url=ref or (f"{BASE_URL}/net/{quote(handle, safe='')}" if handle else ""),
                organization=org.name if org else "",
                address=org.full_address() if org else "",
                city=org.city if org else "",
                state=org.state if org else "",
                country=org.country if org else "",
            ))
        return results

    def _org_asns(self, org: Organization, result: RegistryResult) -> list[str]:
        url = f"{BASE_URL}/org/{quote(org.handle, safe='')}/asns"
        payload = self._get(url, result)
        if not payload:
            # ARIN answers 404 when an org holds no ASNs, which is normal and
            # not an error - but log it so "0 ASNs" is explainable.
            log.debug("No ASN records under org %s (%s)", org.handle, org.name)
            return []
        asns: list[str] = []
        refs = as_list(dig(payload, "asns", "asnRef"))
        if not refs:
            log.debug("ASN response for org %s contained no asnRef entries",
                      org.handle)
        for node in refs:
            if not isinstance(node, dict):
                continue
            start = text_value(node.get("@startAsNumber"))
            end = text_value(node.get("@endAsNumber")) or start
            if not start:
                continue
            try:
                first, last = int(start), int(end)
            except ValueError:
                continue
            # Guard against absurd ranges in malformed data.
            if last < first or last - first > 1024:
                last = first
            asns.extend(f"AS{number}" for number in range(first, last + 1))
        if asns:
            log.debug("Org %s holds ASNs: %s", org.handle, ", ".join(asns))
        return asns

    def _search_customers(self, encoded_query: str, result: RegistryResult) -> list[Netblock]:
        url = f"{BASE_URL}/customers;name={encoded_query}"
        payload = self._get(url, result)
        if not payload:
            return []
        netblocks: list[Netblock] = []
        refs = as_list(dig(payload, "customers", "customerRef"))
        requested = resolved = 0
        for node in refs[:MAX_SEARCH_RESULTS]:
            if not isinstance(node, dict):
                continue
            handle = text_value(node.get("@handle"))
            if not handle:
                continue
            requested += 1
            found = self._customer_detail(handle, result)
            if found:
                resolved += 1
            netblocks.extend(found)
        if requested:
            log.debug("ARIN customer search: %d/%d records resolved to netblocks",
                      resolved, requested)
            if resolved < requested:
                # Not necessarily an error - a customer object can legitimately
                # carry no network reference - but worth surfacing, because it
                # is also what a partial outage looks like.
                log.debug("%d ARIN customer record(s) yielded no network data",
                          requested - resolved)
        return netblocks

    def _customer_detail(self, handle: str, result: RegistryResult) -> list[Netblock]:
        url = f"{BASE_URL}/customer/{quote(handle, safe='')}"
        payload = self._get(url, result)
        node = dig(payload, "customer") if payload else None
        if not isinstance(node, dict):
            return []
        name = text_value(node.get("name"))
        lines = [text_value(line) for line in as_list(dig(node, "streetAddress", "line"))]
        city = text_value(node.get("city"))
        state = text_value(node.get("iso3166-2"))
        country = text_value(dig(node, "iso3166-1", "name"))
        address = join_address(lines, city, country, text_value(node.get("postalCode")))

        netblocks: list[Netblock] = []
        for ref in as_list(dig(node, "nets", "netRef")):
            if not isinstance(ref, dict):
                continue
            start = text_value(ref.get("@startAddress"))
            end = text_value(ref.get("@endAddress"))
            for cidr in range_to_cidrs(start, end):
                netblocks.append(Netblock(
                    cidr=str(cidr),
                    name=name,
                    handle=handle,
                    object_type=ObjectType.CUSTOMER,
                    registry=self.name,
                    source_url=url,
                    address=address,
                    city=city,
                    state=state,
                    country=country,
                ))
        if not netblocks:
            # Customer with no usable network data; still record the name so the
            # user can see the match rather than silently dropping it.
            log.debug("ARIN customer %s has no network references", handle)
        return netblocks

    def _search_nets(self, encoded_query: str, result: RegistryResult) -> list[Netblock]:
        url = f"{BASE_URL}/nets;name={encoded_query}"
        payload = self._get(url, result)
        if not payload:
            return []
        netblocks: list[Netblock] = []
        for node in as_list(dig(payload, "nets", "netRef"))[:MAX_SEARCH_RESULTS]:
            netblocks.extend(self._netblocks_from_ref(node, None))
        return netblocks

    # -- individual records ----------------------------------------------

    def net_detail(self, handle: str) -> list[Netblock]:
        """Fetch a single network record by handle. Used by search enrichment."""
        result = RegistryResult(registry=self.name)
        url = f"{BASE_URL}/net/{quote(handle, safe='')}"
        payload = self._get(url, result)
        node = dig(payload, "net") if payload else None
        if not isinstance(node, dict):
            return []
        name = text_value(node.get("name"))
        net_handle = text_value(node.get("handle")) or handle
        org_name = text_value(node.get("@name")) or text_value(dig(node, "orgRef", "@name"))
        netblocks: list[Netblock] = []
        for block in as_list(dig(node, "netBlocks", "netBlock")):
            if not isinstance(block, dict):
                continue
            start = text_value(block.get("startAddress"))
            length = text_value(block.get("cidrLength"))
            end = text_value(block.get("endAddress"))
            candidates: list[str] = []
            if start and length:
                normalized = normalize_cidr(f"{start}/{length}")
                if normalized:
                    candidates.append(normalized)
            if not candidates and start and end:
                candidates = [str(c) for c in range_to_cidrs(start, end)]
            for cidr in candidates:
                netblocks.append(Netblock(
                    cidr=cidr,
                    name=name,
                    handle=net_handle,
                    object_type=ObjectType.NETWORK,
                    registry=self.name,
                    source_url=url,
                    organization=org_name,
                ))
        return netblocks

    def _org_pocs(self, org: Organization, result: RegistryResult) -> list[Contact]:
        url = f"{BASE_URL}/org/{quote(org.handle, safe='')}/pocs"
        payload = self._get(url, result)
        if not payload:
            return []
        contacts: list[Contact] = []
        for node in as_list(dig(payload, "pocs", "pocLinkRef")):
            if not isinstance(node, dict):
                continue
            handle = text_value(node.get("@handle"))
            target = ""
            if handle:
                target = f"{BASE_URL}/poc/{quote(handle, safe='')}"
            else:
                target = _same_host_ref(text_value(node))
            if not target:
                continue
            contact = self._poc_detail(target, result)
            if contact:
                contacts.append(contact)
        if not contacts:
            log.debug("No point-of-contact records resolved for org %s", org.handle)
        return contacts

    def _poc_detail(self, url: str, result: RegistryResult) -> Contact | None:
        if not url.startswith("http"):
            return None
        payload = self._get(url, result)
        node = dig(payload, "poc") if payload else None
        if not isinstance(node, dict):
            return None
        first = text_value(node.get("firstName"))
        last = text_value(node.get("lastName"))
        name = " ".join(part for part in (first, last) if part)
        lines = [text_value(line) for line in as_list(dig(node, "streetAddress", "line"))]
        address = join_address(
            lines,
            text_value(node.get("city")),
            text_value(dig(node, "iso3166-1", "name")),
            text_value(node.get("postalCode")),
        )
        emails = ", ".join(
            value for value in (text_value(e) for e in as_list(dig(node, "emails", "email")))
            if value
        )
        phones = ", ".join(
            value for value in
            (text_value(dig(p, "number")) for p in as_list(dig(node, "phones", "phone")))
            if value
        )
        return Contact(
            name=name,
            company=text_value(node.get("companyName")),
            address=address,
            emails=emails,
            phones=phones,
            source=url,
        )
