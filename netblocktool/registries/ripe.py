"""RIPE NCC database client.

RIPE's RDAP entity search finds organisations but, unlike ARIN's, does **not**
embed a ``networks`` array in the results. A RIPE-region company therefore
resolved to an organisation and then produced zero netblocks.

This module closes that gap using the RIPE database REST API's *inverse*
lookup: given an organisation handle such as ``ORG-PP1-RIPE``, ask for every
``inetnum``/``inet6num`` object whose ``org:`` attribute references it.

    https://rest.db.ripe.net/search.json
        ?query-string=ORG-PP1-RIPE
        &inverse-attribute=org
        &type-filter=inetnum&type-filter=inet6num

The API is public, requires no key, and is documented at
https://docs.db.ripe.net/Data-Access/RESTful-API/ .
"""

from __future__ import annotations

from ..cidr import normalize_cidr, range_to_cidrs
from ..http import HttpClient, HttpError
from ..logging_setup import get_logger
from ..models import Netblock, ObjectType, Organization

log = get_logger("ripe")

SEARCH_URL = "https://rest.db.ripe.net/search.json"
RIPE_DB_HOST = "rest.db.ripe.net"

#: Guard against an organisation with an implausible number of allocations.
MAX_OBJECTS_PER_ORG = 500

#: RIPE organisation handles are of the form ORG-XXXn-RIPE. Anything else
#: returned by an entity search is a person (PA9687-RIPE) or role
#: (PN4269-RIPE) object. An `org:` inverse lookup can never match those, which
#: is why they previously yielded nothing.
_ORG_HANDLE_PREFIX = "ORG-"

#: For person/role handles the meaningful inverse attributes are the contact
#: fields. This is weaker evidence than an `org:` reference - a single person
#: may be the contact for unrelated networks - so results are capped tightly
#: and scored through the normal name-matching path.
_CONTACT_ATTRIBUTES = ("admin-c", "tech-c")
MAX_OBJECTS_PER_CONTACT = 50


class RipeDbClient:
    """Resolve RIPE organisation handles into the netblocks they hold."""

    def __init__(self, client: HttpClient) -> None:
        self.client = client
        self.client.set_host_rate(RIPE_DB_HOST, min(4.0, client.config.rate_limit))
        self._cache: dict[str, list[Netblock]] = {}

    def netblocks_for_org(self, org: Organization) -> list[Netblock]:
        """Return every inetnum/inet6num referencing this entity.

        Organisation handles are resolved through the ``org:`` attribute.
        Person and role handles - which RIPE's entity search also returns -
        are resolved through the contact attributes instead, since an ``org:``
        inverse lookup can never match them.

        Returns an empty list on any failure; the caller continues without
        RIPE netblock data.
        """
        handle = (org.handle or "").strip()
        if not handle:
            return []
        if handle in self._cache:
            return self._cache[handle]

        is_org = handle.upper().startswith(_ORG_HANDLE_PREFIX)
        attributes = ["org"] if is_org else list(_CONTACT_ATTRIBUTES)
        limit = MAX_OBJECTS_PER_ORG if is_org else MAX_OBJECTS_PER_CONTACT
        if not is_org:
            log.debug("RIPE handle %s is a person/role object; using %s inverse "
                      "lookup instead of org", handle, "/".join(attributes))

        netblocks: list[Netblock] = []
        seen: set[str] = set()
        # inetnum and inet6num are requested separately: RIPE treats repeated
        # type-filter values as a union that changes the result set.
        for object_type in ("inetnum", "inet6num"):
            for found in self._search(handle, attributes, object_type, org,
                                      is_org=is_org):
                if found.cidr in seen:
                    continue
                seen.add(found.cidr)
                netblocks.append(found)

        if len(netblocks) > limit:
            log.warning("RIPE handle %s references %d networks; keeping the first %d",
                        handle, len(netblocks), limit)
            netblocks = netblocks[:limit]

        log.debug("RIPE %s %s (%s) yielded %d netblocks",
                  "org" if is_org else "contact", handle, org.name, len(netblocks))
        self._cache[handle] = netblocks
        return netblocks

    def _search(self, handle: str, inverse_attributes: list[str],
                object_type: str, org: Organization,
                is_org: bool = True) -> list[Netblock]:
        """One inverse-lookup request. Returns [] on any failure."""
        try:
            payload = self.client.get_json(SEARCH_URL, params={
                "query-string": handle,
                # requests serialises a list as repeated query parameters,
                # which is how RIPE expects multiple inverse attributes.
                "inverse-attribute": inverse_attributes,
                "type-filter": object_type,
                "flags": "no-referenced",
            })
        except HttpError as exc:
            log.debug("RIPE %s lookup failed for %s: %s", object_type, handle, exc)
            return []
        return _parse_objects(payload, org, is_org=is_org)


def _parse_objects(payload, org: Organization,
                   is_org: bool = True) -> list[Netblock]:
    """Extract netblocks from a RIPE database search response."""
    if not isinstance(payload, dict):
        return []
    objects = payload.get("objects")
    if not isinstance(objects, dict):
        return []
    entries = objects.get("object")
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list):
        return []

    results: list[Netblock] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        obj_type = str(entry.get("type") or "")
        if obj_type not in ("inetnum", "inet6num"):
            continue
        attributes = _attributes(entry)
        raw_range = _primary_key(entry, obj_type) or attributes.get(obj_type, "")
        for cidr in _range_to_cidrs(raw_range):
            results.append(Netblock(
                cidr=cidr,
                name=attributes.get("netname", "") or org.name,
                handle=raw_range,
                object_type=ObjectType.NETWORK if is_org else ObjectType.CONTACT,
                registry="ripe",
                # Only an org: reference proves registration; a contact
                # reference does not, so do not claim the org handle.
                org_handle=org.handle if is_org else "",
                source_url=f"https://rest.db.ripe.net/ripe/{obj_type}/{raw_range}",
                organization=org.name,
                address=org.full_address(),
                country=attributes.get("country", "") or org.country,
            ))
    return results


def _attributes(entry: dict) -> dict[str, str]:
    """Flatten a RIPE object's attribute list into a dict (first value wins)."""
    block = entry.get("attributes")
    if not isinstance(block, dict):
        return {}
    items = block.get("attribute")
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        return {}
    flat: dict[str, str] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        value = item.get("value")
        if name and isinstance(value, str) and name not in flat:
            flat[name] = value.strip()
    return flat


def _primary_key(entry: dict, obj_type: str) -> str:
    """Read the object's primary key, e.g. ``193.0.0.0 - 193.0.7.255``."""
    block = entry.get("primary-key")
    if not isinstance(block, dict):
        return ""
    items = block.get("attribute")
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        return ""
    for item in items:
        if isinstance(item, dict) and str(item.get("name") or "") == obj_type:
            value = item.get("value")
            if isinstance(value, str):
                return value.strip()
    return ""


def _range_to_cidrs(raw: str) -> list[str]:
    """Convert a RIPE range string into CIDRs.

    ``inetnum`` uses ``start - end``; ``inet6num`` is already a prefix.
    """
    if not raw:
        return []
    text = raw.strip()
    if "-" in text and "/" not in text:
        start, _, end = text.partition("-")
        return [str(c) for c in range_to_cidrs(start.strip(), end.strip())]
    normalized = normalize_cidr(text)
    return [normalized] if normalized else []
