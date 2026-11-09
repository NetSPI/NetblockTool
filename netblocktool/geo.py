"""Geolocation and address enrichment.

The original tool scraped ``https://ipinfo.io/<ip>`` with the XPath
``//*[@id="content"]/section[1]/div/div[1]/div/div[1]/div/ul/li[4]/span[2]``,
which has not matched that page's markup for years and silently returned an
empty string for every netblock.

Two replacements are used, in order of authority:

1. **RDAP** (``/ip/<address>``) - the registry's own record. Authoritative for
   country and registered address, available from every RIR, no key required.
2. **ipinfo.io's JSON endpoint** (``/<ip>/json``) - approximate coordinates and
   city. Free without a token but rate limited; failures are non-fatal.

Geolocation of an IP range is inherently approximate. It reflects where the
address space is *registered or announced*, not where any host physically is.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .cidr import parse_cidr
from .http import HttpClient, HttpError
from .logging_setup import get_logger
from .models import Netblock
from .registries.rdap import RDAP_ENDPOINTS, RdapClient

log = get_logger("geo")

IPINFO_URL = "https://ipinfo.io/{ip}/json"
IPINFO_HOST = "ipinfo.io"


@dataclass(slots=True)
class GeoInfo:
    """Location facts about a netblock."""

    country: str = ""
    city: str = ""
    state: str = ""
    coordinates: str = ""

    def is_empty(self) -> bool:
        return not any((self.country, self.city, self.state, self.coordinates))

    def render(self) -> str:
        parts = [p for p in (self.city, self.state, self.country) if p]
        location = ", ".join(parts)
        if self.coordinates and location:
            return f"{location} ({self.coordinates})"
        return self.coordinates or location


class GeoResolver:
    """Resolve location information for netblocks."""

    def __init__(self, client: HttpClient) -> None:
        self.client = client
        self.client.set_host_rate(IPINFO_HOST, 2.0)
        self._cache: dict[str, GeoInfo] = {}
        self._rdap = RdapClient("arin", client) if "arin" in RDAP_ENDPOINTS else None

    def resolve(self, cidr: str) -> GeoInfo:
        """Look up one netblock's location. Never raises."""
        network = parse_cidr(cidr)
        if network is None:
            return GeoInfo()
        # Query the first usable address in the range.
        ip = str(network.network_address)
        if ip in self._cache:
            return self._cache[ip]

        info = self._from_ipinfo(ip)
        if info.is_empty():
            info = self._from_rdap(ip)
        self._cache[ip] = info
        return info

    def enrich(self, netblocks: list[Netblock], max_workers: int = 4) -> list[Netblock]:
        """Attach location data to a list of netblocks, concurrently."""
        if not netblocks:
            return netblocks
        log.info("Retrieving geolocation data for %d netblocks", len(netblocks))
        workers = max(1, min(max_workers, 8))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="geo") as executor:
            infos = list(executor.map(self._safe_resolve, (n.cidr for n in netblocks)))
        for netblock, info in zip(netblocks, infos, strict=False):
            netblock.geolocation = info.render()
            netblock.country = netblock.country or info.country
            netblock.city = netblock.city or info.city
            netblock.state = netblock.state or info.state
        return netblocks

    def _safe_resolve(self, cidr: str) -> GeoInfo:
        try:
            return self.resolve(cidr)
        except Exception as exc:
            log.debug("Geolocation failed for %s: %s", cidr, exc)
            return GeoInfo()

    # -- backends ---------------------------------------------------------

    def _from_ipinfo(self, ip: str) -> GeoInfo:
        try:
            payload = self.client.get_json(IPINFO_URL.format(ip=ip))
        except HttpError as exc:
            log.debug("ipinfo lookup failed for %s: %s", ip, exc)
            return GeoInfo()
        if not isinstance(payload, dict):
            return GeoInfo()
        # The free tier returns {"error": ...} once the quota is exhausted.
        if payload.get("error") or payload.get("bogon"):
            return GeoInfo()
        return GeoInfo(
            country=str(payload.get("country") or ""),
            city=str(payload.get("city") or ""),
            state=str(payload.get("region") or ""),
            coordinates=str(payload.get("loc") or ""),
        )

    def _from_rdap(self, ip: str) -> GeoInfo:
        if self._rdap is None:
            return GeoInfo()
        payload = self._rdap.lookup_ip(ip)
        if not isinstance(payload, dict):
            return GeoInfo()
        return GeoInfo(country=str(payload.get("country") or ""))
