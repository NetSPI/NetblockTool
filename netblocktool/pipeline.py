"""End-to-end discovery pipeline.

::

    target company
        -> company/entity identification (registry org search)
        -> subsidiary discovery (SEC EDGAR, optional)
        -> per-company registry queries (ARIN + RDAP RIRs)
        -> ASN expansion (announced prefixes)
        -> search-engine enrichment (optional, best effort)
        -> CIDR normalisation, IP-version filter, deduplication
        -> confidence scoring with evidence
        -> CSV / JSON output

Every external source is optional. A failure in any one of them produces a
warning and the run continues with whatever the others returned.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .cidr import find_subsumed, normalize_cidr, parse_cidr
from .config import Config
from .edgar_client import EdgarClient
from .geo import GeoResolver
from .http import HttpClient
from .logging_setup import get_logger
from .models import Contact, Evidence, Netblock, ObjectType, Subsidiary
from .normalize import name_key, normalize_company_name
from .registries import build_clients, query_registries
from .registries.bgp import BgpClient
from .scoring import ScoringContext, address_frequency, mark_corroborated, score_all
from .search import SearchOutcome, get_provider
from .subsidiaries import discover_subsidiaries, merge_targets, subsidiary_keys

log = get_logger("pipeline")

#: How many organisation-registered prefixes to probe when the registry holds
#: no ASN records. A handful is enough to find a company's AS; probing every
#: netblock would be wasteful.
MAX_ASN_SEEDS = 8


@dataclass(slots=True)
class RunOptions:
    """Per-run switches, mostly mirroring the CLI flags."""

    target: str
    company_name: str | None = None
    query_mode: str = "prefix"       # "exact" (-n), "prefix" (default), "full" (-w)
    with_subsidiaries: bool = False
    subsidiary_name: str | None = None
    fetch_pocs: bool = False
    geolocation: bool = False
    threshold: int | None = None
    address_grep: str = ""
    include_address: bool = False
    exclude_subsumed: bool = False
    expand_asns: bool = True
    search_max_pages: int = 10

    def effective_company(self) -> str:
        return self.company_name or self.target


@dataclass(slots=True)
class RunResult:
    """Everything one run produced."""

    target: str
    netblocks: list[Netblock] = field(default_factory=list)
    contacts: list[Contact] = field(default_factory=list)
    subsidiaries: list[Subsidiary] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    search_outcome: SearchOutcome | None = None

    @property
    def ok(self) -> bool:
        return bool(self.netblocks)


def build_query(company: str, mode: str) -> str:
    """Construct the registry search string for a company name.

    ``exact``  -> ``Google``     (``-n``)
    ``prefix`` -> ``Google*``    (default)
    ``full``   -> ``*Google*``   (``-w``; many more false positives)
    """
    cleaned = " ".join(str(company).split()).strip()
    if not cleaned:
        return ""
    if mode == "exact":
        return cleaned
    if mode == "full":
        inner = cleaned.replace(" ", "*").replace("-", "*")
        while "**" in inner:
            inner = inner.replace("**", "*")
        return f"*{inner}*"
    return f"{cleaned}*"


class Pipeline:
    """Runs discovery for one or more companies against shared clients."""

    def __init__(self, config: Config, client: HttpClient | None = None) -> None:
        self.config = config
        self.client = client or HttpClient(config)
        self.registry_clients = build_clients(config.registries, self.client, config)
        self.bgp = BgpClient(self.client)
        self.search_provider = get_provider(config.search_provider, self.client, config)
        self.geo = GeoResolver(self.client)
        self._edgar: EdgarClient | None = None
        # Caches so repeated subsidiary names never trigger duplicate work.
        self._registry_cache: dict[str, list[Netblock]] = {}
        self._current_company: str = ""

    @property
    def edgar(self) -> EdgarClient:
        if self._edgar is None:
            self._edgar = EdgarClient(self.client, self.config)
        return self._edgar

    # -- public API -------------------------------------------------------

    def run(self, options: RunOptions) -> RunResult:
        """Execute the full pipeline for one target."""
        result = RunResult(target=options.target)
        company = options.effective_company()
        self._current_company = company

        subsidiaries: list[Subsidiary] = []
        if options.with_subsidiaries:
            subsidiary_target = options.subsidiary_name or options.target
            try:
                subsidiaries = discover_subsidiaries(self.edgar, subsidiary_target)
            except Exception as exc:
                message = f"SEC subsidiary discovery failed: {exc}"
                log.warning(message)
                result.errors.append(message)
            result.subsidiaries = subsidiaries

        targets = merge_targets(company, subsidiaries)
        log.info("Processing %d compan%s", len(targets),
                 "y" if len(targets) == 1 else "ies")

        all_netblocks: list[Netblock] = []
        all_contacts: list[Contact] = []
        sub_keys = subsidiary_keys(subsidiaries)

        for index, current in enumerate(targets, start=1):
            is_subsidiary = index > 1
            log.info("[%d/%d] %s", index, len(targets), current)
            netblocks, contacts, errors = self._collect_for_company(
                current, options, parent=company, is_subsidiary=is_subsidiary,
            )
            result.errors.extend(errors)
            all_contacts.extend(contacts)

            context = ScoringContext(
                company_name=current,
                org_handles=self._org_handles_for(current),
                address_frequency=address_frequency(
                    n.address for n in netblocks if n.address
                ),
                leading_wildcard=options.query_mode == "full",
                subsidiary_keys=sub_keys,
            )
            scored = score_all(netblocks, context)
            all_netblocks.extend(scored)

        # Search-engine enrichment runs once for the primary target only:
        # running it per subsidiary multiplies the chance of being blocked.
        outcome = self._search(company, options)
        result.search_outcome = outcome
        if outcome.netblocks:
            context = ScoringContext(company_name=company,
                                     leading_wildcard=options.query_mode == "full")
            for netblock in outcome.netblocks:
                netblock.company = company
            all_netblocks.extend(score_all(outcome.netblocks, context))

        # Corroboration must be computed BEFORE deduplication: afterwards there
        # is only one record per CIDR, so the "seen from multiple source types"
        # signal would be lost entirely.
        mark_corroborated(all_netblocks)
        deduped = self._deduplicate(all_netblocks)

        filtered = self._apply_filters(deduped, options)

        if options.expand_asns and filtered:
            self._annotate_origin_asns(filtered, result)

        if options.geolocation and filtered:
            try:
                self.geo.enrich(filtered, max_workers=self.config.max_workers)
            except Exception as exc:
                message = f"Geolocation enrichment failed: {exc}"
                log.warning(message)
                result.errors.append(message)

        if options.fetch_pocs:
            poc_by_handle = {c.company: c for c in all_contacts if c.company}
            for netblock in filtered:
                contact = poc_by_handle.get(netblock.organization)
                if contact:
                    netblock.poc = f"{contact.name} <{contact.emails}>".strip()

        filtered.sort(key=lambda n: (-n.score, n.ip_version or 0, n.cidr))
        result.netblocks = filtered
        result.contacts = _dedupe_contacts(all_contacts)
        return result

    # -- stages -----------------------------------------------------------

    def _collect_for_company(self, company: str, options: RunOptions,
                             parent: str, is_subsidiary: bool
                             ) -> tuple[list[Netblock], list[Contact], list[str]]:
        """Query every registry for one company name."""
        query = build_query(company, options.query_mode)
        if not query:
            return [], [], []

        cache_key = f"{query}|{options.fetch_pocs}"
        if cache_key in self._registry_cache:
            log.debug("Reusing cached registry results for %r", query)
            cached = [_clone_for_company(n, parent, company, is_subsidiary)
                      for n in self._registry_cache[cache_key]]
            return cached, [], []

        registry_result = query_registries(
            query,
            self.registry_clients,
            fetch_pocs=options.fetch_pocs,
            max_workers=self.config.max_workers,
        )

        netblocks = list(registry_result.netblocks)

        asns = list(registry_result.asns)
        if options.expand_asns and not asns:
            # The registry holds no ASN under a matching organisation. This is
            # common: a company's ASN is often registered to a former parent or
            # an acquiring entity. Ask BGP which AS actually originates the
            # netblocks we already found, and keep the ones the company holds.
            asns = self._discover_asns_from_prefixes(netblocks, company)

        if options.expand_asns and asns:
            log.info("Expanding %d ASN(s) into announced prefixes", len(asns))
            org_name = registry_result.organizations[0].name \
                if registry_result.organizations else company
            for asn in asns:
                netblocks.extend(self.bgp.netblocks_for_asn(
                    asn, org_name, registry=registry_result.registry,
                ))

        self._registry_cache[cache_key] = [
            _clone_for_company(n, "", "", False) for n in netblocks
        ]
        self._org_cache_store(company, registry_result)

        stamped = [_clone_for_company(n, parent, company, is_subsidiary)
                   for n in netblocks]
        log.info("Collected %d candidate netblocks for %r", len(stamped), company)
        return stamped, registry_result.contacts, registry_result.errors

    def _search(self, company: str, options: RunOptions) -> SearchOutcome:
        try:
            outcome = self.search_provider.find_netblocks(
                company, max_pages=options.search_max_pages,
            )
        except Exception as exc:
            log.warning("Search provider %s failed: %s",
                        self.search_provider.name, exc)
            return SearchOutcome(provider=self.search_provider.name, completed=True,
                                 diagnostics=[str(exc)])
        if outcome.blocked:
            log.info("Continuing with authoritative registry sources only")
        elif outcome.netblocks:
            log.info("Search provider %s contributed %d candidate netblocks",
                     outcome.provider, len(outcome.netblocks))
        return outcome

    def _discover_asns_from_prefixes(self, netblocks: list[Netblock],
                                     company: str) -> list[str]:
        """Find the company's own ASNs by asking who originates its prefixes.

        Only netblocks registered directly to a matched organisation are used
        as seeds - a reassignment is announced by its upstream provider, so
        seeding from one would discover the ISP's AS, not the company's. The
        AS holder name must also match the company.
        """
        eligible = [
            n for n in netblocks
            if n.object_type is ObjectType.NETWORK and n.org_handle
        ]
        seeds = _spread_seeds(eligible, MAX_ASN_SEEDS)
        if not seeds:
            return []

        organisations = {(n.registry, n.org_handle) for n in seeds}
        log.debug("No registry ASN records; probing %d prefix(es) across %d "
                  "organisation(s) for originating ASNs",
                  len(seeds), len(organisations))
        target = name_key(company)
        found: list[str] = []
        for seed in seeds:
            for asn, holder in self._safe_origin_asns(seed.cidr):
                if asn in found:
                    continue
                holder_key = name_key(holder)
                if not holder_key or not target:
                    continue
                if target in holder_key or holder_key in target:
                    found.append(asn)
        if found:
            log.info("Discovered %d ASN(s) held by %r via BGP origin data: %s",
                     len(found), company, ", ".join(found))
        else:
            log.debug("No company-held ASNs found in BGP origin data")
        return found

    def _annotate_origin_asns(self, netblocks: list[Netblock],
                              result: RunResult) -> None:
        """Fill in the originating ASN for netblocks that lack one.

        Only scored netblocks are looked up, and each distinct CIDR is queried
        at most once. Registry ASN records are often held by a former parent
        company, so BGP origin data is the reliable source.
        """
        candidates = [n for n in netblocks if n.score > 0 and not n.asn]
        if not candidates:
            return
        log.info("Resolving originating ASNs for %d netblocks", len(candidates))
        workers = max(1, min(self.config.max_workers, 8))
        try:
            with ThreadPoolExecutor(max_workers=workers,
                                    thread_name_prefix="asn") as executor:
                origins = list(executor.map(
                    self._safe_origin_asns, (n.cidr for n in candidates)))
        except Exception as exc:
            log.warning("Origin ASN lookup failed: %s", exc)
            result.errors.append(f"Origin ASN lookup failed: {exc}")
            return
        found = third_party = 0
        target_key = name_key(self._current_company or "")
        for netblock, asns in zip(candidates, origins, strict=False):
            if not asns:
                continue
            netblock.asn = ", ".join(asn for asn, _ in asns)
            holders = [h for _, h in asns if h]
            netblock.asn_holder = ", ".join(dict.fromkeys(holders))
            found += 1
            # An origin AS held by someone else means the prefix is announced
            # by a third party - normally the upstream provider of a
            # reassignment. Record that so the ASN is not read as the
            # company's own.
            if holders and target_key and not any(
                    target_key in name_key(h) or name_key(h) in target_key
                    for h in holders):
                third_party += 1
                netblock.evidence.append(Evidence(
                    "THIRD_PARTY_ORIGIN", 0,
                    f"announced by {netblock.asn_holder}, not the company",
                ))
        log.debug("Resolved originating ASNs for %d of %d netblocks "
                  "(%d announced by a third party)",
                  found, len(candidates), third_party)

    def _safe_origin_asns(self, cidr: str) -> list[str]:
        try:
            return self.bgp.origin_asns(cidr)
        except Exception as exc:
            log.debug("Origin ASN lookup failed for %s: %s", cidr, exc)
            return []

    def _deduplicate(self, netblocks: list[Netblock]) -> list[Netblock]:
        """Collapse duplicate CIDRs, keeping the highest-scoring record.

        A CIDR fully contained inside another retained CIDR is marked with a
        zero score and a ``SUBSUMED`` evidence entry rather than being dropped,
        preserving the original tool's behaviour of reporting everything it saw.
        """
        best: dict[str, Netblock] = {}
        for netblock in netblocks:
            cidr = normalize_cidr(netblock.cidr)
            if cidr is None:
                continue
            netblock.cidr = cidr
            existing = best.get(cidr)
            if existing is None or netblock.score > existing.score:
                if existing is not None:
                    # Preserve provenance from the record we are replacing.
                    netblock.subsidiary = netblock.subsidiary or existing.subsidiary
                best[cidr] = netblock

        retained = list(best.values())
        # Containment is recorded as a flag, not by zeroing the score. A
        # BGP-announced more-specific inside a registered allocation is still
        # the company's network - reporting it as "unlikely" was wrong, and it
        # hid genuine results among the discards. Address totals are unaffected
        # because count_addresses() collapses overlapping networks first.
        subsumed = find_subsumed([n.cidr for n in retained if n.score > 0])
        marked = 0
        for netblock in retained:
            if netblock.cidr in subsumed and netblock.score > 0:
                netblock.subsumed = True
                netblock.evidence.append(Evidence(
                    "SUBSUMED", 0, "contained within a larger reported network",
                ))
                marked += 1

        log.info("Deduplicated %d candidates to %d unique netblocks "
                 "(%d marked as contained in a larger block)",
                 len(netblocks), len(retained), marked)
        return retained

    def _apply_filters(self, netblocks: list[Netblock],
                       options: RunOptions) -> list[Netblock]:
        result = netblocks

        if self.config.ip_version is not None:
            before = len(result)
            result = [n for n in result
                      if (parse_cidr(n.cidr) or _NoVersion).version == self.config.ip_version]
            log.info("IPv%d filter kept %d of %d netblocks",
                     self.config.ip_version, len(result), before)

        if options.threshold is not None:
            before = len(result)
            result = [n for n in result if n.score >= options.threshold]
            log.info("Confidence threshold %d kept %d of %d netblocks",
                     options.threshold, len(result), before)

        if options.exclude_subsumed:
            before = len(result)
            result = [n for n in result if not n.subsumed]
            log.info("Excluding contained networks kept %d of %d netblocks",
                     len(result), before)

        if options.address_grep:
            needle = options.address_grep.lower()
            before = len(result)
            result = [n for n in result if needle in (n.address or "").lower()]
            log.info("Address filter %r kept %d of %d netblocks",
                     options.address_grep, len(result), before)

        return result

    # -- org handle bookkeeping ------------------------------------------

    def _org_cache_store(self, company: str, registry_result) -> None:
        handles = getattr(self, "_org_handles", None)
        if handles is None:
            handles = {}
            self._org_handles = handles  # type: ignore[attr-defined]
        key = name_key(company)
        target = normalize_company_name(company)
        matched = {
            org.handle for org in registry_result.organizations
            if org.handle and normalize_company_name(org.name) == target
        }
        handles.setdefault(key, set()).update(matched)

    def _org_handles_for(self, company: str) -> frozenset[str]:
        handles = getattr(self, "_org_handles", {})
        return frozenset(handles.get(name_key(company), set()))

    def close(self) -> None:
        self.client.close()


def _spread_seeds(netblocks: list[Netblock], limit: int) -> list[Netblock]:
    """Pick probe seeds spread across distinct organisations and registries.

    Taking the first N in list order concentrates every probe on whichever
    organisation happened to be returned first - typically the largest ARIN
    org, whose prefixes all originate from the same AS. A multinational's
    regional entities announce from different ASes, so those get missed
    entirely. Round-robin across organisations guarantees each one is probed
    at least once before any is probed twice.
    """
    if limit <= 0:
        return []
    groups: dict[tuple[str, str], list[Netblock]] = {}
    for netblock in netblocks:
        groups.setdefault((netblock.registry, netblock.org_handle), []).append(netblock)

    seeds: list[Netblock] = []
    round_index = 0
    while len(seeds) < limit:
        added = False
        for members in groups.values():
            if round_index < len(members):
                seeds.append(members[round_index])
                added = True
                if len(seeds) >= limit:
                    break
        if not added:
            break
        round_index += 1
    return seeds


class _NoVersion:
    version = None


def _clone_for_company(netblock: Netblock, company: str, subsidiary_name: str,
                       is_subsidiary: bool) -> Netblock:
    """Copy a netblock and stamp it with company/subsidiary provenance."""
    from dataclasses import replace

    clone = replace(netblock, evidence=list(netblock.evidence))
    clone.company = company or netblock.company
    if is_subsidiary:
        clone.subsidiary = subsidiary_name
    elif subsidiary_name and not company:
        clone.subsidiary = ""
    return clone


def _dedupe_contacts(contacts: list[Contact]) -> list[Contact]:
    seen: set[tuple] = set()
    result: list[Contact] = []
    for contact in contacts:
        key = contact.key()
        if key in seen:
            continue
        seen.add(key)
        result.append(contact)
    return result
