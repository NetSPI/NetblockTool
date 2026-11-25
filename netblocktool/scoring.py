"""Transparent, evidence-based confidence scoring.

The original scoring logic was a 130-line chain of nested conditionals with
magic constants applied by list index. This module replaces it with a flat,
additive model: every adjustment is a named :class:`~netblocktool.models.Evidence`
entry with a fixed weight, and the full list is written to the CSV so a reader
can audit exactly why a netblock scored what it did.

Scoring model
-------------

Each netblock starts at a baseline determined by the kind of registry object
that produced it, then accumulates evidence:

===================================  ======  ==========================================
Evidence code                        Points  Meaning
===================================  ======  ==========================================
``BASE_ORG_DIRECT``                    +45   Net registered directly to a matched org
``BASE_CUSTOMER``                      +35   ARIN customer (downstream reassignment)
``BASE_NETWORK``                       +30   Net record matched by name search
``BASE_ASN``                           +25   Prefix announced by a matched ASN
``BASE_CONTACT``                       +12   Matched person/role is an admin-c
                                             or tech-c contact only
``BASE_SEARCH``                        +10   Search-engine result only
``NAME_EXACT``                         +35   Normalised registry name == company name
``NAME_WITH_SUFFIX``                   +28   Matches company + a legal suffix
``NAME_PREFIX``                        +14   Registry name starts with the company name
``NAME_CONTAINS``                       +8   Company name appears inside registry name
``ORG_HANDLE_LINK``                    +20   Object is linked to the resolved org handle
``ASN_ORG_LINK``                       +15   ASN's org matches the company
``AUTHORITATIVE_REGISTRY``              +5   Data came from an RIR, not a search engine
``ADDRESS_MATCH``                    0..+15  Registered address matches the dominant
                                             address seen across the company's objects
``SUBSIDIARY_MATCH``                   +10   Attributed via a confirmed SEC subsidiary
``CORROBORATED``                        +8   Same CIDR seen from two independent sources
``NAME_MISMATCH``                      -40   Company name absent from the registry name
``ALPHA_SUFFIX``                       -10   Letters directly follow the company name
                                             (e.g. "GOOGLEFIBER" for target "Google")
``ALPHA_PREFIX``                       -10   Letters directly precede it (wildcard mode)
``CONFLICTING_ORG``                    -25   Registry names a different organisation
``NOT_PUBLIC``                         -100  Not globally routable address space
===================================  ======  ==========================================

The total is clamped to 0-99 (preserving the original scale) and mapped to a
band:

* ``confirmed`` >= 80 - an authoritative registry record names the company
* ``probable``  >= 55 - strong but indirect evidence
* ``weak``      >= 25 - a plausible association only
* ``unlikely``   < 25 - reported for completeness

``confirmed`` never means ownership was verified by any means beyond the
registry record itself. The tool does not fabricate ownership.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .cidr import is_public, parse_cidr
from .models import Confidence, Evidence, Netblock, ObjectType
from .normalize import name_key, name_variants, normalize_company_name

# -- weights ---------------------------------------------------------------

BASELINE: dict[str, int] = {
    "ORG_DIRECT": 45,
    "CUSTOMER": 35,
    "NETWORK": 30,
    "ASN": 25,
    "CONTACT": 12,
    "SEARCH": 10,
}

WEIGHTS: dict[str, int] = {
    "NAME_EXACT": 35,
    "NAME_WITH_SUFFIX": 28,
    "NAME_PREFIX": 14,
    "NAME_CONTAINS": 8,
    "ORG_HANDLE_LINK": 20,
    "ASN_ORG_LINK": 15,
    "AUTHORITATIVE_REGISTRY": 5,
    "SUBSIDIARY_MATCH": 10,
    "CORROBORATED": 8,
    "NAME_MISMATCH": -40,
    "ALPHA_SUFFIX": -10,
    "ALPHA_PREFIX": -10,
    "CONFLICTING_ORG": -25,
    "NOT_PUBLIC": -100,
}

MAX_ADDRESS_POINTS = 15

#: Score thresholds for each confidence band, highest first.
BANDS: tuple[tuple[int, Confidence], ...] = (
    (80, Confidence.CONFIRMED),
    (55, Confidence.PROBABLE),
    (25, Confidence.WEAK),
    (0, Confidence.UNLIKELY),
)

SCORE_MIN = 0
SCORE_MAX = 99


@dataclass(slots=True)
class ScoringContext:
    """Everything scoring needs beyond the netblock itself."""

    company_name: str
    #: Handles of registry organisations confidently resolved to the company.
    org_handles: frozenset[str] = frozenset()
    #: Address -> share of all addresses seen, from :func:`address_frequency`.
    address_frequency: dict[str, float] | None = None
    #: True when the search query used a leading wildcard.
    leading_wildcard: bool = False
    #: Names of confirmed subsidiaries, normalised.
    subsidiary_keys: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.address_frequency is None:
            self.address_frequency = {}


def address_frequency(addresses: Iterable[str]) -> dict[str, float]:
    """Map each address to the share of all observed addresses it represents.

    A netblock registered to the address that dominates a company's registry
    footprint is more likely to belong to that company.
    """
    cleaned = [a.strip() for a in addresses if a and a.strip()]
    if not cleaned:
        return {}
    counts = Counter(cleaned)
    total = float(len(cleaned))
    return {address: count / total for address, count in counts.items()}


def band_for_score(score: int) -> Confidence:
    """Map a numeric score onto a confidence band."""
    for threshold, band in BANDS:
        if score >= threshold:
            return band
    return Confidence.UNLIKELY


def _linked_handle(netblock: Netblock, context: ScoringContext) -> str:
    """Return the organisation handle linking this netblock to the company.

    Prefers ``org_handle`` (set when a record came from an organisation's
    /nets endpoint). Falls back to ``handle`` for registries whose entity and
    network handles share a namespace.
    """
    if netblock.org_handle and netblock.org_handle in context.org_handles:
        return netblock.org_handle
    if netblock.handle and netblock.handle in context.org_handles:
        return netblock.handle
    return ""


def _baseline(netblock: Netblock, context: ScoringContext) -> Evidence:
    """Pick the starting score based on how the netblock was discovered."""
    if netblock.object_type is ObjectType.ASN:
        return Evidence("BASE_ASN", BASELINE["ASN"], "prefix announced by matched ASN")
    if netblock.object_type is ObjectType.SEARCH:
        return Evidence("BASE_SEARCH", BASELINE["SEARCH"], "search-engine result only")
    if netblock.object_type is ObjectType.CUSTOMER:
        return Evidence("BASE_CUSTOMER", BASELINE["CUSTOMER"], "registry customer record")
    if netblock.object_type is ObjectType.CONTACT:
        return Evidence("BASE_CONTACT", BASELINE["CONTACT"],
                        "matched person/role is a registry contact for this network")
    if _linked_handle(netblock, context):
        return Evidence("BASE_ORG_DIRECT", BASELINE["ORG_DIRECT"],
                        "registered directly to matched organisation")
    if netblock.organization and name_key(netblock.organization) == name_key(context.company_name):
        return Evidence("BASE_ORG_DIRECT", BASELINE["ORG_DIRECT"],
                        "registry organisation matches company")
    return Evidence("BASE_NETWORK", BASELINE["NETWORK"], "registry network record")


def _name_evidence(registry_name: str, company_name: str,
                   leading_wildcard: bool) -> list[Evidence]:
    """Score how closely the registry's name matches the target company."""
    evidence: list[Evidence] = []
    target = normalize_company_name(company_name)
    candidate = normalize_company_name(registry_name)

    if not target:
        return evidence
    if not candidate:
        evidence.append(Evidence("NAME_MISMATCH", WEIGHTS["NAME_MISMATCH"],
                                 "registry record has no usable name"))
        return evidence

    if candidate == target:
        evidence.append(Evidence("NAME_EXACT", WEIGHTS["NAME_EXACT"],
                                 f"'{registry_name}' normalises to '{target}'"))
        return evidence

    if candidate in name_variants(company_name):
        evidence.append(Evidence("NAME_WITH_SUFFIX", WEIGHTS["NAME_WITH_SUFFIX"],
                                 f"'{registry_name}' is company name plus legal suffix"))
        return evidence

    if target not in candidate:
        evidence.append(Evidence("NAME_MISMATCH", WEIGHTS["NAME_MISMATCH"],
                                 f"'{registry_name}' does not contain '{target}'"))
        return evidence

    # The company name appears, but is not the whole name.
    if candidate.startswith(target):
        evidence.append(Evidence("NAME_PREFIX", WEIGHTS["NAME_PREFIX"],
                                 f"'{registry_name}' begins with the company name"))
    else:
        evidence.append(Evidence("NAME_CONTAINS", WEIGHTS["NAME_CONTAINS"],
                                 f"company name appears within '{registry_name}'"))

    # "GOOGLEFIBER" is a weaker signal than "GOOGLE FIBER": glued-on letters
    # often indicate an unrelated organisation that merely shares a substring.
    squashed_target = target.replace(" ", "")
    squashed_candidate = candidate.replace(" ", "")
    index = squashed_candidate.find(squashed_target)
    if index >= 0:
        after = squashed_candidate[index + len(squashed_target):]
        before = squashed_candidate[:index]
        joined_after = candidate.find(target) >= 0 and \
            len(candidate) > candidate.find(target) + len(target) and \
            candidate[candidate.find(target) + len(target)].isalpha()
        if after[:1].isalpha() and joined_after:
            evidence.append(Evidence("ALPHA_SUFFIX", WEIGHTS["ALPHA_SUFFIX"],
                                     "letters immediately follow the company name"))
        if leading_wildcard and before[-1:].isalpha():
            evidence.append(Evidence("ALPHA_PREFIX", WEIGHTS["ALPHA_PREFIX"],
                                     "letters immediately precede the company name"))
    return evidence


def score_netblock(netblock: Netblock, context: ScoringContext) -> Netblock:
    """Score one netblock in place and return it.

    Populates ``score``, ``confidence`` and ``evidence``.
    """
    evidence: list[Evidence] = [_baseline(netblock, context)]

    evidence.extend(_name_evidence(
        netblock.name or netblock.organization,
        context.company_name,
        context.leading_wildcard,
    ))

    linked = _linked_handle(netblock, context)
    if linked:
        evidence.append(Evidence("ORG_HANDLE_LINK", WEIGHTS["ORG_HANDLE_LINK"],
                                 f"linked to organisation handle {linked}"))

    if (netblock.object_type is ObjectType.ASN and netblock.organization
            and name_key(netblock.organization) == name_key(context.company_name)):
        evidence.append(Evidence("ASN_ORG_LINK", WEIGHTS["ASN_ORG_LINK"],
                                 f"{netblock.asn or 'ASN'} registered to the company"))

    if netblock.registry and netblock.object_type is not ObjectType.SEARCH:
        evidence.append(Evidence("AUTHORITATIVE_REGISTRY",
                                 WEIGHTS["AUTHORITATIVE_REGISTRY"],
                                 f"sourced from {netblock.registry.upper()}"))

    if netblock.subsidiary and \
            name_key(netblock.subsidiary) in context.subsidiary_keys:
        evidence.append(Evidence("SUBSIDIARY_MATCH", WEIGHTS["SUBSIDIARY_MATCH"],
                                 f"attributed via subsidiary '{netblock.subsidiary}'"))

    # Address corroboration, scaled by how dominant the address is.
    frequency = (context.address_frequency or {}).get(netblock.address.strip(), 0.0) \
        if netblock.address else 0.0
    if frequency > 0:
        points = round(MAX_ADDRESS_POINTS * frequency)
        if points > 0:
            evidence.append(Evidence("ADDRESS_MATCH", points,
                                     f"address seen on {frequency:.0%} of the company's "
                                     f"registry objects"))

    # Conflicting ownership: the registry names an organisation that is not the
    # company and does not contain it.
    if netblock.organization and netblock.name:
        org_key = name_key(netblock.organization)
        target_key = name_key(context.company_name)
        if org_key and target_key and target_key not in org_key and org_key not in target_key:
            evidence.append(Evidence("CONFLICTING_ORG", WEIGHTS["CONFLICTING_ORG"],
                                     f"registry organisation is '{netblock.organization}'"))

    network = parse_cidr(netblock.cidr)
    if network is None:
        netblock.score = SCORE_MIN
        netblock.confidence = Confidence.UNLIKELY
        netblock.evidence = [Evidence("NO_CIDR", 0, "no valid network information")]
        return netblock
    if not is_public(network):
        evidence.append(Evidence("NOT_PUBLIC", WEIGHTS["NOT_PUBLIC"],
                                 "not globally routable address space"))

    total = sum(item.points for item in evidence)
    clamped = max(SCORE_MIN, min(SCORE_MAX, total))
    if clamped != total:
        evidence.append(Evidence("CLAMPED", 0, f"raw score {total} clamped to {clamped}"))

    netblock.score = clamped
    netblock.confidence = band_for_score(clamped)
    netblock.evidence = evidence
    netblock.ip_version = network.version
    return netblock


def score_all(netblocks: Sequence[Netblock], context: ScoringContext) -> list[Netblock]:
    """Score a batch of netblocks and return them sorted by descending score."""
    scored = [score_netblock(netblock, context) for netblock in netblocks]
    scored.sort(key=lambda n: (-n.score, n.cidr))
    return scored


def mark_corroborated(netblocks: Sequence[Netblock]) -> None:
    """Boost CIDRs independently reported by more than one source type."""
    by_cidr: dict[str, set[str]] = {}
    for netblock in netblocks:
        by_cidr.setdefault(netblock.cidr, set()).add(str(netblock.object_type))
    for netblock in netblocks:
        if len(by_cidr.get(netblock.cidr, ())) > 1 and netblock.score > 0:
            already = any(item.code == "CORROBORATED" for item in netblock.evidence)
            if already:
                continue
            netblock.evidence.append(Evidence(
                "CORROBORATED", WEIGHTS["CORROBORATED"],
                "same CIDR reported by multiple source types",
            ))
            netblock.score = max(SCORE_MIN, min(SCORE_MAX,
                                                netblock.score + WEIGHTS["CORROBORATED"]))
            netblock.confidence = band_for_score(netblock.score)
