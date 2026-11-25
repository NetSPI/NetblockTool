"""Core data structures.

The original tool passed around bare lists and addressed them by index
(``sub_list[4]``), then mutated them in place with ``del sub_list[3]``. That
made the data flow impossible to follow and was the source of several bugs.
Everything is now an explicit dataclass.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class ObjectType(str, enum.Enum):
    """What kind of registry object produced a candidate netblock."""

    NETWORK = "network"
    CUSTOMER = "customer"
    #: Found only because a matched person/role is an admin-c or tech-c
    #: contact. Materially weaker provenance than an org: reference.
    CONTACT = "contact"
    ASN = "asn"
    ORG = "org"
    SEARCH = "search"

    def __str__(self) -> str:
        return self.value


class Confidence(str, enum.Enum):
    """Human-readable ownership bands.

    These are deliberately conservative. ``CONFIRMED`` means an authoritative
    registry record names the target organisation; it never means the tool
    verified ownership by any other means.
    """

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    WEAK = "weak"
    UNLIKELY = "unlikely"

    def __str__(self) -> str:
        return self.value


@dataclass(slots=True, frozen=True)
class Evidence:
    """A single scored reason contributing to a confidence score."""

    code: str
    points: int
    detail: str = ""

    def render(self) -> str:
        sign = "+" if self.points >= 0 else ""
        base = f"{self.code}({sign}{self.points})"
        return f"{base}: {self.detail}" if self.detail else base


@dataclass(slots=True)
class Contact:
    """A registry point of contact."""

    name: str = ""
    company: str = ""
    address: str = ""
    emails: str = ""
    phones: str = ""
    source: str = ""

    def key(self) -> tuple:
        return (self.name, self.company, self.address, self.emails, self.phones)


@dataclass(slots=True)
class Netblock:
    """A candidate netblock plus everything known about it."""

    cidr: str
    name: str = ""
    handle: str = ""
    #: Handle of the organisation this network is registered to, when the
    #: record was reached via an org's /nets endpoint. Distinct from `handle`,
    #: which identifies the network object itself.
    org_handle: str = ""
    object_type: ObjectType = ObjectType.NETWORK
    registry: str = ""
    source_url: str = ""
    address: str = ""
    country: str = ""
    city: str = ""
    state: str = ""
    asn: str = ""
    #: Name of the entity holding the originating AS. When this does not match
    #: the company, the prefix is announced by a third party (typically the
    #: upstream provider of a reassignment) and the ASN is NOT the company's.
    asn_holder: str = ""
    organization: str = ""
    company: str = ""
    subsidiary: str = ""
    geolocation: str = ""
    poc: str = ""
    ip_version: int | None = None
    #: True when this network is fully contained inside another reported
    #: network. Purely structural: it says nothing about whether the company
    #: owns the block, so it must not be conflated with a low confidence score.
    subsumed: bool = False
    score: int = 0
    confidence: Confidence = Confidence.UNLIKELY
    evidence: list[Evidence] = field(default_factory=list)
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def evidence_text(self) -> str:
        """Flatten evidence into a single CSV-friendly string."""
        return "; ".join(item.render() for item in self.evidence)

    def dedupe_key(self) -> tuple[str, str]:
        """Identity used when collapsing duplicates across companies."""
        return (self.cidr, self.handle or self.name)

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output."""
        return {
            "company": self.company,
            "subsidiary": self.subsidiary,
            "cidr": self.cidr,
            "ip_version": self.ip_version,
            "registry": self.registry,
            "asn": self.asn,
            "asn_holder": self.asn_holder,
            "organization": self.organization or self.name,
            "name": self.name,
            "handle": self.handle,
            "type": str(self.object_type),
            "confidence": str(self.confidence),
            "confidence_score": self.score,
            "subsumed": self.subsumed,
            "evidence": [
                {"code": e.code, "points": e.points, "detail": e.detail} for e in self.evidence
            ],
            "source": self.source_url,
            "address": self.address,
            "country": self.country,
            "city": self.city,
            "state": self.state,
            "geolocation": self.geolocation,
            "poc": self.poc,
            "discovered_at": self.discovered_at,
        }


@dataclass(slots=True)
class Organization:
    """A registry organisation/entity record."""

    handle: str
    name: str
    registry: str
    source_url: str = ""
    address: str = ""
    city: str = ""
    state: str = ""
    country: str = ""
    postal_code: str = ""

    def full_address(self) -> str:
        parts = [p.strip() for p in (self.address, self.city, self.state, self.country,
                                     self.postal_code) if p and p.strip()]
        return ", ".join(parts)


@dataclass(slots=True)
class Subsidiary:
    """A subsidiary discovered from an SEC filing."""

    name: str
    parent: str
    source_url: str = ""
    jurisdiction: str = ""

    def normalized_key(self) -> str:
        from .normalize import normalize_company_name

        return normalize_company_name(self.name).lower()
