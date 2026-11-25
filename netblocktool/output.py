"""Result serialisation.

Two security problems in the original output path are fixed here.

**CSV formula injection.** Registry and filing data is attacker-influenceable:
anyone can register an ARIN customer object named ``=cmd|'/c calc'!A1``. Written
raw into a CSV, spreadsheet software may execute it on open. Every field that
begins with ``=``, ``+``, ``-``, ``@`` or a control character is now prefixed
with an apostrophe.

**Path traversal.** ``process_output_name`` used the character class
``[^\\w\\-_\\./ ]``, which explicitly *permits* ``/`` and ``.``, so
``-o ../../etc/cron.d/x`` wrote outside the working directory. Filenames are now
reduced to a single path component.
"""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterable, Sequence
from pathlib import Path

from .logging_setup import get_logger
from .models import Contact, Netblock, Subsidiary

log = get_logger("output")

#: Characters that make a spreadsheet treat a cell as a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")

#: Everything except word characters, dot, hyphen and space is replaced.
_UNSAFE_FILENAME = re.compile(r"[^\w\-. ]", re.UNICODE)

#: Windows reserved device names.
_RESERVED_NAMES = frozenset({
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
})

#: Default CSV schema.
CSV_HEADERS: tuple[str, ...] = (
    "company", "subsidiary", "cidr", "ip_version", "registry", "asn",
    "asn_holder", "organization", "confidence", "confidence_score",
    "subsumed", "evidence", "source",
    "address", "country", "city", "state", "poc", "discovered_at",
)

#: The pre-3.0 schema, available via ``--legacy-csv`` for existing consumers.
LEGACY_CSV_HEADERS: tuple[str, ...] = (
    "Network", "Name", "ID", "Type", "Confidence", "Score Rationale",
    "Resource URL",
)

CONTACT_HEADERS: tuple[str, ...] = (
    "Name", "Company", "Address", "Emails", "Phone Numbers", "Source",
)


def sanitize_filename(name: str, default: str = "netblocktool") -> str:
    """Reduce arbitrary text to a safe single-component filename.

    Strips directory separators, parent references, leading dots and reserved
    device names, so untrusted company names can never escape the output
    directory.
    """
    if not name:
        return default
    # Take the final component only: "../../etc/passwd" -> "passwd".
    candidate = str(name).replace("\\", "/").split("/")[-1]
    candidate = _UNSAFE_FILENAME.sub("_", candidate)
    candidate = candidate.replace(" ", "_").strip("._ ")
    candidate = re.sub(r"_{2,}", "_", candidate)
    if not candidate or set(candidate) <= {"_", "."}:
        return default
    if candidate.lower() in _RESERVED_NAMES or \
            candidate.split(".")[0].lower() in _RESERVED_NAMES:
        candidate = f"_{candidate}"
    return candidate[:120]


def resolve_output_path(name: str, extension: str, directory: Path | None = None) -> Path:
    """Build a safe output path with the given extension."""
    stem = sanitize_filename(Path(str(name)).stem or str(name))
    base = Path(directory) if directory else Path.cwd()
    suffix = extension if extension.startswith(".") else f".{extension}"
    return (base / f"{stem}{suffix}").resolve()


def escape_csv_value(value: object) -> str:
    """Neutralise spreadsheet formula injection in a single cell."""
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    if text.startswith(_FORMULA_PREFIXES):
        return f"'{text}"
    return text


def netblock_row(netblock: Netblock) -> list[str]:
    """Render a netblock as a row in the default schema."""
    return [escape_csv_value(value) for value in (
        netblock.company,
        netblock.subsidiary,
        netblock.cidr,
        netblock.ip_version if netblock.ip_version is not None else "",
        netblock.registry,
        netblock.asn,
        netblock.asn_holder,
        netblock.organization or netblock.name,
        str(netblock.confidence),
        netblock.score,
        "yes" if netblock.subsumed else "",
        netblock.evidence_text(),
        netblock.source_url,
        netblock.address,
        netblock.country,
        netblock.city,
        netblock.state,
        netblock.poc,
        netblock.discovered_at,
    )]


def legacy_netblock_row(netblock: Netblock, include_address: bool,
                        include_geolocation: bool) -> list[str]:
    """Render a netblock in the pre-3.0 column order."""
    row = [escape_csv_value(value) for value in (
        netblock.cidr,
        netblock.name,
        netblock.handle,
        str(netblock.object_type),
        netblock.score,
        netblock.evidence_text(),
        netblock.source_url,
    )]
    if include_address:
        row.append(escape_csv_value(netblock.address))
    if include_geolocation:
        row.append(escape_csv_value(netblock.geolocation))
    return row


def write_csv(netblocks: Sequence[Netblock], path: Path, *,
              legacy: bool = False, include_address: bool = False,
              include_geolocation: bool = False) -> Path:
    """Write netblocks to CSV. Returns the path actually written."""
    path.parent.mkdir(parents=True, exist_ok=True)

    if legacy:
        headers = list(LEGACY_CSV_HEADERS)
        if include_address:
            headers.append("Registered Address")
        if include_geolocation:
            headers.append("Geolocation Information")
        rows = [legacy_netblock_row(n, include_address, include_geolocation)
                for n in netblocks]
    else:
        headers = list(CSV_HEADERS)
        if include_geolocation:
            headers.append("geolocation")
        rows = []
        for netblock in netblocks:
            row = netblock_row(netblock)
            if include_geolocation:
                row.append(escape_csv_value(netblock.geolocation))
            rows.append(row)

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, delimiter=",", quoting=csv.QUOTE_MINIMAL,
                            lineterminator="\n")
        writer.writerow(headers)
        writer.writerows(rows)

    log.info("Wrote %d unique netblocks to %s", len(rows), path.name)
    return path


def write_json(netblocks: Sequence[Netblock], path: Path, *,
               metadata: dict | None = None) -> Path:
    """Write netblocks to a machine-readable JSON document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "metadata": metadata or {},
        "count": len(netblocks),
        "netblocks": [netblock.to_dict() for netblock in netblocks],
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    log.info("Wrote %d netblocks to %s", len(netblocks), path.name)
    return path


def write_contacts(contacts: Sequence[Contact], path: Path) -> Path | None:
    """Write points of contact to CSV, or do nothing if there are none."""
    if not contacts:
        log.debug("No point-of-contact data to write")
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, delimiter=",", quoting=csv.QUOTE_MINIMAL,
                            lineterminator="\n")
        writer.writerow(CONTACT_HEADERS)
        for contact in contacts:
            writer.writerow([escape_csv_value(value) for value in (
                contact.name, contact.company, contact.address,
                contact.emails, contact.phones, contact.source,
            )])
    log.info("Wrote %d points of contact to %s", len(contacts), path.name)
    return path


def write_subsidiaries(subsidiaries: Sequence[Subsidiary], path: Path) -> Path | None:
    """Write discovered subsidiary names, one per line."""
    if not subsidiaries:
        log.debug("No subsidiary data to write")
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for subsidiary in subsidiaries:
            handle.write(f"{subsidiary.name}\n")
    log.info("Wrote %d subsidiaries to %s", len(subsidiaries), path.name)
    return path


def summarize(netblocks: Iterable[Netblock]) -> dict[str, int]:
    """Count results by object type, IP version and confidence band."""
    from .cidr import count_addresses
    from .models import ObjectType

    items = list(netblocks)
    scored = [n for n in items if n.score > 0]
    counts = {
        "total": len(items),
        "scored": len(scored),
        # Count only ASNs not flagged as third-party origins, so an upstream
        # provider's AS is not reported as one of the company's.
        "asn": len({
            asn.strip()
            for n in items
            if n.asn and not any(e.code == "THIRD_PARTY_ORIGIN" for e in n.evidence)
            for asn in str(n.asn).split(",")
            if asn.strip()
        }),
        "asn_third_party": len({
            asn.strip()
            for n in items
            if n.asn and any(e.code == "THIRD_PARTY_ORIGIN" for e in n.evidence)
            for asn in str(n.asn).split(",")
            if asn.strip()
        }),
        "network": sum(1 for n in items if n.object_type is ObjectType.NETWORK),
        "customer": sum(1 for n in items if n.object_type is ObjectType.CUSTOMER),
        "contact": sum(1 for n in items if n.object_type is ObjectType.CONTACT),
        # Netblocks derived from an ASN's announced prefixes. Distinct from
        # "asn", which counts distinct AS numbers.
        "asn_records": sum(1 for n in items if n.object_type is ObjectType.ASN),
        "org_records": sum(1 for n in items if n.object_type is ObjectType.ORG),
        "subsumed": sum(1 for n in items if n.subsumed),
        "search": sum(1 for n in items if n.object_type is ObjectType.SEARCH),
        "ipv4_blocks": sum(1 for n in items if n.ip_version == 4),
        "ipv6_blocks": sum(1 for n in items if n.ip_version == 6),
        "ipv4_addresses": count_addresses((n.cidr for n in scored), 4),
        "ipv6_addresses": count_addresses((n.cidr for n in scored), 6),
    }
    for band in ("confirmed", "probable", "weak", "unlikely"):
        counts[band] = sum(1 for n in items if str(n.confidence) == band)
    return counts
