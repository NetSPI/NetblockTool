"""Subsidiary discovery from SEC Exhibit 21 filings.

Exhibit 21 ("Subsidiaries of the Registrant") is usually a two- or three-column
table: company name, jurisdiction of incorporation, and sometimes ownership
percentage. Modern filings are HTML tables; older ones are pre-formatted text.

The original code tried to guess which HTML tag held the data by counting tag
frequency and assuming ``<font>``, then ran candidate strings through a
40-branch nested conditional. This module parses tables structurally - work out
which column holds names by testing whether the *other* columns look like
jurisdictions or percentages - and falls back to line parsing for text filings.

Not every company files a machine-readable Exhibit 21. Some file on paper, some
are subsidiaries themselves and file nothing, and some list subsidiaries in
prose. All of those cases return an empty list, which is not an error.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from bs4 import BeautifulSoup

from .edgar_client import EdgarClient, EdgarCompany
from .logging_setup import get_logger
from .models import Subsidiary
from .normalize import dedupe_names, is_jurisdiction, name_key, normalize_company_name

log = get_logger("subsidiaries")

#: Header and boilerplate text that is never a company name.
_BOILERPLATE = (
    "exhibit 21", "ex-21", "ex-2101", "ex 21", "jurisdiction", "legal name",
    "registrant", "percent owned", "percentage of", "percentage owned",
    "percent of", "entity name", "voting securities", "owned directly",
    "state or sovereign power", "company name", "ownership %", "state or",
    "province of", "provinceof", "rule 1-02", "of organization",
    "or organization", "of incorporation", "owneddirectly", "percentageof",
    "stateor", "orindirectly by", "item 601", "reg s-k", "no fear act",
    "directory listing", "click here", "subsidiaries of", "subsidiary of",
    "list of subsidiaries", "name of subsidiary", "name of entity",
    "table of contents", "significant subsidiaries", "state of", "country of",
    "organized under", "% owned",
)

_BOILERPLATE_EXACT = frozenset({
    "site map", "contact", "links", "careers", "plain writing", "contracts",
    "organization", "incorporation", "education", "open government",
    "enforcement", "notes:", "notes", "names under which", "usa.gov", "about",
    "and", "foia", "inspector general", "news", "investor.gov", "accessibility",
    "name of company", "regulation", "filings", "divisions", "privacy",
    "what's new", "what we do", "webcasts", "upcoming events", "name",
    "subsidiaries", "subsidiary", "n/a", "none", "total", "notes to",
})

_MONTHS = ("january", "february", "march", "april", "may", "june", "july",
           "august", "september", "october", "november", "december")

#: Ownership percentages, footnote markers and pure numbers.
_NUMERIC_ONLY = re.compile(r"^[\s\d.,%()\-*†‡§]+$")
_ONLY_SYMBOLS = re.compile(r"^[\W_]+$", re.UNICODE)

MIN_NAME_LENGTH = 3
MAX_NAME_LENGTH = 120


def looks_like_company(text: str | None, parent_name: str = "") -> str | None:
    """Return a cleaned company name, or ``None`` if the text is not one.

    Rejects table headers, jurisdictions, percentages, dates, footnotes and the
    parent company's own name.
    """
    if not text:
        return None

    cleaned = str(text).replace("\xa0", " ").replace("\n", " ")
    cleaned = re.sub(r"\s+", " ", cleaned).strip().strip("|")
    # Drop trailing footnote markers: "Acme Ltd (1)" -> "Acme Ltd".
    cleaned = re.sub(r"\s*\((?:\d+|[a-z])\)\s*$", "", cleaned, flags=re.IGNORECASE).strip()
    # Strip surrounding punctuation, but keep a single trailing period: it is
    # part of the name in "Acme Manufacturing Inc." and "Widget Pte. Ltd.".
    cleaned = cleaned.lstrip(" .,;:*†‡§").rstrip(" ,;:*†‡§")
    cleaned = re.sub(r"\.{2,}$", "", cleaned).strip()

    if len(cleaned) < MIN_NAME_LENGTH or len(cleaned) > MAX_NAME_LENGTH:
        return None
    if ".htm" in cleaned.lower() or cleaned.lower().startswith(("http://", "https://")):
        return None
    if _ONLY_SYMBOLS.match(cleaned) or _NUMERIC_ONLY.match(cleaned):
        return None

    lowered = cleaned.lower()
    # Compare against the exact blacklist with a trailing period removed, so
    # "None." is rejected just as "None" is.
    if lowered.rstrip(".") in _BOILERPLATE_EXACT:
        return None
    if any(phrase in lowered for phrase in _BOILERPLATE):
        return None
    if is_jurisdiction(cleaned):
        return None
    # A date such as "December 31, 2023".
    if any(month in lowered for month in _MONTHS) and re.search(r"\d", cleaned):
        return None
    # Must contain at least one letter sequence that could be a word.
    if not re.search(r"[A-Za-z]{2}", cleaned):
        return None
    # The registrant itself is not its own subsidiary.
    if parent_name and name_key(cleaned) == name_key(parent_name):
        return None

    return cleaned


def extract_from_tables(soup: BeautifulSoup, parent_name: str) -> list[str]:
    """Pull subsidiary names out of HTML tables.

    For each table, score every column by how many of its cells look like
    company names versus jurisdictions, then take the best column. This handles
    the common ``name | jurisdiction`` and ``name | jurisdiction | % owned``
    layouts without guessing at tag names.
    """
    names: list[str] = []
    for table in soup.find_all("table"):
        rows: list[list[str]] = []
        for row in table.find_all("tr"):
            cells = [cell.get_text(" ", strip=True).replace("\xa0", " ")
                     for cell in row.find_all(["td", "th"])]
            cells = [c for c in cells if c.strip()]
            if cells:
                rows.append(cells)
        if len(rows) < 2:
            continue

        width = max(len(row) for row in rows)
        best_column, best_score = None, 0
        for column in range(width):
            values = [row[column] for row in rows if len(row) > column]
            score = sum(1 for value in values if looks_like_company(value, parent_name))
            jurisdictions = sum(1 for value in values if is_jurisdiction(value))
            # A column that is mostly jurisdictions is the wrong column even if
            # a few entries survive the company filter.
            if jurisdictions > score:
                continue
            if score > best_score:
                best_column, best_score = column, score

        if best_column is None:
            continue
        for row in rows:
            if len(row) <= best_column:
                continue
            candidate = looks_like_company(row[best_column], parent_name)
            if candidate:
                names.append(candidate)
    return names


def extract_from_text(text: str, parent_name: str) -> list[str]:
    """Fall back to line-by-line extraction for plain-text exhibits."""
    names: list[str] = []
    for line in text.splitlines():
        # Text exhibits align columns with runs of whitespace or tabs; the
        # first column is the company name.
        parts = re.split(r"\s{3,}|\t+", line.strip())
        if not parts:
            continue
        candidate = looks_like_company(parts[0], parent_name)
        if candidate:
            names.append(candidate)
    return names


def parse_exhibit21(document: str, parent_name: str) -> list[str]:
    """Extract subsidiary names from an Exhibit 21 document.

    Tries structured table parsing first and falls back to text parsing when
    that yields too little, which is what happens with pre-2001 text filings.
    """
    if not document or not document.strip():
        return []

    try:
        soup = BeautifulSoup(document, "html.parser")
    except Exception as exc:
        log.debug("Could not parse Exhibit 21 as HTML: %s", exc)
        soup = None

    names: list[str] = []
    if soup is not None:
        names = extract_from_tables(soup, parent_name)
        if len(names) < 3:
            # No usable tables: fall back to the document's visible text.
            log.debug("Table extraction yielded %d names; trying text extraction",
                      len(names))
            names.extend(extract_from_text(soup.get_text("\n"), parent_name))
    else:
        names = extract_from_text(document, parent_name)

    unique = dedupe_names(names)
    log.debug("Extracted %d unique subsidiary names", len(unique))
    return unique


def discover_subsidiaries(client: EdgarClient, company_name: str,
                          max_companies: int = 3) -> list[Subsidiary]:
    """Full subsidiary discovery pipeline for a company name.

    Company name -> EDGAR registrants -> recent 10-K/20-F filings -> Exhibit 21
    -> parsed subsidiary names. Every stage degrades gracefully: a company with
    no EDGAR presence, no filings, or no Exhibit 21 simply yields no
    subsidiaries.
    """
    log.info("Discovering subsidiaries for %r via SEC EDGAR", company_name)

    companies = client.find_companies(company_name, limit=max_companies)
    if not companies:
        log.warning(
            "No SEC registrant matched %r. The company may be private, foreign, "
            "a subsidiary of a holding company, or filed on paper.", company_name,
        )
        return []

    log.debug("Candidate registrants: %s", ", ".join(c.name for c in companies))

    results: list[Subsidiary] = []
    seen: set[str] = set()

    for company in companies:
        subsidiaries = _subsidiaries_for_company(client, company)
        for subsidiary in subsidiaries:
            key = subsidiary.normalized_key()
            if not key or key in seen:
                continue
            seen.add(key)
            results.append(subsidiary)
        if results:
            # The first registrant that yields data is almost always the right
            # one; scanning further mostly adds unrelated same-named companies.
            break

    if not results:
        log.warning("SEC subsidiary data unavailable for %r", company_name)
    else:
        log.info("Discovered %d subsidiaries for %r", len(results), company_name)
    return results


def _subsidiaries_for_company(client: EdgarClient,
                              company: EdgarCompany) -> list[Subsidiary]:
    filings = client.recent_filings(company)
    if not filings:
        log.debug("No candidate filings for %s (CIK %s)", company.name, company.cik)
        return []

    for filing in filings:
        located = client.find_exhibit21(filing)
        if not located:
            continue
        url, document_name = located
        log.debug("Exhibit 21 for %s: %s (%s %s)",
                  company.name, document_name, filing.form, filing.filing_date)
        document = client.fetch_document(url)
        if not document:
            continue
        names = parse_exhibit21(document, company.name)
        if names:
            return [Subsidiary(name=name, parent=company.name, source_url=url)
                    for name in names]
        log.debug("Exhibit 21 at %s produced no usable names", url)
    return []


def subsidiary_keys(subsidiaries: Iterable[Subsidiary]) -> frozenset[str]:
    """Normalised keys for the confidence model's ``SUBSIDIARY_MATCH`` check."""
    return frozenset(s.normalized_key() for s in subsidiaries if s.normalized_key())


def merge_targets(target: str, subsidiaries: Sequence[Subsidiary]) -> list[str]:
    """Build the de-duplicated list of company names to query.

    The target company always comes first, and no subsidiary that normalises to
    the same name is queried twice.
    """
    ordered: list[str] = [target]
    seen = {name_key(target)}
    for subsidiary in subsidiaries:
        key = name_key(subsidiary.name)
        if not key or key in seen:
            continue
        seen.add(key)
        ordered.append(subsidiary.name)
    return ordered


def strip_suffixes_for_query(name: str) -> str:
    """Return the form of a company name best suited to a registry search."""
    normalized = normalize_company_name(name)
    return normalized if normalized else name
