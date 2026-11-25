"""SEC EDGAR client.

Replaces the vendored ``edgar/`` package, which was broken in several ways:

* it downloaded the ~10 MB ``cik-lookup-data.txt`` file **once per company**
  inside a loop, with no caching;
* ``Documents.__init__`` passed ``headers=`` to ``lxml.html.fromstring``,
  a guaranteed ``TypeError``;
* ``Company.get_request`` hard-coded the User-Agent ``"Testing Testing
  test@example.com"``, ignoring the one the user supplied and violating the
  SEC's identification requirement;
* filing discovery scraped ``cgi-bin/browse-edgar`` with XPaths like
  ``//*[@id='formDiv']/div/table/tr[3]/td[4]`` that no longer match the current
  markup (modern EDGAR wraps rows in ``<tbody>``);
* it depended on ``fuzzywuzzy`` and ``tqdm`` for a matching method the tool
  never called.

This module uses EDGAR's documented JSON interfaces instead:

* ``https://www.sec.gov/files/company_tickers.json`` - CIK directory
* ``https://data.sec.gov/submissions/CIK##########.json`` - a company's filings
* ``https://www.sec.gov/Archives/edgar/data/{cik}/{accession}/index.json``
  - the document list for one filing

SEC rules (https://www.sec.gov/os/accessing-edgar-data) require a descriptive
User-Agent with real contact details and cap traffic at 10 requests/second. The
client enforces a 5 req/s ceiling and warns when the User-Agent has not been
customised.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .config import SEC_RATE_LIMIT, Config
from .http import HttpClient, HttpError
from .logging_setup import get_logger
from .normalize import name_key, normalize_company_name

log = get_logger("edgar")

SEC_HOST = "www.sec.gov"
DATA_HOST = "data.sec.gov"

COMPANY_TICKERS_URL = "https://www.sec.gov/files/company_tickers.json"
CIK_LOOKUP_URL = "https://www.sec.gov/Archives/edgar/cik-lookup-data.txt"
SUBMISSIONS_URL = "https://data.sec.gov/submissions/CIK{cik}.json"
ARCHIVE_INDEX_URL = "https://www.sec.gov/Archives/edgar/data/{cik}/{accession}/index.json"
ARCHIVE_DOC_URL = "https://www.sec.gov/Archives/edgar/data/{cik}/{accession}/{document}"

#: Filing types that carry an Exhibit 21 "Subsidiaries of the Registrant".
SUBSIDIARY_FORMS = ("10-K", "10-K405", "10-KSB", "20-F", "40-F", "S-1", "S-4")

#: Exhibit types that contain subsidiary lists.
EX21_PATTERN = re.compile(r"^EX-21", re.IGNORECASE)

MAX_FILINGS_TO_SCAN = 8


@dataclass(slots=True)
class EdgarCompany:
    """An EDGAR registrant."""

    cik: str
    name: str

    @property
    def padded_cik(self) -> str:
        return self.cik.zfill(10)

    @property
    def numeric_cik(self) -> str:
        return str(int(self.cik))


@dataclass(slots=True)
class Filing:
    """One EDGAR filing."""

    accession: str
    form: str
    filing_date: str
    cik: str

    @property
    def accession_nodash(self) -> str:
        return self.accession.replace("-", "")

    @property
    def index_url(self) -> str:
        return ARCHIVE_INDEX_URL.format(cik=str(int(self.cik)),
                                        accession=self.accession_nodash)


class EdgarClient:
    """Query SEC EDGAR for companies, filings and Exhibit 21 documents."""

    def __init__(self, client: HttpClient, config: Config | None = None) -> None:
        self.client = client
        self.config = config or client.config
        self.client.set_host_rate(SEC_HOST, min(SEC_RATE_LIMIT, self.config.rate_limit))
        self.client.set_host_rate(DATA_HOST, min(SEC_RATE_LIMIT, self.config.rate_limit))
        self._directory: dict[str, list[EdgarCompany]] | None = None

        if self.config.is_default_user_agent():
            log.warning(
                "Using the default User-Agent. The SEC requires a descriptive "
                "User-Agent containing real contact details; set -u or "
                "NETBLOCKTOOL_USER_AGENT to avoid being blocked."
            )

    # -- company lookup ---------------------------------------------------

    def _load_directory(self) -> dict[str, list[EdgarCompany]]:
        """Load and index EDGAR's company directory exactly once per run."""
        if self._directory is not None:
            return self._directory

        directory: dict[str, list[EdgarCompany]] = {}
        try:
            payload = self.client.get_json(COMPANY_TICKERS_URL)
        except HttpError as exc:
            log.warning("Could not load the SEC company directory: %s", exc)
            self._directory = {}
            return self._directory

        if isinstance(payload, dict):
            for entry in payload.values():
                if not isinstance(entry, dict):
                    continue
                cik = entry.get("cik_str")
                title = entry.get("title")
                if cik is None or not title:
                    continue
                company = EdgarCompany(cik=str(cik), name=str(title))
                directory.setdefault(name_key(company.name), []).append(company)

        log.debug("Loaded %d companies from the SEC directory", len(directory))
        self._directory = directory
        return directory

    def find_companies(self, name: str, limit: int = 5) -> list[EdgarCompany]:
        """Find EDGAR registrants whose name matches ``name``.

        Exact normalised matches are returned first, then prefix matches, then
        substring matches. Returns an empty list if the directory is
        unavailable - the caller continues without subsidiary data.
        """
        directory = self._load_directory()
        if not directory:
            return []

        target = name_key(name)
        if not target:
            return []

        exact = list(directory.get(target, ()))
        prefix: list[EdgarCompany] = []
        contains: list[EdgarCompany] = []
        for key, companies in directory.items():
            if key == target:
                continue
            if key.startswith(target):
                prefix.extend(companies)
            elif target in key:
                contains.extend(companies)

        ordered = exact + prefix + contains
        seen: set[str] = set()
        result: list[EdgarCompany] = []
        for company in ordered:
            if company.cik in seen:
                continue
            seen.add(company.cik)
            result.append(company)
            if len(result) >= limit:
                break

        log.debug("Matched %d EDGAR companies for %r", len(result), name)
        return result

    # -- filings ----------------------------------------------------------

    def recent_filings(self, company: EdgarCompany,
                       forms: tuple[str, ...] = SUBSIDIARY_FORMS,
                       limit: int = MAX_FILINGS_TO_SCAN) -> list[Filing]:
        """Return the company's most recent filings of the given form types."""
        url = SUBMISSIONS_URL.format(cik=company.padded_cik)
        try:
            payload = self.client.get_json(url)
        except HttpError as exc:
            log.warning("EDGAR submissions unavailable for %s: %s", company.name, exc)
            return []
        if not isinstance(payload, dict):
            return []

        recent = payload.get("filings", {}).get("recent") if isinstance(
            payload.get("filings"), dict) else None
        if not isinstance(recent, dict):
            log.debug("No recent filings block for CIK %s", company.cik)
            return []

        accessions = recent.get("accessionNumber") or []
        form_types = recent.get("form") or []
        dates = recent.get("filingDate") or []
        if not isinstance(accessions, list) or not isinstance(form_types, list):
            return []

        wanted = {form.upper() for form in forms}
        filings: list[Filing] = []
        for index, accession in enumerate(accessions):
            form = str(form_types[index]).upper() if index < len(form_types) else ""
            if form not in wanted:
                continue
            filings.append(Filing(
                accession=str(accession),
                form=form,
                filing_date=str(dates[index]) if index < len(dates) else "",
                cik=company.cik,
            ))
            if len(filings) >= limit:
                break
        log.debug("Found %d candidate filings for %s", len(filings), company.name)
        return filings

    def find_exhibit21(self, filing: Filing) -> tuple[str, str] | None:
        """Locate the Exhibit 21 document inside a filing.

        Returns ``(url, document_name)`` or ``None`` when the filing has no
        Exhibit 21 - which is normal and not an error.
        """
        try:
            payload = self.client.get_json(filing.index_url)
        except HttpError as exc:
            log.debug("Filing index unavailable (%s): %s", filing.accession, exc)
            return None
        if not isinstance(payload, dict):
            return None

        items = payload.get("directory", {}).get("item") if isinstance(
            payload.get("directory"), dict) else None
        if not isinstance(items, list):
            return None

        for item in items:
            if not isinstance(item, dict):
                continue
            doc_type = str(item.get("type") or "")
            document = str(item.get("name") or "")
            if not document or not EX21_PATTERN.match(doc_type):
                continue
            if not document.lower().endswith((".htm", ".html", ".txt")):
                continue
            url = ARCHIVE_DOC_URL.format(
                cik=str(int(filing.cik)),
                accession=filing.accession_nodash,
                document=document,
            )
            return url, document

        # Some older filings do not populate ``type`` in index.json; fall back
        # to a filename heuristic.
        for item in items:
            if not isinstance(item, dict):
                continue
            document = str(item.get("name") or "")
            lowered = document.lower()
            if ("ex21" in lowered or "ex-21" in lowered) and \
                    lowered.endswith((".htm", ".html", ".txt")):
                return ARCHIVE_DOC_URL.format(
                    cik=str(int(filing.cik)),
                    accession=filing.accession_nodash,
                    document=document,
                ), document
        return None

    def fetch_document(self, url: str) -> str | None:
        """Download a filing document, returning ``None`` on failure."""
        try:
            response = self.client.get(url)
        except HttpError as exc:
            log.warning("Could not download %s: %s", url, exc)
            return None
        if not response.ok:
            log.warning("HTTP %d downloading %s", response.status_code, url)
            return None
        return response.text


def company_matches(company: EdgarCompany, target: str) -> bool:
    """True when an EDGAR registrant plausibly is the target company."""
    return normalize_company_name(company.name).startswith(normalize_company_name(target))
