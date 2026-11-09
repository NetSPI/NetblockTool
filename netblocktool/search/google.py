"""Google-backed passive discovery.

Scope and limits
----------------

This provider issues ordinary Google web searches for pages that publish
netblock registration data, and parses CIDRs out of the result titles. It does
**not** attempt to defeat any access control:

* CAPTCHA challenges are detected and reported, never solved or bypassed;
* ``429``/``503`` responses end the scrape rather than triggering a hammering
  retry loop;
* the number of pages is bounded, and every request is rate limited;
* no cookies, no proxy rotation, no header spoofing beyond a plain, honest
  User-Agent.

If Google blocks the request the provider returns ``blocked=True`` with a
diagnostic and the run continues using registry data alone. Users who need
reliable search-derived results should use an API-based provider; this one is a
best-effort convenience.

The original implementation looped ``while continue_scrape`` with a five-second
timeout, no page cap, and would silently return ``False`` (a bool masquerading
as a list) on CAPTCHA.
"""

from __future__ import annotations

import random
import re
import time
from urllib.parse import parse_qs, urlsplit

from bs4 import BeautifulSoup

from ..cidr import is_public, normalize_cidr
from ..http import HttpError
from ..logging_setup import get_logger
from ..models import Netblock, ObjectType
from . import SearchOutcome, SearchProvider

log = get_logger("search.google")

SEARCH_URL = "https://www.google.com/search"
GOOGLE_HOST = "www.google.com"

#: Phrases Google serves when it decides a client is automated.
BLOCK_MARKERS = (
    "our systems have detected unusual traffic",
    "unusual traffic from your computer network",
    "/sorry/index",
    "recaptcha",
    "detected unusual traffic",
    "before you continue to google",
)

#: Google reports the end of results with these.
EXHAUSTED_MARKERS = (
    "did not match any documents",
    "we have omitted some entries very similar",
)

RESULTS_PER_PAGE = 10
DEFAULT_MAX_PAGES = 10

#: Matches a CIDR anywhere in a result snippet.
CIDR_PATTERN = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3}/\d{1,2}|[0-9A-Fa-f:]{2,39}/\d{1,3})\b"
)


class GoogleSearchProvider(SearchProvider):
    """Best-effort netblock discovery through Google web search."""

    name = "google"

    def __init__(self, client, config=None) -> None:
        super().__init__(client, config)
        # Deliberately slow: one request every two seconds at most.
        self.client.set_host_rate(GOOGLE_HOST, 0.5)

    def find_netblocks(self, company: str, *, max_pages: int = DEFAULT_MAX_PAGES) -> SearchOutcome:
        outcome = SearchOutcome(provider=self.name)
        query = f'site:ipinfo.io "{company}" "netblock details"'
        pages = max(1, min(int(max_pages), 30))
        seen: set[str] = set()

        for page in range(pages):
            start = page * RESULTS_PER_PAGE
            try:
                response = self.client.get(
                    SEARCH_URL,
                    params={"hl": "en", "q": query, "start": str(start)},
                    # Search results are volatile; caching them across a run is
                    # fine, but they must not persist between runs.
                    cache=True,
                )
            except HttpError as exc:
                message = f"Google request failed: {exc}"
                log.warning(message)
                outcome.note(message)
                outcome.completed = True
                return outcome

            outcome.pages_fetched += 1

            if response.status_code in (429, 503):
                message = (
                    f"Google returned HTTP {response.status_code} (rate limited). "
                    "Stopping search-engine discovery; registry sources are unaffected."
                )
                log.warning(message)
                outcome.note(message)
                outcome.blocked = True
                outcome.completed = True
                return outcome

            if _is_blocked(response.text, response.url):
                message = (
                    "Google served an anti-bot challenge (CAPTCHA). Search-engine "
                    "discovery is unavailable from this IP; try again later, use a "
                    "different network, or run with -ng to skip it. Registry results "
                    "are unaffected."
                )
                log.warning(message)
                outcome.note(message)
                outcome.blocked = True
                outcome.completed = True
                return outcome

            if not response.ok:
                message = f"Google returned HTTP {response.status_code}; stopping search"
                log.warning(message)
                outcome.note(message)
                outcome.completed = True
                return outcome

            found = self._parse_page(response.text, company, seen)
            outcome.netblocks.extend(found)
            log.debug("Google page %d: %d new netblocks", page + 1, len(found))

            lowered = response.text.lower()
            if not found and any(marker in lowered for marker in EXHAUSTED_MARKERS):
                break
            if not found:
                # Two consecutive empty pages almost always means the end.
                break

            if page < pages - 1:
                time.sleep(random.uniform(1.0, 3.0))

        outcome.completed = True
        return outcome

    # -- parsing ----------------------------------------------------------

    def _parse_page(self, html_text: str, company: str, seen: set[str]) -> list[Netblock]:
        """Extract CIDRs from a results page."""
        try:
            soup = BeautifulSoup(html_text, "html.parser")
        except Exception as exc:
            log.debug("Failed to parse Google HTML: %s", exc)
            return []

        results: list[Netblock] = []
        for anchor in soup.find_all("a", href=True):
            target = _resolve_href(anchor["href"])
            if not target or "ipinfo.io" not in target:
                continue
            text = anchor.get_text(" ", strip=True)
            for raw in CIDR_PATTERN.findall(text):
                cidr = normalize_cidr(raw)
                if not cidr or cidr in seen or not is_public(cidr):
                    continue
                seen.add(cidr)
                results.append(Netblock(
                    cidr=cidr,
                    name=_result_name(text) or company,
                    handle="",
                    object_type=ObjectType.SEARCH,
                    registry="",
                    source_url=target,
                ))
        return results


def _is_blocked(body: str, final_url: str) -> bool:
    """Detect an anti-bot interstitial without attempting to circumvent it."""
    if "/sorry/" in final_url:
        return True
    lowered = body[:20000].lower()
    return any(marker in lowered for marker in BLOCK_MARKERS)


def _resolve_href(href: str) -> str:
    """Unwrap Google's ``/url?q=`` redirector and reject non-HTTP targets."""
    if href.startswith("/url?"):
        params = parse_qs(urlsplit(href).query)
        candidates = params.get("q") or params.get("url") or []
        href = candidates[0] if candidates else ""
    if not href.startswith(("http://", "https://")):
        return ""
    return href


def _result_name(text: str) -> str:
    """Pull an organisation name out of an ipinfo result title, if present."""
    marker = "netblock details -"
    lowered = text.lower()
    index = lowered.find(marker)
    if index < 0:
        return ""
    return text[index + len(marker):].strip(" -|")
