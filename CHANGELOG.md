# Changelog

## 3.7.1

Found by a new end-to-end smoke harness (`tests/smoke/smoke_test.py`).

### Fixed

* **`-p` produced no output.** Point-of-contact lookups followed the absolute
  URL embedded in ARIN's response instead of building one from the POC handle.
  Besides being untestable against anything but the live service, that is an
  SSRF vector: external data chose which host the tool fetched. URLs are now
  built from the handle, and a reference returned in a response is only
  followed when it points at the same host we already trust.
* **`-p` and `-so` failed silently.** When the user explicitly asked for
  contacts or a subsidiary list and none were retrieved, no file appeared and
  nothing was logged. Both now warn.

### Added

* `tests/smoke/smoke_test.py` - an in-process mock of ARIN, RDAP, RIPE DB,
  RIPEstat and SEC EDGAR that drives the real CLI end to end and asserts on the
  files it produces: output formats, IPv4/IPv6 filters, subsidiary discovery,
  PoC output, list mode, path-traversal and CSV-injection defences, and
  behaviour under partial and total registry outage. 36 checks.


## 3.7.0

### Fixed

* **Failures were collected but never shown.** Every failed sub-request was
  appended to `result.errors` and then only written to the JSON output. A run
  could return fewer netblocks than the previous one with nothing on screen to
  explain why - the failure mode that makes results impossible to trust. The
  run now ends with a de-duplicated warning list and the summary gains a
  `Source errors` line when anything failed.
* ARIN customer search now logs how many records resolved to network data.
  A customer object can legitimately carry no network reference, but the same
  shortfall is also what a partial outage looks like, so it is worth surfacing.


## 3.6.0

### Fixed

* **ASN discovery probed only one organisation.** Seeds were taken as the
  first N netblocks in list order, so every probe landed on whichever
  organisation was returned first - typically the largest ARIN org, whose
  prefixes all originate from a single AS. A multinational's regional entities
  announce from different ASes and were never probed, so only one ASN was ever
  discovered no matter how many the company held.

  Seeds are now spread round-robin across distinct (registry, organisation)
  pairs, guaranteeing every organisation is probed at least once before any is
  probed twice. The seed budget rose from 5 to 8 to accommodate this.


## 3.5.1

### Fixed

* **The summary breakdown did not account for every row.** It listed network,
  customer and contact records but not ASN-derived ones, and the `ASNs` line
  counted distinct AS numbers under a heading that read like a row count. On a
  real run, 16 of 76 reported netblocks were missing from the breakdown. Added
  `ASN-derived` and `Search results` lines; the source counts now sum to the
  total. A test asserts the reconciliation.


## 3.5.0

### Fixed

* **Contained networks were reported as low confidence.** Deduplication
  implemented containment by setting the score to 0 and the band to
  `unlikely`. That conflated two unrelated facts: "this network sits inside a
  bigger one we already listed" and "we doubt this belongs to the company".
  The effect became obvious once ASN expansion landed - BGP-announced
  more-specifics sit inside registered allocations, so expanding an ASN pushed
  a batch of genuine, high-confidence company netblocks straight into the
  discard band.

  Containment is now recorded as a `subsumed` flag while the confidence score
  and band are preserved. Address totals are unaffected, because
  `count_addresses()` already collapses overlapping networks before counting.

### Added

* `subsumed` column in CSV and field in JSON.
* `--no-subsumed` to omit networks contained inside another reported network.
* `Contained in a larger block` line in the summary.


## 3.4.0

### Fixed

* **ASNs discovered via BGP were labelled but never expanded.** When a company
  holds no ASN records under a matching registry organisation - common, because
  ASNs are often registered to a former parent - 3.2.0 learned to find the real
  AS from BGP origin data, but only used it to populate a column. Every prefix
  that AS announces was still missed. Discovered ASNs are now fed back into
  prefix expansion.

  Seeding is deliberately narrow: only netblocks registered directly to a
  matched organisation are probed (a reassignment is announced by its upstream
  provider, so seeding from one would discover the ISP's AS), the AS holder
  name must match the company, and at most 5 prefixes are probed.
* **A request known to fail was sent on every run.** RIPE answers HTTP 500 to
  wildcard `fn` patterns. Rather than sending it and falling back, RIPE is now
  queried with the plain name first, keeping the wildcard form as a fallback in
  case the behaviour changes. Other registries are unaffected.


## 3.3.0

Two problems introduced by the 3.2.0 improvements, found on a live run.

### Fixed

* **Third-party ASNs were presented as the company's.** Origin-ASN lookup
  discarded RIPEstat's `holder` field, so for a downstream reassignment the
  *upstream provider's* AS appeared in the `asn` column beside the target
  company. Netblocks now carry `asn_holder`; when the holder does not match the
  company the result gains a zero-weight `THIRD_PARTY_ORIGIN` evidence entry,
  and the summary reports company ASNs and third-party ASNs separately.
* **Contact-derived netblocks were over-weighted.** Resolving RIPE person/role
  handles through `admin-c`/`tech-c` (added in 3.2.0) gave those networks the
  same +30 baseline as org-registered ones, even though an ISP routinely lists
  a customer's staff as technical contacts. Added `ObjectType.CONTACT` with a
  +12 baseline; such records also no longer claim the organisation handle, so
  they cannot earn `ORG_HANDLE_LINK`. A contact-derived network can no longer
  reach `confirmed`.

### Changed

* CSV gains an `asn_holder` column; JSON gains the matching field.
* Summary output splits `ASNs (company)` from `ASNs (3rd party)` and adds a
  `Contact records` line.


## 3.2.0

Four issues found on live runs against ARIN and RIPE.

### Fixed

* **Wasted retries on RDAP search rejections.** RIPE answers HTTP 500 to
  wildcard `fn` patterns. The client treated that as transient and burned three
  retries (~1s) before reaching the wildcard-stripped fallback. A 5xx/4xx from
  an entity *search* is now treated as a rejected query, so the fallback is
  immediate. `HttpClient` gained a `no_retry_status` parameter for this.
* **RIPE person/role handles yielded no netblocks.** Entity search returns
  person (`PA9687-RIPE`) and role (`PN4269-RIPE`) objects alongside
  organisations; an `org:` inverse lookup can never match them. Non-`ORG-`
  handles are now resolved through the `admin-c`/`tech-c` contact attributes,
  capped at 50 objects since contact association is weaker evidence.
* **"Pvt Ltd" and similar suffixes were not recognised.** `PayPal Pvt Ltd`
  normalised to `paypal pvt`, failed to match the target, and its netblocks
  scored `weak` instead of `probable`. Added the missing legal-entity forms
  (`pvt`, `private limited`, `pte ltd`, `pty ltd`, `co ltd`, `kg`, `zrt`, and
  others seen in live RIPE/APNIC data).
* **`ASNs: 0` for companies whose ASNs sit under another entity.** PayPal's
  ARIN organisations hold no ASN records, so registry-based discovery found
  none. Discovered prefixes are now resolved to their originating AS through
  RIPEstat's `prefix-overview` API, which finds them regardless of registry
  bookkeeping. Runs concurrently, caches per CIDR, skips zero-scored netblocks,
  and is disabled by `--no-asn-expansion`.

### Note on scope

Descriptive words such as `Technologies`, `Services` and `Global` are
deliberately **not** treated as legal suffixes. Stripping them would collapse
`Acme Technologies` into `Acme` and invent matches between distinct companies.


## 3.1.0

### Added

* **RIPE netblock resolution.** RIPE's RDAP entity search finds organisations
  but, unlike ARIN's, does not embed a ``networks`` array - so a RIPE-region
  company resolved to an organisation and then produced zero netblocks. The new
  ``registries/ripe.py`` closes the gap using the RIPE database REST API's
  inverse lookup (every ``inetnum``/``inet6num`` whose ``org:`` attribute
  references the handle). Runs automatically when RIPE RDAP returns
  organisations without networks; requires no key.


## 3.0.1

Fixes for three issues found on first real-world runs against live ARIN and
RDAP services.

### Fixed

* **`ORG_HANDLE_LINK` could never fire for network records.** A netblock's
  `handle` is the *network* handle (`NET-66-211-168-0-1`), but the resolved
  organisation handles are *org* handles (`PAYPA`). Comparing the two never
  matched, so the +20 bonus was unreachable and networks registered directly to
  a confirmed organisation were capped below `confirmed`. Netblocks now carry a
  separate `org_handle` field, populated when a record is reached via an
  organisation's `/nets` endpoint.
* **LACNIC returned HTTP 406 Not Acceptable.** RDAP's registered media type is
  `application/rdap+json` (RFC 7480 s4.2); we sent `Accept: application/json`,
  which LACNIC enforces strictly. All RDAP requests now send
  `application/rdap+json` with `application/json` as a fallback.
* **RIPE returned HTTP 500 for wildcard entity searches** and the client
  exhausted its retries against a deterministic failure. Wildcard queries that
  fail are now retried once with the wildcards stripped before giving up.

### Improved

* Added debug logging for ASN lookups and per-organisation netblock counts, so
  a result of "0 ASNs" is now distinguishable from a silently-swallowed 404.


## 3.0.0

Full modernisation. The tool had stopped returning results because most of the
endpoints it depended on were retired; this release rebuilds the data layer on
documented APIs and adds a test suite.

### Fixed

* **ARIN discovery was completely broken.** 2.x POSTed a form to
  `https://whois.arin.net/ui/query.do` and regex-scraped resource URLs out of
  the HTML. That web UI was retired, so every run reported
  `No ARIN objects were found`. Replaced with the Whois-RWS REST API.
* **ASN expansion returned nothing.** `get_asn_subnets()` scraped
  `https://ipinfo.io/AS…` for anchor tags; the page now requires a token and its
  markup changed. Replaced with the RIPEstat `announced-prefixes` API.
* **Geolocation always returned an empty string.** The XPath
  `//*[@id="content"]/section[1]/…/li[4]/span[2]` had not matched ipinfo's
  layout for years. Replaced with its JSON endpoint plus an RDAP fallback.
* **SEC subsidiary discovery was broken.** Filing discovery used XPaths such as
  `//*[@id='formDiv']/div/table/tr[3]/td[4]`; modern EDGAR wraps rows in
  `<tbody>`, so these never matched. Replaced with `data.sec.gov` JSON APIs.
* **`-h` did not work.** The parser used `add_help=False` without defining a
  replacement, so `-h` produced
  `error: the following arguments are required: target`.
* **Path traversal in output filenames.** `process_output_name()` used the
  character class `[^\w\-_\./ ]`, which explicitly permits `/` and `.`, so
  `-o ../../etc/cron.d/x` wrote outside the working directory. Filenames are now
  reduced to a single path component.
* **CSV formula injection.** Registry-supplied names were written raw. A
  customer object named `=cmd|'/c calc'!A1` could execute on open. All values
  beginning with `=`, `+`, `-`, `@` or a control character are now escaped.
* **Nonsensical IPv4 sort key.**
  `ranges.sort(key=lambda n: socket.inet_aton(n.split('/')[1]))` sorted by
  *prefix length* parsed as a dotted quad (`inet_aton("24")` → `0.0.0.24`).
* **`TypeError` in `edgar/document.py`.** `Documents.__init__` passed
  `headers=` to `lxml.html.fromstring()`, which takes no such argument.
* **Hard-coded User-Agent in `edgar/company.py`.** `get_request()` always sent
  `"Testing Testing test@example.com"`, ignoring `-u` and violating the SEC's
  identification requirement.
* **Redundant 10 MB downloads.** `get_subsidiaries()` constructed
  `edgar.Edgar()` inside a loop, re-fetching `cik-lookup-data.txt` once per
  company. The company directory is now fetched at most once per run.
* **Dead conditional.** `if ('(') and (')') in temp` — the left operand is a
  non-empty string constant, so the test was always truthy.
* **`IndexError` on empty addresses.** `if address[0] == ','` crashed whenever a
  registry record had no address.
* **Interactive prompt in a CLI tool.** `process_output_file()` called `input()`
  on `IOError`, and its fallback (`if output: output = 'output'`) discarded
  whatever the user typed.
* **No request timeouts.** `requests` waits forever by default; a single
  unresponsive endpoint could hang the tool indefinitely.
* **Retries without backoff.** `attempts = 20` retried immediately in a tight
  loop with no delay.
* **Unbounded Google scraping.** `while continue_scrape` had no page cap, and
  the function returned `False` (a bool masquerading as a list) on CAPTCHA.
* **Errors silently swallowed.** `except …: None` appeared throughout, hiding
  genuine failures.
* **TLS warnings globally disabled.** `disable_warnings(InsecureRequestWarning)`
  suppressed legitimate certificate problems. Removed; verification is always on.
* Five `SyntaxWarning: invalid escape sequence` warnings on every start-up.
* `edgar/edgar.py::test()` referenced an undefined `Company` and passed the
  wrong keyword (`filingType`).

### Modernized

* **ARIN** → Whois-RWS REST (`/rest/orgs;name=`, `/rest/org/{h}/nets`,
  `/rest/org/{h}/asns`, `/rest/customers;name=`, `/rest/nets;name=`,
  `/rest/org/{h}/pocs`).
* **SEC EDGAR** → `www.sec.gov/files/company_tickers.json`,
  `data.sec.gov/submissions/CIK##########.json`, and per-filing `index.json`.
* **ASN → prefixes** → RIPEstat `announced-prefixes`.
* **`netaddr` → stdlib `ipaddress`.** Dependency removed.
* **`lxml` removed.** All HTML parsing now uses `bs4`'s `html.parser`.
* **`fuzzywuzzy` and `tqdm` removed.** Both were reachable only from
  `match_company_by_company_name()`, which the tool never called. `fuzzywuzzy`
  has been unmaintained since 2020.
* Vendored `edgar/` package deleted and replaced by `netblocktool/edgar_client.py`
  and `netblocktool/subsidiaries.py`.
* 2,252-line monolith split into a typed package using `dataclasses`,
  `pathlib`, `logging`, `argparse`, `enum` and `concurrent.futures`.
* Index-addressed lists (`sub_list[4]`, `del sub_list[3]`) replaced with
  explicit dataclasses.
* `print()` status output replaced with structured `logging`.

### New features

* **Multi-registry support:** ARIN, RIPE NCC, APNIC, AFRINIC and LACNIC, queried
  concurrently and selectable with `--registries`.
* **`SearchProvider` abstraction** with `google` and `none` backends, selectable
  via `--search-provider`.
* **JSON output** (`--json`, `--json-only`) with structured evidence.
* **Transparent confidence model** with an `evidence` column and four
  documented bands.
* **Corroboration scoring:** CIDRs reported by multiple independent source types
  score higher.
* **Environment configuration:** `NETBLOCKTOOL_TIMEOUT`, `NETBLOCKTOOL_USER_AGENT`,
  `NETBLOCKTOOL_MAX_WORKERS`, `NETBLOCKTOOL_MAX_RETRIES`, `NETBLOCKTOOL_RATE_LIMIT`.
* **Network tuning flags:** `--timeout`, `--workers`, `--retries`, `--rate-limit`,
  `--max-objects`.
* `--output-dir`, `--version`, `--no-asn-expansion`, `--legacy-csv`.
* Per-host rate limiting, response caching and request deduplication.
* Test suite of 423 offline tests with realistic fixtures.
* `pyproject.toml` packaging with a `netblocktool` console script.

### Compatibility

* **Python:** 3.10+ (tested 3.10–3.13). 2.x targeted 3.7.
* **All 2.x CLI flags are preserved:** `-l -o -v -q -n -w -ng -c -e -p -4 -6
  -s -sn -sp -so -u -g -a -ag`. Combined short forms such as `-wpgav` and
  `-gavl` still work.
* **`-h` now works** (it did not in 2.x).
* **CSV:** the default schema is extended. `--legacy-csv` reproduces the 2.x
  column layout exactly.
* **`-sp` is deprecated but accepted.** The Exhibit 21 parser now tries table
  extraction and text extraction automatically, so the alternate mode is
  redundant. Passing it logs a warning and changes nothing.
* **PoC output** moved from `Company_contacts.csv` to the same name with an
  added `Source` column.

### Behaviour changes worth knowing

* Non-routable space (RFC 1918, loopback, link-local, multicast, reserved) is
  now scored 0 instead of being reported as company-owned.
* Networks contained inside a larger reported network are marked `SUBSUMED`
  with score 0 rather than being dropped, preserving 2.x's "report everything
  seen" behaviour while making the reason explicit.
* Confidence scores are not numerically comparable to 2.x scores; the model is
  different. The 0–99 range is unchanged.
* Status output now goes to stderr, leaving stdout clean for piping.
