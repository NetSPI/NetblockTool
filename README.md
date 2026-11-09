# NetblockTool

Find public netblocks owned by a company and its subsidiaries.

[![licence badge]][licence]
[![stars badge]][stars]
[![forks badge]][forks]
[![issues badge]][issues]

[licence badge]:https://img.shields.io/badge/license-New%20BSD-blue.svg
[stars badge]:https://img.shields.io/github/stars/NetSPI/NetblockTool.svg
[forks badge]:https://img.shields.io/github/forks/NetSPI/NetblockTool.svg
[issues badge]:https://img.shields.io/github/issues/NetSPI/NetblockTool.svg

[licence]:https://github.com/NetSPI/NetblockTool/blob/master/LICENSE
[stars]:https://github.com/NetSPI/NetblockTool/stargazers
[forks]:https://github.com/NetSPI/NetblockTool/network
[issues]:https://github.com/NetSPI/NetblockTool/issues

---

## Overview

NetblockTool builds a deduplicated, confidence-scored list of the public IPv4
and IPv6 netblocks that appear to belong to a target company and the
subsidiaries it discloses to the SEC.

* **Passive only.** No traffic is ever sent to the target's hosts. The tool
  reads public registry records, public SEC filings and (optionally) public
  search results.
* **Authoritative sources first.** Regional Internet Registry data is the
  primary source; search-engine results are optional enrichment.
* **Every result is explained.** Each netblock carries an `evidence` field
  listing the named, weighted reasons behind its score, so findings can be
  audited rather than taken on faith.

> ### Passive reconnaissance disclaimer
>
> This tool performs open-source intelligence gathering against public
> databases. It does **not** scan ports, enumerate services, probe hosts,
> fingerprint software or test for vulnerabilities, and it will not be extended
> to do so. Discovered netblocks are *candidates* based on public records; they
> are not proof of ownership or authorisation. **Confirm scope with the asset
> owner in writing before directing any active testing at anything this tool
> reports.**

---

## What changed in 3.0

Version 2.x stopped returning results because the endpoints it depended on were
retired. 3.0 is a full rewrite of the data layer.

| Area | 2.x | 3.0 |
|---|---|---|
| ARIN | Scraped HTML from `whois.arin.net/ui/query.do` (retired web UI) | Documented Whois-RWS REST API (`/rest/orgs;name=`, `/rest/org/{h}/nets`, …) |
| Other RIRs | None — ARIN only | RDAP for RIPE NCC, APNIC, AFRINIC, LACNIC |
| ASN → prefixes | Scraped `ipinfo.io/AS…` HTML | RIPEstat `announced-prefixes` JSON API |
| Geolocation | XPath scrape of an ipinfo page layout that no longer exists | ipinfo JSON API with RDAP fallback |
| SEC subsidiaries | Scraped `cgi-bin/browse-edgar` with brittle XPaths | `data.sec.gov` submissions + filing-index JSON |
| CIDR maths | `netaddr` | stdlib `ipaddress` |
| HTML parsing | `lxml` + `bs4` | `bs4` only |
| Dependencies | 6 (incl. abandoned `fuzzywuzzy`) | 2 |
| Confidence | ~130 lines of nested conditionals | Flat, documented, weighted evidence model |
| Tests | None | 423, all offline |

Full details in [`CHANGELOG.md`](CHANGELOG.md).

---

## Architecture

```
netblocktool/
├── cli.py              Argument parsing, output orchestration
├── pipeline.py         End-to-end discovery pipeline
├── config.py           Configuration + environment variables
├── http.py             Timeouts, retries, backoff, rate limiting, caching
├── models.py           Netblock / Organization / Contact / Evidence dataclasses
├── cidr.py             CIDR parsing, filtering, dedup (stdlib ipaddress)
├── normalize.py        Company-name normalisation
├── scoring.py          Confidence model
├── output.py           CSV / JSON writers, injection + traversal defences
├── geo.py              Geolocation and address enrichment
├── edgar_client.py     SEC EDGAR JSON API client
├── subsidiaries.py     Exhibit 21 parsing and subsidiary pipeline
├── registries/
│   ├── arin.py         ARIN Whois-RWS REST
│   ├── rdap.py         Generic RDAP (RIPE, APNIC, AFRINIC, LACNIC)
│   ├── ripe.py         RIPE database inverse lookup (org → inetnums)
│   ├── bgp.py          ASN → announced prefixes
│   └── base.py         RegistryClient interface + shared parsing helpers
└── search/
    ├── __init__.py     SearchProvider interface
    └── google.py       Google provider (best effort)
```

Pipeline:

```
target company
  → company/entity identification      (registry organisation search)
  → subsidiary discovery               (SEC EDGAR Exhibit 21, optional)
  → normalise company names
  → per-company registry queries       (ARIN + RDAP RIRs, concurrent)
  → ASN expansion                      (announced prefixes)
  → search-engine enrichment           (optional, best effort)
  → normalise + filter + deduplicate CIDRs
  → confidence scoring with evidence
  → CSV / JSON output
```

---

## Installation

Requires **Python 3.10+** (tested on 3.10–3.13).

```bash
git clone https://github.com/NetSPI/NetblockTool.git
cd NetblockTool
pip3 install -r requirements.txt
```

Or install as a package, which provides a `netblocktool` command:

```bash
pip3 install .
```

Runtime dependencies are just `requests` and `beautifulsoup4`.

---

## Quick start

```bash
python3 NetblockTool.py Google
```

Verbose, IPv4 only, skipping search engines:

```bash
python3 NetblockTool.py -v -4 -ng Google
```

Include subsidiaries (set a real contact string for the SEC first):

```bash
export NETBLOCKTOOL_USER_AGENT="Acme Security research@acme.com"
python3 NetblockTool.py -v -s Google
```

---

## CLI reference

```
python3 NetblockTool.py [options] {target company}
```

### Common options

| Flag | Description |
|---|---|
| `-l`, `--list` | List mode; target is a file with one company per line |
| `-o`, `--output` | Output file name (no extension; default is the target name) |
| `--output-dir` | Directory to write output files to (default: cwd) |
| `-v`, `--verbose` | Verbose/debug logging |
| `-q`, `--quiet` | Quiet mode; warnings and errors only |
| `-h`, `--help` | Show help and exit |
| `--version` | Show version and exit |

### Data retrieval & processing

| Flag | Description |
|---|---|
| `-n`, `--no-wildcard` | Exact query (`query = target`) |
| `-w`, `--wildcard` | Full wildcard query (`query = *target*`); many more false positives |
| `-ng`, `--no-google` | Skip search-engine discovery entirely |
| `-c`, `--company-name` | Company name if different from the target |
| `-e`, `--threshold` | Only return results with a confidence score ≥ *SCORE* (0–99) |
| `-p`, `--poc-out` | Retrieve and write point-of-contact information |
| `-4`, `--ipv4` | Only return IPv4 netblocks |
| `-6`, `--ipv6` | Only return IPv6 netblocks |
| `--no-subsumed` | Omit networks fully contained inside another reported network |
| `--no-asn-expansion` | Do not expand ASNs into their announced prefixes |
| `--registries` | Comma-separated registries (`arin,ripe,apnic,afrinic,lacnic`) |
| `--search-provider` | Passive search provider (`none`, `google`) |

### Company subsidiaries

| Flag | Description |
|---|---|
| `-s`, `--subsidiary` | Discover subsidiaries via SEC EDGAR and include their netblocks |
| `-sn`, `--subsidiary-name` | Company name to use when fetching subsidiaries |
| `-sp`, `--subsidiary-parse-alt` | *Deprecated*; the parser now tries every strategy automatically |
| `-so`, `--subsidiary-out` | Write subsidiary names to `Company_subsidiaries.txt` |
| `-u`, `--user-agent` | Identification string sent to the SEC and other sources |

### Physical location

| Flag | Description |
|---|---|
| `-g`, `--geolocation` | Retrieve geolocation data where available |
| `-a`, `--address-out` | Include registered address information in the output |
| `-ag`, `--address-grep` | Only return netblocks whose address contains *TEXT* |

### Output format

| Flag | Description |
|---|---|
| `--json` | Also write machine-readable JSON output |
| `--json-only` | Write only JSON, no CSV |
| `--legacy-csv` | Use the NetblockTool 2.x CSV column layout |

### Network behaviour

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--timeout` | `NETBLOCKTOOL_TIMEOUT` | `15` | Per-request timeout (seconds) |
| `--workers` | `NETBLOCKTOOL_MAX_WORKERS` | `8` | Maximum concurrent lookups |
| `--retries` | `NETBLOCKTOOL_MAX_RETRIES` | `3` | Retry attempts per request |
| `--rate-limit` | `NETBLOCKTOOL_RATE_LIMIT` | `8` | Requests per second, per host |
| `--max-objects` | — | `500` | Cap on registry objects expanded per company |
| — | `NETBLOCKTOOL_USER_AGENT` | — | Identification string |

No API keys are required for any core functionality.

---

## Examples

```bash
# Simple run
python3 NetblockTool.py Google

# Verbose status updates
python3 NetblockTool.py -v Google

# Include subsidiary netblocks
python3 NetblockTool.py -v -s Google

# Point-of-contact information
python3 NetblockTool.py -v -p Google

# Everything: wildcards, PoCs, geolocation, addresses, subsidiary file
python3 NetblockTool.py -wpgav Facebook -so -o Results

# List mode with geolocation and addresses
python3 NetblockTool.py -gavl companies.txt

# High-confidence IPv4 only, no search engines, JSON output
python3 NetblockTool.py -v -4 -ng -e 70 --json -o Results Google

# European registries only
python3 NetblockTool.py -v --registries ripe Spotify
```

---

## Subsidiary discovery

`-s` runs this pipeline:

1. Match the company name against EDGAR's company directory.
2. Fetch its recent 10-K / 20-F / 40-F filings from `data.sec.gov`.
3. Locate the **Exhibit 21** ("Subsidiaries of the Registrant") document.
4. Parse the subsidiary table, identifying the company-name column
   structurally rather than by guessing at HTML tag names.
5. Normalise and deduplicate the names.
6. Query the registries for each, preserving which company produced each result.

Results are written to `Company_subsidiaries.csv`, and every row's `subsidiary`
column records its origin. Use `-so` to also write a plain list of names.

**The SEC requires identification.** Set a descriptive User-Agent containing
real contact details or SEC may block you:

```bash
export NETBLOCKTOOL_USER_AGENT="Acme Security research@acme.com"
# or
python3 NetblockTool.py -v -s -u "Acme Security research@acme.com" Google
```

Not every company yields subsidiaries. Private companies, foreign issuers,
companies that are themselves subsidiaries, and companies that filed on paper
all produce an empty list. This is expected, is logged as a warning, and does
not stop the run.

---

## IPv4 and IPv6

Both are fully supported throughout. Use `-4` or `-6` to restrict output.
Netblocks are parsed with the standard library `ipaddress` module, so:

* addresses are canonicalised (`2001:DB8::/32` → `2001:db8::/32`);
* host bits are tolerated (`8.8.8.5/24` → `8.8.8.0/24`);
* non-routable space (RFC 1918, loopback, link-local, multicast, reserved) is
  scored to zero rather than reported as company-owned;
* a network fully contained inside a larger reported network keeps its
  confidence and is flagged `subsumed`, rather than being dropped or
  downgraded. Use `--no-subsumed` to omit them. Address totals never
  double-count overlapping networks.

---

## Output format

Default CSV columns:

| Column | Description |
|---|---|
| `company` | Target company this result was gathered for |
| `subsidiary` | Subsidiary that produced it, if any |
| `cidr` | The netblock |
| `ip_version` | `4` or `6` |
| `registry` | Source registry (`arin`, `ripe`, …) |
| `asn` | Announcing ASN, when derived from BGP data |
| `asn_holder` | Entity holding that AS. If it is not the company, the prefix is announced by a third party (usually an upstream provider) |
| `organization` | Registered organisation name |
| `confidence` | `confirmed`, `probable`, `weak` or `unlikely` |
| `confidence_score` | Numeric score, 0–99 |
| `subsumed` | `yes` when this network sits inside another reported network. Structural only — it does not lower confidence |
| `evidence` | Every scored reason behind the score |
| `source` | URL of the record the data came from |
| `address` | Registered address |
| `country`, `city`, `state` | Location fields |
| `poc` | Point of contact, with `-p` |
| `discovered_at` | UTC timestamp |

`--legacy-csv` reproduces the 2.x layout (`Network, Name, ID, Type, Confidence,
Score Rationale, Resource URL`, plus optional address and geolocation columns).

`--json` writes the same data with structured evidence:

```json
{
  "metadata": { "tool": "NetblockTool", "version": "3.0.0", "target": "Google" },
  "count": 1,
  "netblocks": [
    {
      "cidr": "8.8.8.0/24",
      "ip_version": 4,
      "registry": "arin",
      "asn": "AS15169",
      "confidence": "confirmed",
      "confidence_score": 88,
      "evidence": [
        { "code": "BASE_ASN", "points": 25, "detail": "prefix announced by matched ASN" },
        { "code": "NAME_EXACT", "points": 35, "detail": "'Google LLC' normalises to 'google'" }
      ]
    }
  ]
}
```

All CSV values are escaped, and any value beginning with `=`, `+`, `-` or `@`
is prefixed with an apostrophe to prevent spreadsheet formula injection.

---

## Confidence scoring

Scoring is additive and transparent. Each netblock starts at a baseline set by
how it was found, then accumulates named evidence.

| Evidence code | Points | Meaning |
|---|---:|---|
| `BASE_ORG_DIRECT` | +45 | Registered directly to a matched organisation |
| `BASE_CUSTOMER` | +35 | Registry customer / reassignment record |
| `BASE_NETWORK` | +30 | Network record matched by name |
| `BASE_ASN` | +25 | Prefix announced by a matched ASN |
| `BASE_CONTACT` | +12 | Matched person/role is only an admin-c/tech-c contact |
| `BASE_SEARCH` | +10 | Search-engine result only |
| `NAME_EXACT` | +35 | Normalised registry name equals the company name |
| `NAME_WITH_SUFFIX` | +28 | Matches company name plus a legal suffix |
| `NAME_PREFIX` | +14 | Registry name begins with the company name |
| `NAME_CONTAINS` | +8 | Company name appears inside the registry name |
| `ORG_HANDLE_LINK` | +20 | Linked to the resolved organisation handle |
| `ASN_ORG_LINK` | +15 | ASN is registered to the company |
| `AUTHORITATIVE_REGISTRY` | +5 | Came from an RIR, not a search engine |
| `ADDRESS_MATCH` | 0…+15 | Matches the company's dominant registered address |
| `SUBSIDIARY_MATCH` | +10 | Attributed via a confirmed SEC subsidiary |
| `CORROBORATED` | +8 | Same CIDR reported by two independent source types |
| `NAME_MISMATCH` | −40 | Company name absent from the registry name |
| `ALPHA_SUFFIX` | −10 | Letters glued after the name (`GOOGLEFIBER` for `Google`) |
| `ALPHA_PREFIX` | −10 | Letters glued before it (wildcard mode only) |
| `CONFLICTING_ORG` | −25 | Registry names a different organisation |
| `NOT_PUBLIC` | −100 | Not globally routable address space |
| `SUBSUMED` | 0 | Contained within a larger reported network (flag only; does not change the score) |
| `NO_CIDR` | 0 | No valid network information |
| `THIRD_PARTY_ORIGIN` | 0 | Prefix announced by an AS the company does not hold |

Totals are clamped to 0–99 and mapped to bands:

| Band | Score | Meaning |
|---|---|---|
| `confirmed` | ≥ 80 | An authoritative registry record names the company |
| `probable` | ≥ 55 | Strong but indirect evidence |
| `weak` | ≥ 25 | A plausible association only |
| `unlikely` | < 25 | Reported for completeness |

**`confirmed` means the registry says so — nothing more.** It is not
verification of ownership by any other means, and registry data can be stale or
wrong. Search-engine evidence alone can never reach `confirmed`.

---

## Data sources

| Source | Used for | Key required |
|---|---|---|
| [ARIN Whois-RWS](https://www.arin.net/resources/registry/whois/rws/api/) | Orgs, networks, customers, ASNs, PoCs | No |
| RDAP — RIPE NCC, APNIC, AFRINIC, LACNIC | Entity and network records | No |
| [RIPE database REST](https://docs.db.ripe.net/Data-Access/RESTful-API/) | Netblocks for RIPE organisations | No |
| [RIPEstat](https://stat.ripe.net/docs/data_api) | ASN announced prefixes, prefix origin ASNs | No |
| [SEC EDGAR](https://www.sec.gov/os/accessing-edgar-data) | Subsidiary discovery | No (UA required) |
| ipinfo.io JSON | Approximate geolocation | No (rate limited) |
| Google | Optional netblock discovery | No |

---

## Limitations

* **Search-engine results are unreliable by design.** Google actively blocks
  automated queries. The tool detects CAPTCHA and rate-limit responses, reports
  them, and continues without search data — it makes **no attempt** to bypass
  anti-bot controls. Prefer the authoritative registry sources; `-ng` disables
  search entirely.
* **RDAP entity search is optional in the standard**, and coverage varies.
  Only ARIN embeds networks in entity results; RIPE organisations are resolved
  through the RIPE database instead. APNIC, AFRINIC and LACNIC have no
  equivalent bulk inverse lookup, so they find organisations but few netblocks.
* **ASN discovery uses two paths.** First, registry ASN records under matching
  organisations. If there are none, the tool asks BGP which AS originates the
  company's organisation-registered prefixes, and expands any AS whose holder
  name matches the company. This finds ASNs registered to a former parent or an
  acquiring entity, which registry lookup alone cannot. Reassignments are never
  used as seeds, since those are announced by the upstream provider, and probes
  are spread across every matched organisation so regional entities announcing
  from a different AS are not missed. Both paths are skipped with
  `--no-asn-expansion`.
* **ASN prefixes are routing data, not allocations.** An AS may announce space
  belonging to transit customers. Such results get the lower `BASE_ASN`
  baseline. ASNs announcing more than 2,000 prefixes are truncated.
* **Not every company has extractable subsidiaries.** See above.
* **Exhibit 21 layouts vary enormously.** The parser handles the common table
  and plain-text forms; unusual filings may yield partial results.
* **Geolocation is approximate**, reflecting where space is registered or
  announced, not where any host physically sits.
* **Registry data can be stale.** Reassignments and acquisitions frequently lag
  in WHOIS. Always corroborate before acting on results.
* Only public registry, filing and search data is consulted. Address space that
  is unregistered, registered under an unrelated shell name, or held by a cloud
  provider on the company's behalf will not be found.

---

## Troubleshooting

**"No netblocks found"**
Try `-w` for a broader wildcard query, or `-c` if the registered entity name
differs from the trading name (`-c "Alphabet"` for `Google`). Check the target
is not spelled with a legal suffix (`Google`, not `Google Inc`).

**`[WARN] Google served an anti-bot challenge (CAPTCHA)`**
Expected and harmless. Registry results are unaffected. Wait, change egress IP,
or run with `-ng`.

**SEC returns 403 / no subsidiaries**
Set a real contact string: `-u "Your Org you@example.com"` or
`NETBLOCKTOOL_USER_AGENT`. The SEC blocks unidentified automated clients.

**Results changed between runs**
Registry data is live and does change. If the count dropped, check the
`Source errors` line and the warnings at the end of the run: a failed
sub-request silently reduces results, and the tool now tells you when that
happened.

**Too many false positives**
Raise the threshold with `-e 70`, avoid `-w`, and filter on `confidence`.

**Timeouts or rate limiting**
Increase `--timeout`, lower `--rate-limit`, and reduce `--workers`.

**`requires Python 3.10 or newer`**
Check `python3 -V`. Use a `venv` on a newer interpreter if needed.

---

## Development

```bash
pip3 install -r requirements-dev.txt

pytest -q                          # unit suite, no network access required
python3 tests/smoke/smoke_test.py  # end-to-end smoke test against a local mock
ruff check .               # linting
python3 -m compileall .    # syntax check
mypy netblocktool          # advisory; the codebase is partially typed
```

`tests/smoke/smoke_test.py` starts an in-process mock of every external
service (ARIN, RDAP, RIPE DB, RIPEstat, SEC EDGAR) and drives the real CLI end
to end, asserting on the files it produces: output formats, IPv4/IPv6 filters,
subsidiary discovery, point-of-contact output, path-traversal and CSV-injection
defences, and behaviour under partial and total registry outage.

The test suite is fully offline. All HTTP traffic is served by a fake client in
`tests/conftest.py` using fixtures in `tests/fixtures/`, so tests never depend
on ARIN, SEC, RDAP, RIPEstat or Google being reachable or behaving in any
particular way.

To add a search backend, subclass `SearchProvider` in `netblocktool/search/`
and register it in `PROVIDERS`. To add a registry, implement `RegistryClient`
in `netblocktool/registries/`.

---

## Background

The original design and methodology are described in NetSPI's blog post:
<https://blog.netspi.com/netblocktool/>

## License

New BSD. See [LICENSE](LICENSE).
