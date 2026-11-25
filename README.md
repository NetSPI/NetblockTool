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

## Overview

NetblockTool passively discovers IP ranges owned by a company by querying public registry, BGP, and filing data - no traffic is ever sent to the target's hosts.

**Data sources:**
- **ARIN** - Whois-RWS REST API (`/rest/orgs`, `/rest/org/{handle}/nets`, `/rest/org/{handle}/asns`)
- **RDAP** - RIPE NCC, APNIC, AFRINIC, LACNIC
- **BGPView** - ASN -> announced prefixes; prefix -> origin AS discovery
- **SEC EDGAR** - Exhibit 21 subsidiary filings (optional, `-s`)
- **Google dorking** - passive search enrichment (optional, skipped automatically if blocked)

Each result is given a transparent confidence score (`confirmed / probable / weak / unlikely`) with a full evidence trail written to the CSV.

---

## Install

```bash
git clone https://github.com/NetSPI/NetblockTool.git
cd NetblockTool
pip3 install -r requirements.txt
```

Requires Python 3.10+.

---

## Quick Start

```bash
# Basic run - registry + search enrichment
python3 NetblockTool.py Google

# IPv4 only, skip search engine
python3 NetblockTool.py -4 -ng netspi

# Include subsidiary companies (via SEC EDGAR)
python3 NetblockTool.py -s Google

# Google files as "Alphabet Inc" - use -sn to match the legal name
python3 NetblockTool.py -s -sn "Alphabet Inc" Google

# Full enrichment - subsidiaries, PoCs, geolocation, addresses, JSON output
python3 NetblockTool.py -wpgav Facebook -so -o Results --json

# List mode - one company per line
python3 NetblockTool.py -gavl companies.txt
```

Add `-v` for debug output. Without it, INFO-level progress messages are still printed so the tool never appears to hang on large queries.

---

## Output

Results are written to `{Company}.csv` by default. Use `-o Name` to set a custom filename (no extension).

**CSV columns:** Company, Subsidiary, Network, IP Version, Registry, ASN, ASN Holder, Organization, Name, Handle, Type, Confidence, Confidence Score, Subsumed, Evidence, Source URL, Address, Country, City, State, Geolocation, PoC, Discovered At

The **Evidence** column contains the scoring audit trail - a semicolon-separated list of `CODE(±points): detail` entries explaining exactly why a netblock scored what it did.

**Confidence bands:**

| Band | Score | Meaning |
|---|---|---|
| `confirmed` | ≥ 80 | Authoritative registry record names the company |
| `probable` | ≥ 55 | Strong but indirect evidence |
| `weak` | ≥ 25 | Plausible association |
| `unlikely` | < 25 | Reported for completeness |

**JSON output:** Add `--json` to write `{Company}.json` alongside the CSV, or `--json-only` to skip the CSV entirely.

---

## All Options

```
Data retrieval & processing:
  -n, --no-wildcard       Exact query (query = target)
  -w, --wildcard          Full wildcard query (query = *target*); more false positives
  -ng, --no-google        Skip search-engine discovery
  -c COMPANY              Company name if different from the target argument
  -e SCORE                Only return results with confidence score >= SCORE
  -p, --poc-out           Retrieve point-of-contact information
  -4, --ipv4              Only return IPv4 netblocks
  -6, --ipv6              Only return IPv6 netblocks
  --no-subsumed           Omit networks contained inside a larger reported network
  --no-asn-expansion      Do not expand ASNs into announced prefixes
  --registries LIST       Comma-separated registries (default: arin,ripe,apnic,afrinic,lacnic)

Company subsidiaries:
  -s, --subsidiary        Discover subsidiaries via SEC EDGAR
  -sn NAME                Legal name to use for EDGAR subsidiary search
  -so, --subsidiary-out   Write subsidiary names to {Company}_subsidiaries.txt
  -u, --user-agent TEXT   Identification string for SEC EDGAR
                          (required by SEC policy; see https://www.sec.gov/os/accessing-edgar-data)

Physical location:
  -g, --geolocation       Retrieve geolocation data
  -a, --address-out       Include registered address in output
  -ag TEXT                Only return netblocks whose address contains TEXT

Output format:
  -o NAME                 Output filename (no extension)
  --output-dir DIR        Directory to write output files
  --json                  Write JSON output alongside CSV
  --json-only             Write JSON only, no CSV
  --legacy-csv            Use NetblockTool 2.x CSV column layout

Network behaviour:
  --timeout SECONDS       Per-request timeout (default: 15)
  --workers N             Max concurrent lookups (default: 8)
  --retries N             Retry attempts per request (default: 3)
  --rate-limit RPS        Requests per second per host (default: 8)
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NETBLOCKTOOL_USER_AGENT` | Firefox UA | User-Agent / SEC identification string |
| `NETBLOCKTOOL_TIMEOUT` | `15.0` | Per-request timeout in seconds |
| `NETBLOCKTOOL_MAX_WORKERS` | `8` | Maximum concurrent lookups |
| `NETBLOCKTOOL_MAX_RETRIES` | `3` | Retry attempts per request |
| `NETBLOCKTOOL_RATE_LIMIT` | `8.0` | Requests per second per host |
| `NETBLOCKTOOL_CACHE_DIR` | (disabled) | Directory for on-disk HTTP response cache |

Command-line flags always take precedence over environment variables.

---

## Notes

- **SEC EDGAR subsidiary discovery** requires a descriptive User-Agent with real contact details per [SEC policy](https://www.sec.gov/os/accessing-edgar-data). Set `-u "Company Name admin@example.com"` or `NETBLOCKTOOL_USER_AGENT` before using `-s`.
- Companies that file under a different legal name (e.g. Google -> Alphabet Inc, Instagram -> Meta Platforms) must use `-sn "<legal name>"` for subsidiary discovery to work.
- **Google dorking** is best-effort. The tool continues with authoritative registry data if it is blocked.
- **`subsumed` flag** marks a netblock that is fully contained inside another reported network. It does not mean the company doesn't own it - it is a structural note only.

---

## Background

More detail on how the tool works: https://blog.netspi.com/netblocktool/
