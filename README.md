# NetblockTool — modernize-from-upstream

This branch brings NetblockTool up to date with the v3.7.1 upstream release,
which addresses both issues raised in the review.

---

## What was fixed

### 1. SyntaxWarning: invalid escape sequence

The older codebase used unescaped backslashes in regex strings — for example
`re.compile("\d+")` instead of `re.compile(r"\d+")`. Python 3.12+ promotes
these to `SyntaxWarning` and they will become `SyntaxError` in a future
release.

Every regex string in the updated codebase uses raw string literals (`r"..."`).
You can confirm no warnings are produced:

```bash
python3 -W error NetblockTool.py --help
```

No output on stderr means zero warnings.

### 2. ARIN returns no data

The previous version POSTed queries to `https://whois.arin.net/ui/query.do`
and regex-scraped resource URLs from the returned HTML. That web UI was retired;
the endpoint no longer returns usable results, which is why ARIN queries came
back empty.

The updated ARIN client (`netblocktool/registries/arin.py`) uses the
documented Whois-RWS REST API instead:

| Endpoint | Purpose |
|---|---|
| `/rest/orgs;name=<q>` | Organisation name search |
| `/rest/org/{handle}/nets` | Networks registered to an org |
| `/rest/org/{handle}/asns` | ASNs registered to an org |
| `/rest/customers;name=<q>` | Customer/reassignment records |
| `/rest/nets;name=<q>` | Network name search |

Reference: <https://www.arin.net/resources/registry/whois/rws/api/>

---

## Quick verification

```bash
# Install dependencies
pip3 install -r requirements.txt

# Run against NetSPI (the tool author's own org — a known-good target)
python3 NetblockTool.py -4 -ng netspi

# Expected: 7 IPv4 netblocks, confidence confirmed/probable
```

Progress output shows each registry step at INFO level. You should see ARIN org
and network lookups completing rather than silently returning nothing. Add `-v`
for full debug output.

---

## Running the test suite

```bash
pip3 install pytest
pytest -q
```

All 523 unit tests run fully offline (no network access required). The test
suite also covers the ARIN client via a fixture-driven mock of the REST API.

---

## Dependencies

Runtime: `requests>=2.31` and `beautifulsoup4>=4.12` only.

The old dependencies (`netaddr`, `lxml`, `fuzzywuzzy`, `tqdm`) were removed
upstream in 3.0 — the first three were replaced by stdlib equivalents and the
latter two were only used by dead code.
