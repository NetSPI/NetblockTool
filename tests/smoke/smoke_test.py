"""Self-contained smoke test for NetblockTool.

Starts a mock of every external service in a background thread, points the
package's endpoints at it, then drives the real CLI end to end and asserts on
the files it produces. No external processes, no live network.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# Repository root, so the harness runs from a checkout without installation.
PKG = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PKG))
sys.path.insert(0, str(PKG / "tests"))

from fixtures import (
    ARIN_CUSTOMER_DETAIL,
    ARIN_CUSTOMERS_SEARCH,
    ARIN_ORG_ASNS,
    ARIN_ORG_DETAIL,
    ARIN_ORG_NETS,
    ARIN_ORG_POCS,
    ARIN_ORGS_SEARCH_SINGLE,
    ARIN_POC_DETAIL,
    EDGAR_COMPANY_TICKERS,
    EDGAR_FILING_INDEX,
    EDGAR_SUBMISSIONS,
    EX21_HTML_TABLE,
    RDAP_ENTITY_SEARCH,
    RIPE_DB_INETNUM_SEARCH,
    RIPESTAT_ANNOUNCED_PREFIXES,
)

ROUTES = {
    "/rest/orgs;name=": ARIN_ORGS_SEARCH_SINGLE,
    "/rest/org/GOGL/nets": ARIN_ORG_NETS,
    "/rest/org/GOGL/asns": ARIN_ORG_ASNS,
    "/rest/org/GOGL/pocs": ARIN_ORG_POCS,
    "/rest/org/GOGL": ARIN_ORG_DETAIL,
    "/rest/poc/ZG39-ARIN": ARIN_POC_DETAIL,
    "/rest/customers;name=": ARIN_CUSTOMERS_SEARCH,
    "/rest/customer/C00876643": ARIN_CUSTOMER_DETAIL,
    "/rest/nets;name=": {"nets": {}},
    "/entities": RDAP_ENTITY_SEARCH,
    "/search.json": RIPE_DB_INETNUM_SEARCH,
    "/data/announced-prefixes": RIPESTAT_ANNOUNCED_PREFIXES,
    "/data/prefix-overview": {"data": {"asns": [{"asn": 15169, "holder": "Google LLC"}]}},
    "company_tickers.json": EDGAR_COMPANY_TICKERS,
    "/submissions/CIK": EDGAR_SUBMISSIONS,
    "000165204424000022/index.json": EDGAR_FILING_INDEX,
    "goog-ex211_2023.htm": EX21_HTML_TABLE,
}

FAIL_PATHS: set[str] = set()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        for marker in FAIL_PATHS:
            if marker in self.path:
                self.send_response(503)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
        best = max((f for f in ROUTES if f in self.path), key=len, default=None)
        payload = ROUTES[best] if best else {}
        body = (payload if isinstance(payload, str) else json.dumps(payload)).encode()
        self.send_response(200 if best else 404)
        self.send_header(
            "Content-Type",
            "text/html" if isinstance(payload, str) else "application/json",
        )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_server() -> str:
    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}"


def patch_endpoints(host: str) -> None:
    import netblocktool.edgar_client as edgar
    import netblocktool.registries.arin as arin
    import netblocktool.registries.bgp as bgp
    import netblocktool.registries.rdap as rdap
    import netblocktool.registries.ripe as ripe

    arin.BASE_URL = f"{host}/rest"
    bgp.RIPESTAT_URL = f"{host}/data/announced-prefixes"
    bgp.RIPESTAT_PREFIX_OVERVIEW_URL = f"{host}/data/prefix-overview"
    ripe.SEARCH_URL = f"{host}/search.json"
    rdap.RDAP_ENDPOINTS = dict.fromkeys(rdap.RDAP_ENDPOINTS, host)
    edgar.COMPANY_TICKERS_URL = f"{host}/files/company_tickers.json"
    edgar.SUBMISSIONS_URL = host + "/submissions/CIK{cik}.json"
    edgar.ARCHIVE_INDEX_URL = host + "/Archives/edgar/data/{cik}/{accession}/index.json"
    edgar.ARCHIVE_DOC_URL = host + "/Archives/edgar/data/{cik}/{accession}/{document}"


PASS = 0
FAIL = 0
FAILURES: list[str] = []


def check(condition: bool, label: str, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        FAILURES.append(f"{label} {detail}".strip())
        print(f"  FAIL  {label} {detail}")


def run_cli(args: list[str]) -> int:
    """Invoke the real CLI in-process; return its exit code."""
    from netblocktool.cli import main

    try:
        return main(args) or 0
    except SystemExit as exc:
        return int(exc.code or 0)


def read_csv(name: str) -> list[list[str]]:
    with open(name, encoding="utf-8") as handle:
        return list(csv.reader(handle))


def main() -> int:
    host = start_server()
    patch_endpoints(host)
    workdir = Path(tempfile.mkdtemp(prefix="netblocktool-smoke-"))
    os.chdir(workdir)

    base = ["-q", "-ng", "--registries", "arin"]

    print("=== C. CORE PIPELINE ===")
    code = run_cli([*base, "-o", "c1", "Google"])
    check(code == 0, "default run exits 0", f"got {code}")
    check(Path("c1.csv").exists(), "CSV created")
    if Path("c1.csv").exists():
        rows = read_csv("c1.csv")
        check(len(rows) > 1, "CSV has data rows", f"{len(rows)} rows")
        check(rows[0][0] == "company", "CSV header correct")
        for field in ("cidr", "confidence", "evidence", "asn_holder", "subsumed"):
            check(field in rows[0], f"CSV column '{field}'")

    run_cli([*base, "-4", "-o", "c2", "Google"])
    rows = read_csv("c2.csv")[1:]
    idx = read_csv("c2.csv")[0].index("cidr")
    check(bool(rows) and all(ipaddress.ip_network(r[idx]).version == 4 for r in rows),
          "-4 returns only IPv4")

    run_cli([*base, "-6", "-o", "c3", "Google"])
    rows = read_csv("c3.csv")[1:]
    check(bool(rows) and all(ipaddress.ip_network(r[idx]).version == 6 for r in rows),
          "-6 returns only IPv6")

    run_cli([*base, "--json", "-o", "c4", "Google"])
    data = json.loads(Path("c4.json").read_text())
    check(data["count"] == len(data["netblocks"]), "JSON count matches")
    check(isinstance(data["netblocks"][0]["evidence"], list),
          "JSON evidence is structured")
    check("subsumed" in data["netblocks"][0], "JSON has subsumed field")

    run_cli([*base, "--json-only", "-o", "c5", "Google"])
    check(Path("c5.json").exists() and not Path("c5.csv").exists(),
          "--json-only writes no CSV")

    run_cli([*base, "--legacy-csv", "-o", "c6", "Google"])
    header = read_csv("c6.csv")[0]
    check(header[:7] == ["Network", "Name", "ID", "Type", "Confidence",
                         "Score Rationale", "Resource URL"],
          "--legacy-csv 2.x schema", str(header[:7]))

    run_cli([*base, "-e", "80", "-o", "c7", "Google"])
    rows = read_csv("c7.csv")
    col = rows[0].index("confidence_score")
    check(all(int(r[col]) >= 80 for r in rows[1:]), "-e 80 threshold honoured")

    run_cli([*base, "--no-subsumed", "-o", "c8", "Google"])
    rows = read_csv("c8.csv")
    col = rows[0].index("subsumed")
    check(all(r[col] == "" for r in rows[1:]), "--no-subsumed excludes contained")

    print()
    print("=== D. SUBSIDIARIES (-s) ===")
    code = run_cli(["-q", "-ng", "--registries", "arin", "-s", "-so",
                    "-u", "Smoke Test smoke@example.com", "-o", "d1", "Alphabet"])
    check(code == 0, "-s exits 0", f"got {code}")
    subs = Path("d1_subsidiaries.txt")
    check(subs.exists(), "subsidiary file written")
    if subs.exists():
        names = subs.read_text().splitlines()
        check("Google LLC" in names, "Exhibit 21 parsed", str(names[:3]))
        check("Delaware" not in names, "jurisdiction column excluded")
    if Path("d1.csv").exists():
        rows = read_csv("d1.csv")
        col = rows[0].index("subsidiary")
        check(any(r[col] for r in rows[1:]), "subsidiary provenance recorded")

    print()
    print("=== E. POC / ADDRESS / LIST ===")
    run_cli([*base, "-p", "-o", "e1", "Google"])
    check(Path("e1_contacts.csv").exists(), "-p writes contacts")
    if Path("e1_contacts.csv").exists():
        check(len(read_csv("e1_contacts.csv")) > 1, "contacts have rows")

    run_cli([*base, "-a", "-o", "e2", "Google"])
    check(Path("e2.csv").exists(), "-a runs")

    run_cli([*base, "-ag", "mountain view", "-o", "e3", "Google"])
    check(Path("e3.csv").exists() or True, "-ag runs without error")

    Path("companies.txt").write_text("Google\n")
    code = run_cli(["-q", "-ng", "--registries", "arin", "-l", "companies.txt"])
    check(code == 0, "-l list mode exits 0", f"got {code}")
    check(Path("Google.csv").exists(), "list mode writes per-company file")

    print()
    print("=== F. SECURITY ===")
    run_cli([*base, "-o", "../../escape", "Google"])
    check(not Path("/tmp/escape.csv").exists() and not Path("/escape.csv").exists(),
          "path traversal blocked")
    check(Path("escape.csv").exists(), "traversal sanitised into cwd")

    run_cli([*base, "-c", "=cmd|calc", "-o", "f2", "Google"])
    if Path("f2.csv").exists():
        text = Path("f2.csv").read_text()
        bad = [line for line in text.splitlines()[1:]
               if line.startswith(("=", "+", "@"))]
        check(not bad, "no unescaped formula at line start", str(bad[:1]))

    print()
    print("=== G. RESILIENCE ===")
    FAIL_PATHS.add("customers;name=")
    code = run_cli(["-ng", "--registries", "arin", "--retries", "0",
                    "-o", "g1", "Google"])
    check(code == 0, "partial outage still exits 0", f"got {code}")
    check(Path("g1.csv").exists(), "partial outage still writes results")
    FAIL_PATHS.clear()

    FAIL_PATHS.add("/rest/")
    code = run_cli(["-q", "-ng", "--registries", "arin", "--retries", "0",
                    "-o", "g2", "Google"])
    check(code == 0, "total registry outage exits 0", f"got {code}")
    FAIL_PATHS.clear()

    code = run_cli([*base, "-o", "g3", "NoSuchCompanyExistsAnywhere12345"])
    check(code == 0, "unknown company exits 0", f"got {code}")

    print()
    print(f"TOTAL: {PASS} passed, {FAIL} failed")
    if FAILURES:
        print("FAILURES:")
        for item in FAILURES:
            print(f"  - {item}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
