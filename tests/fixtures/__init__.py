"""Realistic fixture payloads for external services.

These mirror the shape of real responses (including ARIN's ``{"$": value}``
JSON-from-XML transliteration) so parsing regressions are caught without ever
touching the live services.
"""

from __future__ import annotations

# -- ARIN Whois-RWS ---------------------------------------------------------

ARIN_ORGS_SEARCH = {
    "orgs": {
        "@xmlns": "http://www.arin.net/whoisrws/core/v1",
        "orgRef": [
            {
                "@handle": "GOGL",
                "@name": "Google LLC",
                "$": "https://whois.arin.net/rest/org/GOGL",
            },
            {
                "@handle": "GOOGL-2",
                "@name": "Google Fiber Inc.",
                "$": "https://whois.arin.net/rest/org/GOOGL-2",
            },
        ],
    }
}

#: Single-result form: ARIN collapses a one-element list into a bare object.
ARIN_ORGS_SEARCH_SINGLE = {
    "orgs": {
        "orgRef": {
            "@handle": "GOGL",
            "@name": "Google LLC",
            "$": "https://whois.arin.net/rest/org/GOGL",
        }
    }
}

ARIN_ORG_DETAIL = {
    "org": {
        "handle": {"$": "GOGL"},
        "name": {"$": "Google LLC"},
        "city": {"$": "Mountain View"},
        "iso3166-2": {"$": "CA"},
        "iso3166-1": {"name": {"$": "United States"}, "code2": {"$": "US"}},
        "postalCode": {"$": "94043"},
        "streetAddress": {
            "line": [
                {"@number": "0", "$": "1600 Amphitheatre Parkway"},
            ]
        },
    }
}

#: Address with several street lines, which the original code mishandled.
ARIN_ORG_DETAIL_MULTILINE = {
    "org": {
        "handle": {"$": "MULTI"},
        "name": {"$": "Multiline Corp"},
        "city": {"$": "Springfield"},
        "iso3166-1": {"name": {"$": "United States"}},
        "postalCode": {"$": "12345"},
        "streetAddress": {
            "line": [
                {"@number": "0", "$": "Building 5"},
                {"@number": "1", "$": "123 Main Street"},
            ]
        },
    }
}

ARIN_ORG_NETS = {
    "nets": {
        "netRef": [
            {
                "@endAddress": "8.8.8.255",
                "@startAddress": "8.8.8.0",
                "@handle": "NET-8-8-8-0-1",
                "@name": "GOOGLE-CLOUD",
                "$": "https://whois.arin.net/rest/net/NET-8-8-8-0-1",
            },
            {
                "@endAddress": "2001:4860:4860:ffff:ffff:ffff:ffff:ffff",
                "@startAddress": "2001:4860:4860::",
                "@handle": "NET6-2001-4860-1",
                "@name": "GOOGLE-IPV6",
                "$": "https://whois.arin.net/rest/net/NET6-2001-4860-1",
            },
        ]
    }
}

ARIN_ORG_ASNS = {
    "asns": {
        "asnRef": {
            "@endAsNumber": "15169",
            "@startAsNumber": "15169",
            "@handle": "AS15169",
            "@name": "GOOGLE",
            "$": "https://whois.arin.net/rest/asn/AS15169",
        }
    }
}

ARIN_CUSTOMERS_SEARCH = {
    "customers": {
        "customerRef": {
            "@handle": "C00876643",
            "@name": "GOOGLE INC-040731031303",
            "$": "https://whois.arin.net/rest/customer/C00876643",
        }
    }
}

ARIN_CUSTOMER_DETAIL = {
    "customer": {
        "handle": {"$": "C00876643"},
        "name": {"$": "GOOGLE INC-040731031303"},
        "city": {"$": "Plano"},
        "iso3166-1": {"name": {"$": "United States"}},
        "postalCode": {"$": "75075"},
        "streetAddress": {"line": {"@number": "0", "$": "Private Address"}},
        "nets": {
            "netRef": {
                "@startAddress": "69.224.21.208",
                "@endAddress": "69.224.21.215",
                "@handle": "NET-69-224-21-208-1",
                "@name": "SBC-CUST",
            }
        },
    }
}

ARIN_NET_DETAIL = {
    "net": {
        "handle": {"$": "NET-107-167-160-0-1"},
        "name": {"$": "GOOGLE-CLOUD"},
        "orgRef": {"@handle": "GOGL", "@name": "Google LLC"},
        "netBlocks": {
            "netBlock": {
                "startAddress": {"$": "107.167.160.0"},
                "endAddress": {"$": "107.167.191.255"},
                "cidrLength": {"$": "19"},
                "type": {"$": "DA"},
            }
        },
    }
}

#: A net record carrying several blocks, returned as a list.
ARIN_NET_DETAIL_MULTIBLOCK = {
    "net": {
        "handle": {"$": "NET-MULTI-1"},
        "name": {"$": "EXAMPLE-MULTI"},
        "netBlocks": {
            "netBlock": [
                {"startAddress": {"$": "192.0.2.0"}, "cidrLength": {"$": "24"}},
                {"startAddress": {"$": "198.51.100.0"}, "cidrLength": {"$": "24"}},
            ]
        },
    }
}

ARIN_ORG_POCS = {
    "pocs": {
        "pocLinkRef": {
            "@description": "Tech",
            "@handle": "ZG39-ARIN",
            "$": "https://whois.arin.net/rest/poc/ZG39-ARIN",
        }
    }
}

ARIN_POC_DETAIL = {
    "poc": {
        "handle": {"$": "ZG39-ARIN"},
        "firstName": {"$": "Jane"},
        "lastName": {"$": "Doe"},
        "companyName": {"$": "Google LLC"},
        "city": {"$": "Mountain View"},
        "iso3166-1": {"name": {"$": "United States"}},
        "postalCode": {"$": "94043"},
        "streetAddress": {"line": {"@number": "0", "$": "1600 Amphitheatre Parkway"}},
        "emails": {"email": [{"$": "noc@example.com"}, {"$": "abuse@example.com"}]},
        "phones": {"phone": {"number": {"$": "+1-650-253-0000"}}},
    }
}

#: An org record with no address at all - the original code raised IndexError
#: on ``address[0]`` for this.
ARIN_ORG_DETAIL_NO_ADDRESS = {
    "org": {"handle": {"$": "BARE"}, "name": {"$": "Bare Org"}}
}


# -- RDAP -------------------------------------------------------------------

RDAP_ENTITY_SEARCH = {
    "rdapConformance": ["rdap_level_0", "cidr0"],
    "entitySearchResults": [
        {
            "objectClassName": "entity",
            "handle": "ORG-EX1-RIPE",
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Example Networks B.V."],
                    ["adr", {"label": "Sesamstraat 1\n1234 AB\nAmsterdam\nNetherlands"},
                     "text", ["", "", "", "", "", "", ""]],
                ],
            ],
            "links": [
                {"rel": "self", "href": "https://rdap.db.ripe.net/entity/ORG-EX1-RIPE"}
            ],
            "networks": [
                {
                    "objectClassName": "ip network",
                    "handle": "193.0.0.0 - 193.0.7.255",
                    "name": "EXAMPLE-NET",
                    "startAddress": "193.0.0.0",
                    "endAddress": "193.0.7.255",
                    "country": "NL",
                    "cidr0_cidrs": [{"v4prefix": "193.0.0.0", "length": 21}],
                }
            ],
            "autnums": [
                {"objectClassName": "autnum", "startAutnum": 3333, "endAutnum": 3333}
            ],
        }
    ],
}

RDAP_ENTITY_SEARCH_EMPTY: dict = {"rdapConformance": ["rdap_level_0"]}

RDAP_IP_LOOKUP = {
    "objectClassName": "ip network",
    "handle": "NET-8-8-8-0-1",
    "startAddress": "8.8.8.0",
    "endAddress": "8.8.8.255",
    "country": "US",
    "name": "GOOGLE-CLOUD",
}


# -- RIPEstat ---------------------------------------------------------------

RIPESTAT_ANNOUNCED_PREFIXES = {
    "status": "ok",
    "data": {
        "resource": "15169",
        "prefixes": [
            {"prefix": "8.8.8.0/24", "timelines": []},
            {"prefix": "8.8.4.0/24", "timelines": []},
            {"prefix": "2001:4860::/32", "timelines": []},
            {"prefix": "not-a-prefix", "timelines": []},
        ],
    },
}

RIPESTAT_EMPTY = {"status": "ok", "data": {"resource": "64496", "prefixes": []}}


# -- SEC EDGAR --------------------------------------------------------------

EDGAR_COMPANY_TICKERS = {
    "0": {"cik_str": 1652044, "ticker": "GOOGL", "title": "Alphabet Inc."},
    "1": {"cik_str": 320193, "ticker": "AAPL", "title": "Apple Inc."},
    "2": {"cik_str": 789019, "ticker": "MSFT", "title": "MICROSOFT CORP"},
}

EDGAR_SUBMISSIONS = {
    "cik": "1652044",
    "name": "Alphabet Inc.",
    "filings": {
        "recent": {
            "accessionNumber": ["0001652044-24-000022", "0001652044-23-000016",
                                "0001652044-24-000100"],
            "form": ["10-K", "10-K", "8-K"],
            "filingDate": ["2024-01-31", "2023-02-03", "2024-04-01"],
            "primaryDocument": ["goog-20231231.htm", "goog-20221231.htm", "goog-8k.htm"],
        }
    },
}

EDGAR_FILING_INDEX = {
    "directory": {
        "name": "/Archives/edgar/data/1652044/000165204424000022",
        "item": [
            {"name": "goog-20231231.htm", "type": "10-K", "size": "1000000"},
            {"name": "goog-ex211_2023.htm", "type": "EX-21.1", "size": "12000"},
            {"name": "goog-ex231.htm", "type": "EX-23.1", "size": "5000"},
        ],
    }
}

EDGAR_FILING_INDEX_NO_EX21 = {
    "directory": {
        "name": "/Archives/edgar/data/1652044/000165204423000016",
        "item": [{"name": "goog-20221231.htm", "type": "10-K", "size": "1000000"}],
    }
}

EX21_HTML_TABLE = """
<html><body>
<p>Exhibit 21.1</p>
<p>SUBSIDIARIES OF THE REGISTRANT</p>
<table>
  <tr><td>Legal Name</td><td>Jurisdiction of Incorporation</td></tr>
  <tr><td>Google LLC</td><td>Delaware</td></tr>
  <tr><td>YouTube, LLC</td><td>Delaware</td></tr>
  <tr><td>Fitbit LLC</td><td>Delaware</td></tr>
  <tr><td>DeepMind Technologies Limited</td><td>United Kingdom</td></tr>
  <tr><td>Google Ireland Limited</td><td>Ireland</td></tr>
</table>
</body></html>
"""

#: Three-column layout with ownership percentages and footnote markers.
EX21_HTML_THREE_COLUMN = """
<html><body>
<table>
  <tr><th>Name of Subsidiary</th><th>State or Other Jurisdiction</th>
      <th>Percentage Owned</th></tr>
  <tr><td>Acme Manufacturing Inc. (1)</td><td>Delaware</td><td>100%</td></tr>
  <tr><td>Acme Logistics GmbH</td><td>Germany</td><td>100%</td></tr>
  <tr><td>Acme Financial Services LLC</td><td>Nevada</td><td>80%</td></tr>
  <tr><td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td></tr>
</table>
</body></html>
"""

#: Legacy pre-formatted text exhibit.
EX21_TEXT = """
                                                        EXHIBIT 21

                    SUBSIDIARIES OF THE REGISTRANT

Name                                    Jurisdiction of Incorporation
----                                    -----------------------------
Widget Industries Inc.                  Delaware
Widget Europe Limited                   United Kingdom
Widget Asia Pte. Ltd.                   Singapore
"""

EX21_EMPTY = "<html><body><p>Exhibit 21.1</p><p>None.</p></body></html>"


# -- Google -----------------------------------------------------------------

GOOGLE_RESULTS_HTML = """
<html><body>
<div><a href="/url?q=https://ipinfo.io/AS15169/8.8.8.0/24&amp;sa=U">
  8.8.8.0/24 Netblock Details - Google LLC</a></div>
<div><a href="/url?q=https://ipinfo.io/AS15169/8.8.4.0/24&amp;sa=U">
  8.8.4.0/24 Netblock Details - Google LLC</a></div>
<div><a href="https://ipinfo.io/AS15169/2001:4860::/32">
  2001:4860::/32 Netblock Details - Google LLC</a></div>
<div><a href="/url?q=https://example.com/unrelated&amp;sa=U">Unrelated result</a></div>
</body></html>
"""

GOOGLE_CAPTCHA_HTML = """
<html><body><div>
Our systems have detected unusual traffic from your computer network.
Please try your request again later.
</div></body></html>
"""

GOOGLE_NO_RESULTS_HTML = """
<html><body><p>Your search did not match any documents.</p></body></html>
"""


# -- RIPE database (inverse org lookup) -------------------------------------

RIPE_DB_INETNUM_SEARCH = {
    "objects": {
        "object": [
            {
                "type": "inetnum",
                "primary-key": {"attribute": [
                    {"name": "inetnum", "value": "193.0.0.0 - 193.0.7.255"},
                ]},
                "attributes": {"attribute": [
                    {"name": "inetnum", "value": "193.0.0.0 - 193.0.7.255"},
                    {"name": "netname", "value": "EXAMPLE-NET"},
                    {"name": "country", "value": "NL"},
                    {"name": "org", "value": "ORG-EX1-RIPE"},
                ]},
            },
            {
                "type": "inetnum",
                "primary-key": {"attribute": [
                    {"name": "inetnum", "value": "212.58.224.0 - 212.58.255.255"},
                ]},
                "attributes": {"attribute": [
                    {"name": "netname", "value": "EXAMPLE-NET-2"},
                    {"name": "country", "value": "GB"},
                ]},
            },
        ]
    }
}

#: Single-object form: RIPE collapses a one-element list into a bare object.
RIPE_DB_INET6NUM_SEARCH = {
    "objects": {
        "object": {
            "type": "inet6num",
            "primary-key": {"attribute": {
                "name": "inet6num", "value": "2001:610::/32"}},
            "attributes": {"attribute": [
                {"name": "netname", "value": "EXAMPLE-V6"},
                {"name": "country", "value": "NL"},
            ]},
        }
    }
}

RIPE_DB_EMPTY: dict = {"objects": {"object": []}}


RIPESTAT_PREFIX_OVERVIEW = {
    "status": "ok",
    "data": {
        "resource": "66.211.168.0/22",
        "asns": [{"asn": 17012, "holder": "PAYPAL-CORP"}],
        "announced": True,
    },
}

RIPESTAT_PREFIX_OVERVIEW_MULTI = {
    "status": "ok",
    "data": {
        "resource": "8.8.8.0/24",
        "asns": [{"asn": 15169, "holder": "GOOGLE"}, {"asn": 396982, "holder": "GOOGLE-CLOUD"}],
    },
}

RIPESTAT_PREFIX_OVERVIEW_UNANNOUNCED = {
    "status": "ok",
    "data": {"resource": "192.0.2.0/24", "asns": [], "announced": False},
}
