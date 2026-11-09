"""Registry clients: ARIN Whois-RWS, RDAP and BGP prefix expansion.

Every test uses :class:`FakeHttpClient`; nothing here touches a live registry.
"""

from __future__ import annotations

import pytest
from fixtures import (
    ARIN_CUSTOMER_DETAIL,
    ARIN_CUSTOMERS_SEARCH,
    ARIN_NET_DETAIL,
    ARIN_NET_DETAIL_MULTIBLOCK,
    ARIN_ORG_ASNS,
    ARIN_ORG_DETAIL,
    ARIN_ORG_DETAIL_MULTILINE,
    ARIN_ORG_DETAIL_NO_ADDRESS,
    ARIN_ORG_NETS,
    ARIN_ORG_POCS,
    ARIN_ORGS_SEARCH,
    ARIN_ORGS_SEARCH_SINGLE,
    ARIN_POC_DETAIL,
    RDAP_ENTITY_SEARCH,
    RDAP_ENTITY_SEARCH_EMPTY,
    RDAP_IP_LOOKUP,
    RIPE_DB_EMPTY,
    RIPE_DB_INET6NUM_SEARCH,
    RIPE_DB_INETNUM_SEARCH,
    RIPESTAT_ANNOUNCED_PREFIXES,
    RIPESTAT_EMPTY,
    RIPESTAT_PREFIX_OVERVIEW,
    RIPESTAT_PREFIX_OVERVIEW_MULTI,
    RIPESTAT_PREFIX_OVERVIEW_UNANNOUNCED,
)

from netblocktool.http import HttpError
from netblocktool.models import ObjectType
from netblocktool.registries import query_registries
from netblocktool.registries.arin import ArinClient
from netblocktool.registries.base import as_list, dig, join_address, text_value
from netblocktool.registries.bgp import BgpClient, parse_asn
from netblocktool.registries.rdap import RdapClient, _parse_vcard

# -- ARIN JSON helpers ------------------------------------------------------


class TestArinJsonHelpers:
    @pytest.mark.parametrize("node,expected", [
        ({"$": "value"}, "value"),
        ({"$": "  padded  "}, "padded"),
        ("plain", "plain"),
        (42, "42"),
        (None, ""),
        ({}, ""),
        ({"other": "key"}, ""),
        ([{"$": "first"}, {"$": "second"}], "first"),
    ])
    def test_text_value(self, node, expected):
        assert text_value(node) == expected

    def test_as_list_normalises_single_and_multiple(self):
        # ARIN collapses one-element lists into a bare object.
        assert as_list({"a": 1}) == [{"a": 1}]
        assert as_list([{"a": 1}, {"a": 2}]) == [{"a": 1}, {"a": 2}]
        assert as_list(None) == []

    def test_dig_survives_missing_keys(self):
        assert dig({"a": {"b": "c"}}, "a", "b") == "c"
        assert dig({"a": {}}, "a", "b") is None
        assert dig({}, "a", "b", "c") is None
        assert dig(None, "a") is None
        assert dig("string", "a") is None

    def test_join_address_dedupes_and_skips_blanks(self):
        assert join_address(["123 Main St"], "Springfield", "", "US") == \
            "123 Main St, Springfield, US"
        assert join_address([], "Springfield", "Springfield") == "Springfield"
        assert join_address([]) == ""


# -- ARIN client ------------------------------------------------------------


def arin_routes() -> dict:
    return {
        "/rest/orgs;name=": ARIN_ORGS_SEARCH,
        "/rest/org/GOGL/nets": ARIN_ORG_NETS,
        "/rest/org/GOGL/asns": ARIN_ORG_ASNS,
        "/rest/org/GOGL/pocs": ARIN_ORG_POCS,
        "/rest/org/GOGL": ARIN_ORG_DETAIL,
        "/rest/org/GOOGL-2/nets": {"nets": {}},
        "/rest/org/GOOGL-2/asns": {"asns": {}},
        "/rest/org/GOOGL-2": ARIN_ORG_DETAIL,
        "/rest/customers;name=": ARIN_CUSTOMERS_SEARCH,
        "/rest/customer/C00876643": ARIN_CUSTOMER_DETAIL,
        "/rest/nets;name=": {"nets": {}},
        "/rest/poc/ZG39-ARIN": ARIN_POC_DETAIL,
    }


class TestArinSearch:
    def test_finds_organisations(self, make_client):
        client = ArinClient(make_client(arin_routes()))
        result = client.search("Google*")
        handles = {org.handle for org in result.organizations}
        assert "GOGL" in handles

    def test_extracts_ipv4_and_ipv6_netblocks(self, make_client):
        client = ArinClient(make_client(arin_routes()))
        result = client.search("Google*")
        cidrs = {n.cidr for n in result.netblocks}
        assert "8.8.8.0/24" in cidrs
        assert any(":" in c for c in cidrs)

    def test_org_address_is_attached(self, make_client):
        client = ArinClient(make_client(arin_routes()))
        result = client.search("Google*")
        block = next(n for n in result.netblocks if n.cidr == "8.8.8.0/24")
        assert "1600 Amphitheatre Parkway" in block.address
        assert block.city == "Mountain View"

    def test_customer_records_become_netblocks(self, make_client):
        client = ArinClient(make_client(arin_routes()))
        result = client.search("Google*")
        customer = [n for n in result.netblocks
                    if n.object_type is ObjectType.CUSTOMER]
        assert customer
        assert customer[0].cidr == "69.224.21.208/29"

    def test_asns_collected(self, make_client):
        client = ArinClient(make_client(arin_routes()))
        result = client.search("Google*")
        assert "AS15169" in result.asns

    def test_pocs_only_fetched_when_requested(self, make_client):
        fake = make_client(arin_routes())
        ArinClient(fake).search("Google*", fetch_pocs=False)
        assert fake.call_count("/pocs") == 0

        fake2 = make_client(arin_routes())
        result = ArinClient(fake2).search("Google*", fetch_pocs=True)
        assert fake2.call_count("/pocs") > 0
        assert result.contacts
        assert result.contacts[0].name == "Jane Doe"
        assert "noc@example.com" in result.contacts[0].emails

    def test_single_result_collapsed_form(self, make_client):
        routes = arin_routes()
        routes["/rest/orgs;name="] = ARIN_ORGS_SEARCH_SINGLE
        result = ArinClient(make_client(routes)).search("Google*")
        assert len(result.organizations) == 1

    def test_no_results_is_not_an_error(self, make_client):
        routes = {"/rest/orgs;name=": {"orgs": {}},
                  "/rest/customers;name=": {"customers": {}},
                  "/rest/nets;name=": {"nets": {}}}
        result = ArinClient(make_client(routes)).search("Nonexistent*")
        assert result.netblocks == []
        assert result.errors == []


class TestArinResilience:
    def test_http_error_is_recorded_not_raised(self, make_client):
        routes = arin_routes()
        routes["/rest/orgs;name="] = HttpError("connection timed out")
        result = ArinClient(make_client(routes)).search("Google*")
        assert result.errors
        assert "timed out" in result.errors[0]

    def test_partial_failure_keeps_other_data(self, make_client):
        # Org search works, but the nets endpoint fails.
        routes = arin_routes()
        routes["/rest/org/GOGL/nets"] = HttpError("500 server error")
        result = ArinClient(make_client(routes)).search("Google*")
        assert result.organizations
        assert result.errors
        # Customer data still came through.
        assert any(n.object_type is ObjectType.CUSTOMER for n in result.netblocks)

    def test_malformed_json_shape_is_tolerated(self, make_client):
        routes = arin_routes()
        routes["/rest/orgs;name="] = ["unexpected", "list"]
        result = ArinClient(make_client(routes)).search("Google*")
        assert result.errors

    def test_missing_fields_do_not_crash(self, make_client):
        routes = arin_routes()
        routes["/rest/org/GOGL"] = ARIN_ORG_DETAIL_NO_ADDRESS
        # Historically this raised IndexError on address[0].
        result = ArinClient(make_client(routes)).search("Google*")
        assert result is not None

    def test_empty_response_body(self, make_client):
        routes = arin_routes()
        routes["/rest/orgs;name="] = {}
        result = ArinClient(make_client(routes)).search("Google*")
        assert result.organizations == []

    def test_multiline_address_joined(self, make_client):
        # Dedicated routes so only the multiline org is in play.
        routes = {
            "/rest/orgs;name=": {"orgs": {"orgRef": {
                "@handle": "MULTI", "@name": "Multiline Corp",
                "$": "https://whois.arin.net/rest/org/MULTI"}}},
            "/rest/org/MULTI/nets": ARIN_ORG_NETS,
            "/rest/org/MULTI/asns": {"asns": {}},
            "/rest/org/MULTI": ARIN_ORG_DETAIL_MULTILINE,
            "/rest/customers;name=": {"customers": {}},
            "/rest/nets;name=": {"nets": {}},
        }
        result = ArinClient(make_client(routes)).search("Multi*")
        block = next(n for n in result.netblocks if n.cidr == "8.8.8.0/24")
        assert "Building 5" in block.address
        assert "123 Main Street" in block.address


class TestArinNetDetail:
    def test_single_block(self, make_client):
        client = ArinClient(make_client({"/rest/net/": ARIN_NET_DETAIL}))
        blocks = client.net_detail("NET-107-167-160-0-1")
        assert len(blocks) == 1
        assert blocks[0].cidr == "107.167.160.0/19"
        assert blocks[0].name == "GOOGLE-CLOUD"

    def test_multiple_blocks(self, make_client):
        client = ArinClient(make_client({"/rest/net/": ARIN_NET_DETAIL_MULTIBLOCK}))
        blocks = client.net_detail("NET-MULTI-1")
        assert {b.cidr for b in blocks} == {"192.0.2.0/24", "198.51.100.0/24"}

    def test_missing_record(self, make_client):
        client = ArinClient(make_client({}))
        assert client.net_detail("NET-DOES-NOT-EXIST") == []


# -- RDAP -------------------------------------------------------------------


class TestRdap:
    def test_entity_search_extracts_org_and_networks(self, make_client):
        client = RdapClient("ripe", make_client({"/entities": RDAP_ENTITY_SEARCH}))
        result = client.search("Example*")
        assert result.organizations[0].name == "Example Networks B.V."
        assert result.netblocks[0].cidr == "193.0.0.0/21"
        assert "AS3333" in result.asns

    def test_registry_is_recorded(self, make_client):
        client = RdapClient("apnic", make_client({"/entities": RDAP_ENTITY_SEARCH}))
        result = client.search("Example*")
        assert result.registry == "apnic"
        assert result.netblocks[0].registry == "apnic"

    def test_empty_search_results(self, make_client):
        client = RdapClient("ripe", make_client({"/entities": RDAP_ENTITY_SEARCH_EMPTY}))
        result = client.search("Nothing*")
        assert result.organizations == []
        assert result.netblocks == []
        assert result.errors == []

    def test_unsupported_search_is_recorded_not_raised(self, make_client):
        # LACNIC generally rejects entity search with 501.
        client = RdapClient("lacnic", make_client({"/entities": HttpError("HTTP 501")}))
        result = client.search("Anything*")
        assert result.errors
        assert result.netblocks == []

    def test_malformed_payload_tolerated(self, make_client):
        client = RdapClient("ripe", make_client({"/entities": "not json at all"}))
        result = client.search("Example*")
        assert result.netblocks == []

    def test_ip_lookup(self, make_client):
        client = RdapClient("arin", make_client({"/ip/": RDAP_IP_LOOKUP}))
        payload = client.lookup_ip("8.8.8.8")
        assert payload["country"] == "US"

    def test_ip_lookup_failure_returns_none(self, make_client):
        client = RdapClient("arin", make_client({"/ip/": HttpError("timeout")}))
        assert client.lookup_ip("8.8.8.8") is None

    def test_unknown_registry_rejected(self, make_client):
        with pytest.raises(KeyError):
            RdapClient("notarealrir", make_client({}))


class TestVcardParsing:
    def test_extracts_fn_and_label_address(self):
        result = _parse_vcard(RDAP_ENTITY_SEARCH["entitySearchResults"][0]["vcardArray"])
        assert result["fn"] == "Example Networks B.V."
        assert "Sesamstraat 1" in result["adr"]

    @pytest.mark.parametrize("value", [None, [], ["vcard"], "string", {}, 42])
    def test_malformed_vcard_returns_empty(self, value):
        assert _parse_vcard(value) == {}

    def test_structured_address_array(self):
        vcard = ["vcard", [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", "Acme"],
            ["adr", {}, "text", ["", "", "1 Road", "Springfield", "IL", "62701", "US"]],
        ]]
        result = _parse_vcard(vcard)
        assert result["city"] == "Springfield"
        assert result["state"] == "IL"
        assert result["country"] == "US"


# -- BGP / ASN --------------------------------------------------------------


class TestParseAsn:
    @pytest.mark.parametrize("raw,expected", [
        ("AS15169", "AS15169"),
        ("as15169", "AS15169"),
        ("15169", "AS15169"),
        (" AS15169 ", "AS15169"),
    ])
    def test_valid(self, raw, expected):
        assert parse_asn(raw) == expected

    @pytest.mark.parametrize("raw", [
        "", None, "ASN15169", "AS", "notanasn", "AS-1", "AS0",
        "AS99999999999", "AS15169extra",
    ])
    def test_invalid(self, raw):
        assert parse_asn(raw) is None


class TestBgpClient:
    def test_returns_announced_prefixes(self, make_client):
        client = BgpClient(make_client({"announced-prefixes": RIPESTAT_ANNOUNCED_PREFIXES}))
        prefixes = client.announced_prefixes("AS15169")
        assert "8.8.8.0/24" in prefixes
        assert "2001:4860::/32" in prefixes

    def test_invalid_prefixes_dropped(self, make_client):
        client = BgpClient(make_client({"announced-prefixes": RIPESTAT_ANNOUNCED_PREFIXES}))
        assert "not-a-prefix" not in client.announced_prefixes("AS15169")

    def test_results_are_cached(self, make_client):
        fake = make_client({"announced-prefixes": RIPESTAT_ANNOUNCED_PREFIXES})
        client = BgpClient(fake)
        client.announced_prefixes("AS15169")
        client.announced_prefixes("AS15169")
        assert fake.call_count("announced-prefixes") == 1

    def test_empty_result(self, make_client):
        client = BgpClient(make_client({"announced-prefixes": RIPESTAT_EMPTY}))
        assert client.announced_prefixes("AS64496") == []

    def test_http_failure_returns_empty(self, make_client):
        client = BgpClient(make_client({"announced-prefixes": HttpError("503")}))
        assert client.announced_prefixes("AS15169") == []

    def test_malformed_payload_returns_empty(self, make_client):
        client = BgpClient(make_client({"announced-prefixes": {"unexpected": True}}))
        assert client.announced_prefixes("AS15169") == []

    def test_invalid_asn_makes_no_request(self, make_client):
        fake = make_client({"announced-prefixes": RIPESTAT_ANNOUNCED_PREFIXES})
        assert BgpClient(fake).announced_prefixes("garbage") == []
        assert fake.call_count("announced-prefixes") == 0

    def test_netblocks_carry_asn_metadata(self, make_client):
        client = BgpClient(make_client(
            {"announced-prefixes": RIPESTAT_ANNOUNCED_PREFIXES}))
        blocks = client.netblocks_for_asn("AS15169", "Google LLC", registry="arin")
        assert all(b.object_type is ObjectType.ASN for b in blocks)
        assert all(b.asn == "AS15169" for b in blocks)
        assert blocks[0].organization == "Google LLC"


# -- aggregation ------------------------------------------------------------


class TestQueryRegistries:
    def test_merges_results_from_multiple_registries(self, make_client):
        arin = ArinClient(make_client(arin_routes()))
        rdap = RdapClient("ripe", make_client({"/entities": RDAP_ENTITY_SEARCH}))
        merged = query_registries("Google*", [arin, rdap])
        cidrs = {n.cidr for n in merged.netblocks}
        assert "8.8.8.0/24" in cidrs
        assert "193.0.0.0/21" in cidrs

    def test_one_failing_registry_does_not_stop_others(self, make_client):
        good = ArinClient(make_client(arin_routes()))
        bad = RdapClient("ripe", make_client({"/entities": HttpError("down")}))
        merged = query_registries("Google*", [good, bad])
        assert merged.netblocks
        assert merged.errors

    def test_no_clients(self, make_client):
        merged = query_registries("Google*", [])
        assert merged.netblocks == []

    def test_asns_are_normalised_and_deduped(self, make_client):
        arin = ArinClient(make_client(arin_routes()))
        merged = query_registries("Google*", [arin, arin])
        assert merged.asns == sorted(set(merged.asns))


class TestOrgHandleLinking:
    """Regression: ORG_HANDLE_LINK was unreachable for network records.

    A netblock's `handle` is the NET handle ("NET-8-8-8-0-1") while the
    resolved organisation handles are ORG handles ("GOGL"). Comparing the two
    never matched, so networks registered directly to a confirmed org were
    capped at "probable" instead of reaching "confirmed".
    """

    def test_org_nets_record_the_owning_org_handle(self, make_client):
        client = ArinClient(make_client(arin_routes()))
        result = client.search("Google*")
        block = next(n for n in result.netblocks if n.cidr == "8.8.8.0/24")
        assert block.org_handle == "GOGL"
        assert block.handle == "NET-8-8-8-0-1"
        assert block.org_handle != block.handle

    def test_name_search_nets_have_no_org_handle(self, make_client):
        # Nets found by name search are not known to belong to a matched org.
        routes = {
            "/rest/orgs;name=": {"orgs": {}},
            "/rest/customers;name=": {"customers": {}},
            "/rest/nets;name=": ARIN_ORG_NETS,
        }
        result = ArinClient(make_client(routes)).search("Google*")
        assert all(n.org_handle == "" for n in result.netblocks)


class TestRdapAcceptHeader:
    """Regression: LACNIC answered 406 to Accept: application/json."""

    def test_rdap_media_type_is_requested(self, make_client):
        captured = {}

        def capture(url, params):
            return RDAP_ENTITY_SEARCH

        fake = make_client({"/entities": capture})
        original = fake.get_json

        def wrapper(url, *, headers=None, params=None, cache=True,
                    no_retry_status=None):
            captured["accept"] = (headers or {}).get("Accept", "")
            return original(url, headers=headers, params=params, cache=cache,
                            no_retry_status=no_retry_status)

        fake.get_json = wrapper
        RdapClient("lacnic", fake).search("Example*")
        assert "application/rdap+json" in captured["accept"]


class TestRdapWildcardFallback:
    """Regression: RIPE 500s on wildcard queries and we gave up immediately."""

    def test_retries_without_wildcards_after_failure(self, make_client):
        calls: list[str] = []

        def route(url, params):
            calls.append(params.get("fn", ""))
            if "*" in params.get("fn", ""):
                raise HttpError("HTTP 500 from rdap.db.ripe.net")
            return RDAP_ENTITY_SEARCH

        # APNIC is not in NO_WILDCARD_SEARCH, so it tries the wildcard first.
        result = RdapClient("apnic", make_client({"/entities": route})).search("Paypal*")
        assert calls == ["Paypal*", "Paypal"]
        assert result.netblocks          # the fallback succeeded
        assert result.errors == []

    def test_gives_up_after_the_fallback(self, make_client):
        calls: list[str] = []

        def route(url, params):
            calls.append(params.get("fn", ""))
            raise HttpError("HTTP 500")

        result = RdapClient("apnic", make_client({"/entities": route})).search("Paypal*")
        assert len(calls) == 2           # bounded: no infinite retry
        assert result.errors

    def test_no_fallback_for_plain_queries(self, make_client):
        calls: list[str] = []

        def route(url, params):
            calls.append(params.get("fn", ""))
            raise HttpError("HTTP 500")

        RdapClient("apnic", make_client({"/entities": route})).search("Paypal")
        assert len(calls) == 1


class TestRipeDbResolution:
    """Regression: RIPE entity search found organisations but no netblocks.

    RIPE's RDAP does not embed a `networks` array (ARIN's does), so a
    RIPE-region company resolved to an org and then produced nothing. The
    RIPE database inverse lookup closes that gap.
    """

    def test_inetnum_range_converted_to_cidrs(self, make_client):
        from netblocktool.models import Organization
        from netblocktool.registries.ripe import RipeDbClient

        client = RipeDbClient(make_client({"search.json": RIPE_DB_INETNUM_SEARCH}))
        org = Organization(handle="ORG-EX1-RIPE", name="Example Networks B.V.",
                           registry="ripe")
        cidrs = {n.cidr for n in client.netblocks_for_org(org)}
        assert "193.0.0.0/21" in cidrs
        assert "212.58.224.0/19" in cidrs

    def test_netname_and_org_handle_preserved(self, make_client):
        from netblocktool.models import Organization
        from netblocktool.registries.ripe import RipeDbClient

        client = RipeDbClient(make_client({"search.json": RIPE_DB_INETNUM_SEARCH}))
        org = Organization(handle="ORG-EX1-RIPE", name="Example Networks B.V.",
                           registry="ripe")
        block = next(n for n in client.netblocks_for_org(org)
                     if n.cidr == "193.0.0.0/21")
        assert block.name == "EXAMPLE-NET"
        assert block.org_handle == "ORG-EX1-RIPE"
        assert block.registry == "ripe"
        assert block.country == "NL"

    def test_inet6num_prefix_form(self, make_client):
        from netblocktool.models import Organization
        from netblocktool.registries.ripe import RipeDbClient

        client = RipeDbClient(make_client({"search.json": RIPE_DB_INET6NUM_SEARCH}))
        org = Organization(handle="ORG-EX1-RIPE", name="Example", registry="ripe")
        assert any(n.cidr == "2001:610::/32" for n in client.netblocks_for_org(org))

    def test_results_are_cached(self, make_client):
        from netblocktool.models import Organization
        from netblocktool.registries.ripe import RipeDbClient

        fake = make_client({"search.json": RIPE_DB_INETNUM_SEARCH})
        client = RipeDbClient(fake)
        org = Organization(handle="ORG-EX1-RIPE", name="Example", registry="ripe")
        client.netblocks_for_org(org)
        before = fake.call_count("search.json")
        client.netblocks_for_org(org)
        assert fake.call_count("search.json") == before

    @pytest.mark.parametrize("payload", [
        RIPE_DB_EMPTY, {}, {"objects": None}, {"objects": {"object": "bad"}},
        HttpError("503"), "not json",
    ])
    def test_failures_return_empty(self, make_client, payload):
        from netblocktool.models import Organization
        from netblocktool.registries.ripe import RipeDbClient

        client = RipeDbClient(make_client({"search.json": payload}))
        org = Organization(handle="ORG-EX1-RIPE", name="Example", registry="ripe")
        assert client.netblocks_for_org(org) == []

    def test_blank_handle_makes_no_request(self, make_client):
        from netblocktool.models import Organization
        from netblocktool.registries.ripe import RipeDbClient

        fake = make_client({"search.json": RIPE_DB_INETNUM_SEARCH})
        org = Organization(handle="", name="Example", registry="ripe")
        assert RipeDbClient(fake).netblocks_for_org(org) == []
        assert fake.call_count("search.json") == 0

    def test_rdap_falls_back_to_ripe_db(self, make_client):
        # Entity search returns an org but no embedded networks.
        entity_only = {"entitySearchResults": [{
            "objectClassName": "entity", "handle": "ORG-EX1-RIPE",
            "vcardArray": ["vcard", [["fn", {}, "text", "Example Networks B.V."]]],
        }]}
        fake = make_client({
            "/entities": entity_only,
            "search.json": RIPE_DB_INETNUM_SEARCH,
        })
        result = RdapClient("ripe", fake).search("Example*")
        assert result.organizations
        assert result.netblocks, "RIPE DB fallback should supply netblocks"
        assert any(n.cidr == "193.0.0.0/21" for n in result.netblocks)

    def test_arin_rdap_does_not_use_ripe_db(self, make_client):
        fake = make_client({"/entities": RDAP_ENTITY_SEARCH})
        RdapClient("apnic", fake).search("Example*")
        assert fake.call_count("rest.db.ripe.net") == 0


class TestOriginAsnLookup:
    """Regression: ASNs: 0 for companies whose ASN is held by another entity.

    PayPal's ARIN organisations hold no ASN records, so registry-based ASN
    discovery found nothing. Asking which AS actually originates a discovered
    prefix finds them regardless of registry bookkeeping.
    """

    def test_returns_origin_asn(self, make_client):
        client = BgpClient(make_client({"prefix-overview": RIPESTAT_PREFIX_OVERVIEW}))
        assert [a for a, _ in client.origin_asns("66.211.168.0/22")] == ["AS17012"]

    def test_multiple_origins(self, make_client):
        client = BgpClient(make_client({"prefix-overview": RIPESTAT_PREFIX_OVERVIEW_MULTI}))
        assert [a for a, _ in client.origin_asns("8.8.8.0/24")] == \
            ["AS15169", "AS396982"]

    def test_unannounced_prefix(self, make_client):
        client = BgpClient(make_client(
            {"prefix-overview": RIPESTAT_PREFIX_OVERVIEW_UNANNOUNCED}))
        assert client.origin_asns("192.0.2.0/24") == []

    def test_results_are_cached(self, make_client):
        fake = make_client({"prefix-overview": RIPESTAT_PREFIX_OVERVIEW})
        client = BgpClient(fake)
        client.origin_asns("66.211.168.0/22")
        client.origin_asns("66.211.168.0/22")
        assert fake.call_count("prefix-overview") == 1

    @pytest.mark.parametrize("payload", [
        HttpError("503"), {"unexpected": True}, {"data": None}, "not json", {},
    ])
    def test_failures_return_empty(self, make_client, payload):
        client = BgpClient(make_client({"prefix-overview": payload}))
        assert client.origin_asns("66.211.168.0/22") == []

    def test_blank_cidr_makes_no_request(self, make_client):
        fake = make_client({"prefix-overview": RIPESTAT_PREFIX_OVERVIEW})
        assert BgpClient(fake).origin_asns("") == []
        assert fake.call_count("prefix-overview") == 0


class TestRipePersonRoleHandles:
    """Regression: person/role handles yielded 0 netblocks.

    RIPE entity search returns person (PA9687-RIPE) and role (PN4269-RIPE)
    objects alongside organisations. An `org:` inverse lookup can never match
    those, so they silently produced nothing.
    """

    def test_person_handle_uses_contact_attributes(self, make_client):
        from netblocktool.models import Organization
        from netblocktool.registries.ripe import RipeDbClient

        captured: list = []

        def route(url, params):
            captured.append(params.get("inverse-attribute"))
            return RIPE_DB_INETNUM_SEARCH

        client = RipeDbClient(make_client({"search.json": route}))
        org = Organization(handle="PA9687-RIPE", name="PayPal", registry="ripe")
        blocks = client.netblocks_for_org(org)
        assert blocks, "person handle should still resolve netblocks"
        assert all(attr == ["admin-c", "tech-c"] for attr in captured)

    def test_org_handle_still_uses_org_attribute(self, make_client):
        from netblocktool.models import Organization
        from netblocktool.registries.ripe import RipeDbClient

        captured: list = []

        def route(url, params):
            captured.append(params.get("inverse-attribute"))
            return RIPE_DB_INETNUM_SEARCH

        client = RipeDbClient(make_client({"search.json": route}))
        org = Organization(handle="ORG-EX1-RIPE", name="Example", registry="ripe")
        client.netblocks_for_org(org)
        assert all(attr == ["org"] for attr in captured)

    def test_duplicate_cidrs_across_object_types_collapsed(self, make_client):
        from netblocktool.models import Organization
        from netblocktool.registries.ripe import RipeDbClient

        client = RipeDbClient(make_client({"search.json": RIPE_DB_INETNUM_SEARCH}))
        org = Organization(handle="ORG-EX1-RIPE", name="Example", registry="ripe")
        cidrs = [n.cidr for n in client.netblocks_for_org(org)]
        assert len(cidrs) == len(set(cidrs))


class TestOriginAsnHolder:
    """Regression: the originating AS holder was discarded.

    For a downstream reassignment the origin AS belongs to the upstream
    provider, not the target company. Reporting it in an `asn` column beside
    the company presented an ISP's ASN as though it were the company's.
    """

    def test_holder_is_returned(self, make_client):
        client = BgpClient(make_client({"prefix-overview": RIPESTAT_PREFIX_OVERVIEW}))
        assert client.origin_asns("66.211.168.0/22") == [("AS17012", "PAYPAL-CORP")]

    def test_multiple_origins_with_holders(self, make_client):
        client = BgpClient(make_client(
            {"prefix-overview": RIPESTAT_PREFIX_OVERVIEW_MULTI}))
        assert client.origin_asns("8.8.8.0/24") == [
            ("AS15169", "GOOGLE"), ("AS396982", "GOOGLE-CLOUD")]

    def test_missing_holder_yields_empty_string(self, make_client):
        payload = {"data": {"asns": [{"asn": 17012}]}}
        client = BgpClient(make_client({"prefix-overview": payload}))
        assert client.origin_asns("1.1.1.0/24") == [("AS17012", "")]


class TestContactProvenance:
    """Netblocks found only via admin-c/tech-c are marked CONTACT, not NETWORK."""

    def test_contact_lookup_marks_object_type(self, make_client):
        from netblocktool.models import ObjectType, Organization
        from netblocktool.registries.ripe import RipeDbClient

        client = RipeDbClient(make_client({"search.json": RIPE_DB_INETNUM_SEARCH}))
        org = Organization(handle="PA9687-RIPE", name="PayPal", registry="ripe")
        blocks = client.netblocks_for_org(org)
        assert blocks
        assert all(n.object_type is ObjectType.CONTACT for n in blocks)

    def test_contact_lookup_does_not_claim_org_handle(self, make_client):
        from netblocktool.models import Organization
        from netblocktool.registries.ripe import RipeDbClient

        client = RipeDbClient(make_client({"search.json": RIPE_DB_INETNUM_SEARCH}))
        org = Organization(handle="PA9687-RIPE", name="PayPal", registry="ripe")
        # A contact reference is not proof of registration, so it must not
        # grant the ORG_HANDLE_LINK bonus.
        assert all(n.org_handle == "" for n in client.netblocks_for_org(org))

    def test_org_lookup_still_marks_network(self, make_client):
        from netblocktool.models import ObjectType, Organization
        from netblocktool.registries.ripe import RipeDbClient

        client = RipeDbClient(make_client({"search.json": RIPE_DB_INETNUM_SEARCH}))
        org = Organization(handle="ORG-EX1-RIPE", name="Example", registry="ripe")
        blocks = client.netblocks_for_org(org)
        assert all(n.object_type is ObjectType.NETWORK for n in blocks)
        assert all(n.org_handle == "ORG-EX1-RIPE" for n in blocks)


class TestRipeWildcardAvoidance:
    """RIPE rejects wildcard fn patterns; sending one is a wasted request."""

    def test_plain_name_tried_first_for_ripe(self, make_client):
        calls: list[str] = []

        def route(url, params):
            calls.append(params.get("fn", ""))
            return RDAP_ENTITY_SEARCH

        RdapClient("ripe", make_client({"/entities": route})).search("Paypal*")
        assert calls == ["Paypal"], "RIPE must not be sent a known-bad wildcard"

    def test_other_registries_still_try_wildcard_first(self, make_client):
        calls: list[str] = []

        def route(url, params):
            calls.append(params.get("fn", ""))
            return RDAP_ENTITY_SEARCH

        RdapClient("apnic", make_client({"/entities": route})).search("Paypal*")
        assert calls == ["Paypal*"]

    def test_ripe_still_falls_back_to_wildcard(self, make_client):
        calls: list[str] = []

        def route(url, params):
            calls.append(params.get("fn", ""))
            if params.get("fn") == "Paypal":
                raise HttpError("HTTP 500")
            return RDAP_ENTITY_SEARCH

        result = RdapClient("ripe", make_client({"/entities": route})).search("Paypal*")
        assert calls == ["Paypal", "Paypal*"]
        assert result.organizations


class TestPocUrlConstruction:
    """Regression: -p produced no output.

    POC lookups followed the absolute URL embedded in ARIN's response rather
    than building one from the handle. That is an SSRF vector - external data
    chose the host we fetched - and it made the code impossible to exercise
    against anything but the live service.
    """

    def test_poc_url_built_from_handle(self, make_client):
        fake = make_client(arin_routes())
        result = ArinClient(fake).search("Google*", fetch_pocs=True)
        assert result.contacts, "contacts should resolve via the handle"
        assert result.contacts[0].name == "Jane Doe"
        assert any("/rest/poc/ZG39-ARIN" in url for url, _ in fake.calls)

    def test_off_host_reference_is_ignored(self, make_client):
        from netblocktool.registries.arin import _same_host_ref

        assert _same_host_ref("https://evil.example.com/rest/poc/X") == ""
        assert _same_host_ref("https://whois.arin.net/rest/poc/X") == \
            "https://whois.arin.net/rest/poc/X"

    @pytest.mark.parametrize("url", [
        "", "not-a-url", "file:///etc/passwd", "ftp://host/x",
    ])
    def test_malformed_references_rejected(self, url):
        from netblocktool.registries.arin import _same_host_ref

        assert _same_host_ref(url) == ""

    def test_poc_failure_does_not_break_search(self, make_client):
        routes = arin_routes()
        routes["/rest/poc/ZG39-ARIN"] = HttpError("timeout")
        result = ArinClient(make_client(routes)).search("Google*", fetch_pocs=True)
        assert result.netblocks       # netblocks unaffected
        assert result.contacts == []
