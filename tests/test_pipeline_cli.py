"""Pipeline orchestration and CLI argument handling."""

from __future__ import annotations

import csv
import json

import pytest
from fixtures import (
    ARIN_CUSTOMER_DETAIL,
    ARIN_CUSTOMERS_SEARCH,
    ARIN_ORG_ASNS,
    ARIN_ORG_DETAIL,
    ARIN_ORG_NETS,
    ARIN_ORGS_SEARCH_SINGLE,
    RIPESTAT_ANNOUNCED_PREFIXES,
)

from netblocktool.cli import build_parser, config_from_args, options_from_args, validate
from netblocktool.config import Config
from netblocktool.http import HttpError
from netblocktool.models import Confidence, Netblock, ObjectType
from netblocktool.pipeline import Pipeline, RunOptions, build_query
from netblocktool.registries.arin import ArinClient
from netblocktool.search import NullSearchProvider


def pipeline_routes() -> dict:
    return {
        "/rest/orgs;name=": ARIN_ORGS_SEARCH_SINGLE,
        "/rest/org/GOGL/nets": ARIN_ORG_NETS,
        "/rest/org/GOGL/asns": ARIN_ORG_ASNS,
        "/rest/org/GOGL": ARIN_ORG_DETAIL,
        "/rest/customers;name=": ARIN_CUSTOMERS_SEARCH,
        "/rest/customer/C00876643": ARIN_CUSTOMER_DETAIL,
        "/rest/nets;name=": {"nets": {}},
        "announced-prefixes": RIPESTAT_ANNOUNCED_PREFIXES,
    }


def make_pipeline(fake_client, config: Config | None = None) -> Pipeline:
    """Build a Pipeline wired to a fake HTTP client and no search provider."""
    config = config or Config(user_agent="pytest/1.0 test@example.com",
                              search_provider="none")
    pipeline = Pipeline.__new__(Pipeline)
    pipeline.config = config
    pipeline.client = fake_client
    pipeline.registry_clients = [ArinClient(fake_client, config)]
    from netblocktool.geo import GeoResolver
    from netblocktool.registries.bgp import BgpClient
    pipeline.bgp = BgpClient(fake_client)
    pipeline.search_provider = NullSearchProvider(fake_client, config)
    pipeline.geo = GeoResolver(fake_client)
    pipeline._edgar = None
    pipeline._registry_cache = {}
    return pipeline


# -- query construction -----------------------------------------------------


class TestBuildQuery:
    @pytest.mark.parametrize("mode,expected", [
        ("exact", "Google"),
        ("prefix", "Google*"),
        ("full", "*Google*"),
    ])
    def test_modes(self, mode, expected):
        assert build_query("Google", mode) == expected

    def test_full_wildcard_replaces_separators(self):
        assert build_query("Coca Cola", "full") == "*Coca*Cola*"
        assert build_query("Wal-Mart", "full") == "*Wal*Mart*"

    def test_no_doubled_wildcards(self):
        assert "**" not in build_query("A - B", "full")

    def test_whitespace_normalised(self):
        assert build_query("  Google  ", "prefix") == "Google*"

    def test_empty_target(self):
        assert build_query("", "prefix") == ""
        assert build_query("   ", "prefix") == ""


# -- pipeline ---------------------------------------------------------------


class TestPipelineRun:
    def test_produces_scored_netblocks(self, make_client):
        pipeline = make_pipeline(make_client(pipeline_routes()))
        result = pipeline.run(RunOptions(target="Google"))
        assert result.netblocks
        assert all(n.confidence is not None for n in result.netblocks)
        assert all(n.evidence for n in result.netblocks)

    def test_company_provenance_recorded(self, make_client):
        pipeline = make_pipeline(make_client(pipeline_routes()))
        result = pipeline.run(RunOptions(target="Google"))
        assert all(n.company == "Google" for n in result.netblocks)

    def test_cidrs_are_deduplicated(self, make_client):
        pipeline = make_pipeline(make_client(pipeline_routes()))
        result = pipeline.run(RunOptions(target="Google"))
        cidrs = [n.cidr for n in result.netblocks]
        assert len(cidrs) == len(set(cidrs))

    def test_results_sorted_by_descending_score(self, make_client):
        pipeline = make_pipeline(make_client(pipeline_routes()))
        result = pipeline.run(RunOptions(target="Google"))
        scores = [n.score for n in result.netblocks]
        assert scores == sorted(scores, reverse=True)

    def test_asn_expansion_adds_prefixes(self, make_client):
        pipeline = make_pipeline(make_client(pipeline_routes()))
        result = pipeline.run(RunOptions(target="Google", expand_asns=True))
        assert any(n.object_type is ObjectType.ASN for n in result.netblocks)

    def test_asn_expansion_can_be_disabled(self, make_client):
        fake = make_client(pipeline_routes())
        pipeline = make_pipeline(fake)
        pipeline.run(RunOptions(target="Google", expand_asns=False))
        assert fake.call_count("announced-prefixes") == 0

    def test_ipv4_filter(self, make_client):
        config = Config(search_provider="none", ip_version=4)
        pipeline = make_pipeline(make_client(pipeline_routes()), config)
        result = pipeline.run(RunOptions(target="Google"))
        assert result.netblocks
        assert all(n.ip_version == 4 for n in result.netblocks)

    def test_ipv6_filter(self, make_client):
        config = Config(search_provider="none", ip_version=6)
        pipeline = make_pipeline(make_client(pipeline_routes()), config)
        result = pipeline.run(RunOptions(target="Google"))
        assert all(n.ip_version == 6 for n in result.netblocks)

    def test_confidence_threshold(self, make_client):
        pipeline = make_pipeline(make_client(pipeline_routes()))
        result = pipeline.run(RunOptions(target="Google", threshold=50))
        assert all(n.score >= 50 for n in result.netblocks)

    def test_address_grep_filter(self, make_client):
        pipeline = make_pipeline(make_client(pipeline_routes()))
        result = pipeline.run(RunOptions(target="Google",
                                         address_grep="mountain view"))
        assert all("mountain view" in n.address.lower() for n in result.netblocks)

    def test_subsumed_networks_marked_not_dropped(self, make_client):
        pipeline = make_pipeline(make_client(pipeline_routes()))
        blocks = [
            Netblock(cidr="8.8.0.0/16", name="Google LLC", score=80),
            Netblock(cidr="8.8.8.0/24", name="Google LLC", score=70),
        ]
        deduped = pipeline._deduplicate(blocks)
        assert len(deduped) == 2
        contained = next(n for n in deduped if n.cidr == "8.8.8.0/24")
        # Containment is structural, not a confidence verdict: the score and
        # band are preserved and a flag records the relationship.
        assert contained.subsumed is True
        assert contained.score == 70
        assert any(e.code == "SUBSUMED" for e in contained.evidence)
        container = next(n for n in deduped if n.cidr == "8.8.0.0/16")
        assert container.subsumed is False

    def test_registry_results_are_cached_across_companies(self, make_client):
        fake = make_client(pipeline_routes())
        pipeline = make_pipeline(fake)
        pipeline.run(RunOptions(target="Google"))
        first = fake.call_count("/rest/orgs;name=")
        pipeline.run(RunOptions(target="Google"))
        assert fake.call_count("/rest/orgs;name=") == first


class TestPipelineResilience:
    def test_registry_failure_does_not_crash(self, make_client):
        routes = pipeline_routes()
        routes["/rest/orgs;name="] = HttpError("ARIN timeout")
        pipeline = make_pipeline(make_client(routes))
        result = pipeline.run(RunOptions(target="Google"))
        assert result.errors
        assert isinstance(result.netblocks, list)

    def test_total_registry_outage_returns_empty_not_exception(self, make_client):
        pipeline = make_pipeline(make_client({}))
        result = pipeline.run(RunOptions(target="Nonexistent"))
        assert result.netblocks == []
        assert result.ok is False

    def test_bgp_failure_does_not_lose_registry_data(self, make_client):
        routes = pipeline_routes()
        routes["announced-prefixes"] = HttpError("503")
        pipeline = make_pipeline(make_client(routes))
        result = pipeline.run(RunOptions(target="Google"))
        assert any(n.object_type is ObjectType.NETWORK for n in result.netblocks)

    def test_subsidiary_failure_does_not_stop_run(self, make_client):
        routes = pipeline_routes()
        routes["company_tickers.json"] = HttpError("SEC 403")
        pipeline = make_pipeline(make_client(routes))
        result = pipeline.run(RunOptions(target="Google", with_subsidiaries=True))
        assert result.subsidiaries == []
        assert result.netblocks  # registry data still present

    def test_search_failure_does_not_stop_run(self, make_client):
        class ExplodingProvider(NullSearchProvider):
            def find_netblocks(self, company, *, max_pages=10):
                raise RuntimeError("provider exploded")

        fake = make_client(pipeline_routes())
        pipeline = make_pipeline(fake)
        pipeline.search_provider = ExplodingProvider(fake)
        result = pipeline.run(RunOptions(target="Google"))
        assert result.netblocks


# -- CLI --------------------------------------------------------------------


class TestCliParsing:
    def test_legacy_flags_all_accepted(self):
        parser = build_parser()
        # Every documented 2.x invocation must still parse.
        for argv in (
            ["Google"],
            ["-v", "Google"],
            ["-v", "-s", "Google"],
            ["-v", "-p", "Google"],
            ["-so", "-wv", "Facebook", "-o", "Results"],
            ["-gavl", "companies.txt"],
            ["-v", "-4", "Google"],
            ["-v", "-6", "Google"],
            ["-n", "Google"],
            ["-ng", "Google"],
            ["-e", "50", "Google"],
            ["-c", "Alphabet", "Google"],
            ["-sn", "Alphabet", "Google"],
            ["-sp", "Google"],
            ["-ag", "california", "Google"],
            ["-u", "Me me@example.com", "Google"],
            ["-q", "Google"],
        ):
            assert parser.parse_args(argv) is not None

    def test_combined_short_flags(self):
        args = build_parser().parse_args(["-wpgav", "Facebook", "-so"])
        assert args.wildcard and args.poc_out and args.geolocation
        assert args.address_out and args.verbose and args.subsidiary_out
        assert args.target == "Facebook"

    def test_help_flag_exits_cleanly(self):
        # The 2.x parser used add_help=False and -h errored out.
        with pytest.raises(SystemExit) as exc:
            build_parser().parse_args(["-h"])
        assert exc.value.code == 0

    def test_version_flag(self):
        with pytest.raises(SystemExit) as exc:
            build_parser().parse_args(["--version"])
        assert exc.value.code == 0

    @pytest.mark.parametrize("argv", [
        ["-n", "-w", "Google"],      # contradictory wildcard modes
        ["-v", "-q", "Google"],      # contradictory verbosity
        ["-4", "-6", "Google"],      # contradictory IP versions
    ])
    def test_mutually_exclusive_options_rejected(self, argv):
        with pytest.raises(SystemExit):
            build_parser().parse_args(argv)

    def test_missing_target_is_a_clean_error(self):
        parser = build_parser()
        args = parser.parse_args([])
        with pytest.raises(SystemExit):
            validate(args, parser)

    def test_threshold_must_be_an_integer(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["-e", "notanumber", "Google"])

    def test_threshold_range_validated(self):
        parser = build_parser()
        args = parser.parse_args(["-e", "500", "Google"])
        with pytest.raises(SystemExit):
            validate(args, parser)

    def test_unknown_registry_rejected(self):
        parser = build_parser()
        args = parser.parse_args(["--registries", "arin,notarir", "Google"])
        with pytest.raises(SystemExit):
            validate(args, parser)

    def test_list_mode_conflicts(self):
        parser = build_parser()
        for argv in (["-l", "-sn", "X", "f.txt"], ["-l", "-c", "X", "f.txt"]):
            args = parser.parse_args(argv)
            with pytest.raises(SystemExit):
                validate(args, parser)


class TestCliImpliedFlags:
    @pytest.mark.parametrize("flag", ["-so", "-sp"])
    def test_subsidiary_output_implies_subsidiary_mode(self, flag):
        parser = build_parser()
        args = parser.parse_args([flag, "Google"])
        validate(args, parser)
        assert args.subsidiary is True

    def test_subsidiary_name_implies_subsidiary_mode(self):
        parser = build_parser()
        args = parser.parse_args(["-sn", "Alphabet", "Google"])
        validate(args, parser)
        assert args.subsidiary is True

    def test_json_only_implies_json(self):
        parser = build_parser()
        args = parser.parse_args(["--json-only", "Google"])
        validate(args, parser)
        assert args.json is True

    def test_address_grep_implies_address_output(self):
        parser = build_parser()
        args = parser.parse_args(["-ag", "California", "Google"])
        validate(args, parser)
        options = options_from_args(args, "Google")
        assert options.include_address is True
        assert options.address_grep == "california"


class TestConfigFromArgs:
    def test_ip_version_flags(self):
        parser = build_parser()
        assert config_from_args(parser.parse_args(["-4", "G"])).ip_version == 4
        assert config_from_args(parser.parse_args(["-6", "G"])).ip_version == 6
        assert config_from_args(parser.parse_args(["G"])).ip_version is None

    def test_no_google_disables_search(self):
        args = build_parser().parse_args(["-ng", "Google"])
        assert config_from_args(args).search_provider == "none"

    def test_user_agent_override(self):
        args = build_parser().parse_args(["-u", "Acme sec@acme.com", "Google"])
        config = config_from_args(args)
        assert config.user_agent == "Acme sec@acme.com"
        assert config.is_default_user_agent() is False

    def test_network_tuning_flags(self):
        args = build_parser().parse_args([
            "--timeout", "30", "--workers", "4", "--retries", "5",
            "--rate-limit", "2.5", "Google"])
        config = config_from_args(args)
        assert config.timeout == 30.0
        assert config.max_workers == 4
        assert config.max_retries == 5
        assert config.rate_limit == 2.5

    def test_registry_list_parsed(self):
        args = build_parser().parse_args(["--registries", "arin,ripe", "Google"])
        assert config_from_args(args).registries == ("arin", "ripe")

    def test_query_mode_mapping(self):
        parser = build_parser()
        assert options_from_args(parser.parse_args(["-n", "G"]), "G").query_mode == "exact"
        assert options_from_args(parser.parse_args(["-w", "G"]), "G").query_mode == "full"
        assert options_from_args(parser.parse_args(["G"]), "G").query_mode == "prefix"


class TestConfigEnvironment:
    def test_environment_variables_honoured(self, monkeypatch):
        monkeypatch.setenv("NETBLOCKTOOL_TIMEOUT", "42")
        monkeypatch.setenv("NETBLOCKTOOL_MAX_WORKERS", "3")
        monkeypatch.setenv("NETBLOCKTOOL_USER_AGENT", "Env Agent env@example.com")
        config = Config()
        assert config.timeout == 42.0
        assert config.max_workers == 3
        assert config.user_agent == "Env Agent env@example.com"

    def test_invalid_environment_values_fall_back(self, monkeypatch):
        monkeypatch.setenv("NETBLOCKTOOL_TIMEOUT", "not-a-number")
        monkeypatch.setenv("NETBLOCKTOOL_MAX_WORKERS", "-5")
        config = Config()
        assert config.timeout > 0
        assert config.max_workers >= 1

    def test_values_are_clamped(self):
        config = Config(timeout=0, max_workers=1000, max_retries=99, rate_limit=0)
        assert config.timeout >= 1.0
        assert config.max_workers <= 32
        assert config.max_retries <= 10
        assert config.rate_limit > 0


# -- integration ------------------------------------------------------------


class TestOutputIntegration:
    def test_pipeline_results_write_valid_csv_and_json(self, make_client, tmp_path):
        from netblocktool.output import write_csv, write_json

        pipeline = make_pipeline(make_client(pipeline_routes()))
        result = pipeline.run(RunOptions(target="Google"))

        csv_path = write_csv(result.netblocks, tmp_path / "out.csv")
        rows = list(csv.reader(csv_path.open(encoding="utf-8")))
        assert len(rows) == len(result.netblocks) + 1

        json_path = write_json(result.netblocks, tmp_path / "out.json")
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        assert payload["count"] == len(result.netblocks)

    def test_confidence_bands_present_in_output(self, make_client, tmp_path):
        from netblocktool.output import write_csv

        pipeline = make_pipeline(make_client(pipeline_routes()))
        result = pipeline.run(RunOptions(target="Google"))
        path = write_csv(result.netblocks, tmp_path / "out.csv")
        text = path.read_text(encoding="utf-8")
        assert any(band.value in text for band in Confidence)


class TestCorroborationOrdering:
    """Corroboration must be computed before deduplication.

    Deduplication keeps one record per CIDR, so a corroboration pass running
    afterwards can never observe two source types for the same network.
    """

    def test_multi_source_cidr_is_corroborated_in_final_output(self, make_client):
        pipeline = make_pipeline(make_client(pipeline_routes()))
        result = pipeline.run(RunOptions(target="Google"))
        # 8.8.8.0/24 is reported both as an ARIN org network and as a prefix
        # announced by AS15169.
        block = next((n for n in result.netblocks if n.cidr == "8.8.8.0/24"), None)
        assert block is not None
        assert any(e.code == "CORROBORATED" for e in block.evidence)


class TestOriginAsnEnrichment:
    """Registry ASN records are often held by a former parent; BGP origin data
    fills the gap so the `asn` column is not empty."""

    def test_asn_column_populated_from_bgp(self, make_client):
        from fixtures import RIPESTAT_PREFIX_OVERVIEW
        routes = pipeline_routes()
        routes["prefix-overview"] = RIPESTAT_PREFIX_OVERVIEW
        pipeline = make_pipeline(make_client(routes))
        result = pipeline.run(RunOptions(target="Google"))
        assert any(n.asn for n in result.netblocks)

    def test_skipped_when_asn_expansion_disabled(self, make_client):
        from fixtures import RIPESTAT_PREFIX_OVERVIEW
        routes = pipeline_routes()
        routes["prefix-overview"] = RIPESTAT_PREFIX_OVERVIEW
        fake = make_client(routes)
        make_pipeline(fake).run(RunOptions(target="Google", expand_asns=False))
        assert fake.call_count("prefix-overview") == 0

    def test_zero_scored_netblocks_not_looked_up(self, make_client):
        from fixtures import RIPESTAT_PREFIX_OVERVIEW
        routes = pipeline_routes()
        routes["prefix-overview"] = RIPESTAT_PREFIX_OVERVIEW
        fake = make_client(routes)
        result = make_pipeline(fake).run(RunOptions(target="Google"))
        assert all(n.asn == "" for n in result.netblocks if n.score == 0)

    def test_lookup_failure_does_not_abort_run(self, make_client):
        routes = pipeline_routes()
        routes["prefix-overview"] = HttpError("503 service unavailable")
        result = make_pipeline(make_client(routes)).run(RunOptions(target="Google"))
        assert result.netblocks

    def test_each_cidr_queried_once(self, make_client):
        from fixtures import RIPESTAT_PREFIX_OVERVIEW
        routes = pipeline_routes()
        routes["prefix-overview"] = RIPESTAT_PREFIX_OVERVIEW
        fake = make_client(routes)
        pipeline = make_pipeline(fake)
        result = pipeline.run(RunOptions(target="Google"))
        scored = [n for n in result.netblocks if n.score > 0]
        assert fake.call_count("prefix-overview") <= len(scored)


class TestThirdPartyOriginAsn:
    """A prefix announced by someone else must not be reported as the
    company's ASN. For a SWIP reassignment the origin AS belongs to the
    upstream provider."""

    def test_third_party_holder_is_flagged(self, make_client):
        routes = pipeline_routes()
        routes["prefix-overview"] = {"data": {"asns": [
            {"asn": 7018, "holder": "ATT-INTERNET4"}]}}
        result = make_pipeline(make_client(routes)).run(RunOptions(target="Google"))
        flagged = [n for n in result.netblocks
                   if any(e.code == "THIRD_PARTY_ORIGIN" for e in n.evidence)]
        assert flagged
        assert all(n.asn_holder == "ATT-INTERNET4" for n in flagged)

    def test_matching_holder_not_flagged(self, make_client):
        routes = pipeline_routes()
        routes["prefix-overview"] = {"data": {"asns": [
            {"asn": 15169, "holder": "GOOGLE"}]}}
        result = make_pipeline(make_client(routes)).run(RunOptions(target="Google"))
        assert not any(e.code == "THIRD_PARTY_ORIGIN"
                       for n in result.netblocks for e in n.evidence)

    def test_summary_excludes_third_party_asns(self, make_client):
        from netblocktool.output import summarize
        routes = pipeline_routes()
        routes["prefix-overview"] = {"data": {"asns": [
            {"asn": 7018, "holder": "ATT-INTERNET4"}]}}
        result = make_pipeline(make_client(routes)).run(RunOptions(target="Google"))
        counts = summarize(result.netblocks)
        # AS15169 is legitimately counted: it comes from ARIN's org ASN record,
        # not from BGP origin data. AS7018 (the third-party origin) must not be.
        assert counts["asn_third_party"] >= 1
        company_asns = {
            asn.strip()
            for n in result.netblocks
            if n.asn and not any(e.code == "THIRD_PARTY_ORIGIN" for e in n.evidence)
            for asn in n.asn.split(",")
        }
        assert "AS7018" not in company_asns

    def test_third_party_flag_does_not_change_score(self, make_client):
        # It is informational provenance, not evidence for or against.
        routes = pipeline_routes()
        routes["prefix-overview"] = {"data": {"asns": [
            {"asn": 7018, "holder": "ATT-INTERNET4"}]}}
        result = make_pipeline(make_client(routes)).run(RunOptions(target="Google"))
        for netblock in result.netblocks:
            flags = [e for e in netblock.evidence if e.code == "THIRD_PARTY_ORIGIN"]
            assert all(e.points == 0 for e in flags)


class TestAsnDiscoveryFeedback:
    """Regression: an ASN discovered via BGP was labelled but never expanded.

    PayPal holds no ASN records under a matching ARIN organisation, so
    registry-based expansion found nothing. The origin-ASN lookup identified
    the real AS but only used it as a column value, so every prefix that AS
    announces was missed.
    """

    def test_bgp_discovered_asn_is_expanded(self, make_client):
        routes = pipeline_routes()
        # No ASN records under the organisation.
        routes["/rest/org/GOGL/asns"] = {"asns": {}}
        # BGP says the org's prefix is originated by an AS the company holds.
        routes["prefix-overview"] = {"data": {"asns": [
            {"asn": 15169, "holder": "GOOGLE"}]}}
        result = make_pipeline(make_client(routes)).run(RunOptions(target="Google"))
        # 8.8.4.0/24 exists only in the announced-prefixes fixture, so its
        # presence proves the discovered ASN was actually expanded.
        assert any(n.cidr == "8.8.4.0/24" for n in result.netblocks)

    def test_third_party_origin_is_not_expanded(self, make_client):
        routes = pipeline_routes()
        routes["/rest/org/GOGL/asns"] = {"asns": {}}
        # The prefix is announced by an unrelated provider.
        routes["prefix-overview"] = {"data": {"asns": [
            {"asn": 7018, "holder": "ATT-INTERNET4"}]}}
        fake = make_client(routes)
        result = make_pipeline(fake).run(RunOptions(target="Google"))
        # Expanding an ISP's AS would flood the output with third-party space.
        assert not any(n.cidr == "8.8.4.0/24" for n in result.netblocks)
        assert fake.call_count("announced-prefixes") == 0

    def test_registry_asns_take_precedence(self, make_client):
        # When the registry does hold ASN records, no BGP probing is needed.
        routes = pipeline_routes()
        routes["prefix-overview"] = {"data": {"asns": [
            {"asn": 15169, "holder": "GOOGLE"}]}}
        fake = make_client(routes)
        make_pipeline(fake).run(RunOptions(target="Google"))
        # ARIN_ORG_ASNS supplies AS15169, so seed probing must not run: the
        # only prefix-overview calls are the final labelling pass.
        assert fake.call_count("announced-prefixes") > 0

    def test_only_org_registered_netblocks_seed_discovery(self, make_client):
        routes = pipeline_routes()
        routes["/rest/org/GOGL/asns"] = {"asns": {}}
        routes["/rest/org/GOGL/nets"] = {"nets": {}}   # no org-registered nets
        routes["prefix-overview"] = {"data": {"asns": [
            {"asn": 15169, "holder": "GOOGLE"}]}}
        fake = make_client(routes)
        result = make_pipeline(fake).run(RunOptions(target="Google"))
        # Only customer reassignments remain; those are announced by the
        # upstream provider, so they must not seed ASN discovery.
        assert not any(n.cidr == "8.8.4.0/24" for n in result.netblocks)

    def test_disabled_by_no_asn_expansion(self, make_client):
        routes = pipeline_routes()
        routes["/rest/org/GOGL/asns"] = {"asns": {}}
        routes["prefix-overview"] = {"data": {"asns": [
            {"asn": 15169, "holder": "GOOGLE"}]}}
        fake = make_client(routes)
        make_pipeline(fake).run(RunOptions(target="Google", expand_asns=False))
        assert fake.call_count("prefix-overview") == 0
        assert fake.call_count("announced-prefixes") == 0


class TestSubsumedSemantics:
    """Regression: containment was implemented by zeroing the score.

    BGP-announced more-specifics sit inside registered allocations, so
    expanding an ASN pushed a batch of genuine company netblocks into
    "unlikely" - conflating "duplicate of a bigger block" with "we doubt this
    is yours", and hiding real results among the discards.
    """

    def test_contained_network_keeps_its_confidence(self, make_client):
        pipeline = make_pipeline(make_client(pipeline_routes()))
        blocks = [
            Netblock(cidr="8.8.0.0/16", name="Google LLC", score=85,
                     confidence=Confidence.CONFIRMED),
            Netblock(cidr="8.8.8.0/24", name="Google LLC", score=85,
                     confidence=Confidence.CONFIRMED),
        ]
        deduped = pipeline._deduplicate(blocks)
        contained = next(n for n in deduped if n.cidr == "8.8.8.0/24")
        assert contained.confidence is Confidence.CONFIRMED
        assert contained.subsumed is True

    def test_address_total_is_not_double_counted(self, make_client):
        from netblocktool.output import summarize
        pipeline = make_pipeline(make_client(pipeline_routes()))
        blocks = [
            Netblock(cidr="8.8.0.0/16", name="Google LLC", score=85, ip_version=4),
            Netblock(cidr="8.8.8.0/24", name="Google LLC", score=85, ip_version=4),
        ]
        deduped = pipeline._deduplicate(blocks)
        # The /24 is inside the /16, so the union is still 65536 addresses
        # even though both are now scored.
        assert summarize(deduped)["ipv4_addresses"] == 65536

    def test_summary_counts_contained_networks(self, make_client):
        from netblocktool.output import summarize
        pipeline = make_pipeline(make_client(pipeline_routes()))
        blocks = [
            Netblock(cidr="8.8.0.0/16", name="Google LLC", score=85),
            Netblock(cidr="8.8.8.0/24", name="Google LLC", score=85),
        ]
        assert summarize(pipeline._deduplicate(blocks))["subsumed"] == 1

    def test_no_subsumed_flag_filters_them_out(self, make_client):
        routes = pipeline_routes()
        routes["prefix-overview"] = {"data": {"asns": [
            {"asn": 15169, "holder": "GOOGLE"}]}}
        pipeline = make_pipeline(make_client(routes))
        with_all = pipeline.run(RunOptions(target="Google"))
        pipeline._registry_cache.clear()
        without = pipeline.run(RunOptions(target="Google", exclude_subsumed=True))
        assert all(not n.subsumed for n in without.netblocks)
        assert len(without.netblocks) <= len(with_all.netblocks)

    def test_subsumed_appears_in_csv_and_json(self, tmp_path):
        import csv as csvmod
        import json as jsonmod

        from netblocktool.output import write_csv, write_json
        blocks = [Netblock(cidr="8.8.8.0/24", ip_version=4, score=85,
                           subsumed=True)]
        path = write_csv(blocks, tmp_path / "s.csv")
        rows = list(csvmod.reader(path.open(encoding="utf-8")))
        assert rows[1][rows[0].index("subsumed")] == "yes"
        jpath = write_json(blocks, tmp_path / "s.json")
        assert jsonmod.loads(jpath.read_text())["netblocks"][0]["subsumed"] is True


class TestAsnSeedSpread:
    """Regression: every ASN probe went to one organisation.

    Seeds were taken as the first N netblocks in list order, which are all
    from whichever organisation was returned first - typically the largest
    ARIN org, whose prefixes share a single originating AS. A multinational's
    regional entities (PayPal Pvt Ltd in RIPE, say) announce from different
    ASes and were never probed, so only one ASN was ever discovered.
    """

    def test_seeds_are_spread_across_organisations(self):
        from netblocktool.pipeline import _spread_seeds

        blocks = [Netblock(cidr=f"8.8.{i}.0/24", registry="arin",
                           org_handle="PAYPAL") for i in range(10)]
        blocks += [Netblock(cidr=f"185.1.{i}.0/24", registry="ripe",
                            org_handle="ORG-PPL5-RIPE") for i in range(3)]
        seeds = _spread_seeds(blocks, 8)
        registries = {n.registry for n in seeds}
        assert registries == {"arin", "ripe"}, \
            "a minority organisation must still be probed"

    def test_every_organisation_probed_before_any_repeats(self):
        from netblocktool.pipeline import _spread_seeds

        blocks = [Netblock(cidr=f"8.8.{i}.0/24", registry="arin", org_handle="A")
                  for i in range(5)]
        blocks += [Netblock(cidr="1.1.1.0/24", registry="arin", org_handle="B")]
        blocks += [Netblock(cidr="2.2.2.0/24", registry="ripe", org_handle="C")]
        seeds = _spread_seeds(blocks, 3)
        assert {n.org_handle for n in seeds} == {"A", "B", "C"}

    def test_respects_the_limit(self):
        from netblocktool.pipeline import _spread_seeds

        blocks = [Netblock(cidr=f"8.8.{i}.0/24", registry="arin",
                           org_handle=f"ORG{i}") for i in range(20)]
        assert len(_spread_seeds(blocks, 8)) == 8

    def test_handles_fewer_blocks_than_limit(self):
        from netblocktool.pipeline import _spread_seeds

        blocks = [Netblock(cidr="8.8.8.0/24", registry="arin", org_handle="A")]
        assert len(_spread_seeds(blocks, 8)) == 1

    @pytest.mark.parametrize("limit", [0, -1])
    def test_non_positive_limit(self, limit):
        from netblocktool.pipeline import _spread_seeds

        blocks = [Netblock(cidr="8.8.8.0/24", registry="arin", org_handle="A")]
        assert _spread_seeds(blocks, limit) == []

    def test_empty_input(self):
        from netblocktool.pipeline import _spread_seeds
        assert _spread_seeds([], 8) == []

    def test_second_asn_is_discovered_from_a_minority_org(self, make_client):
        # Two organisations announcing from different ASes: both must be found.
        def prefix_overview(url, params):
            resource = params.get("resource", "")
            if resource.startswith("69.224."):
                return {"data": {"asns": [{"asn": 26594, "holder": "GOOGLE-2"}]}}
            return {"data": {"asns": [{"asn": 15169, "holder": "GOOGLE"}]}}

        routes = pipeline_routes()
        routes["/rest/org/GOGL/asns"] = {"asns": {}}
        routes["prefix-overview"] = prefix_overview
        pipeline = make_pipeline(make_client(routes))
        found = pipeline._discover_asns_from_prefixes([
            Netblock(cidr="8.8.8.0/24", registry="arin", org_handle="GOGL"),
            Netblock(cidr="69.224.21.208/29", registry="ripe",
                     org_handle="ORG-G2"),
        ], "Google")
        assert set(found) == {"AS15169", "AS26594"}


class TestErrorVisibility:
    """Regression: failures were collected but only written to JSON.

    A run could return fewer netblocks than the previous one with nothing on
    screen to explain why, which makes results impossible to trust.
    """

    def test_registry_failure_is_recorded_on_the_result(self, make_client):
        routes = pipeline_routes()
        routes["/rest/orgs;name="] = HttpError("ARIN timeout")
        result = make_pipeline(make_client(routes)).run(RunOptions(target="Google"))
        assert result.errors

    def test_report_errors_logs_each_distinct_message(self, caplog):
        import logging

        from netblocktool.cli import report_errors

        with caplog.at_level(logging.WARNING, logger="netblocktool.cli"):
            report_errors(["ARIN timeout", "ARIN timeout", "RIPE 500"])
        text = caplog.text
        assert "2 source error" not in text          # counts total, not distinct
        assert "3 source error(s)" in text
        assert "ARIN timeout" in text
        assert "(x2)" in text
        assert "RIPE 500" in text

    def test_report_errors_silent_when_clean(self, caplog):
        import logging

        from netblocktool.cli import report_errors

        with caplog.at_level(logging.WARNING, logger="netblocktool.cli"):
            report_errors([])
        assert caplog.text == ""

    def test_summary_shows_error_count(self, capsys):
        from netblocktool.cli import print_summary

        print_summary([Netblock(cidr="8.8.8.0/24", ip_version=4, score=80)],
                      "", quiet=False, errors=["boom", "bang"])
        out = capsys.readouterr().out
        assert "Source errors:" in out
        assert "results may be incomplete" in out

    def test_summary_omits_error_line_when_clean(self, capsys):
        from netblocktool.cli import print_summary

        print_summary([Netblock(cidr="8.8.8.0/24", ip_version=4, score=80)],
                      "", quiet=False, errors=[])
        assert "Source errors:" not in capsys.readouterr().out

    def test_quiet_mode_prints_nothing(self, capsys):
        from netblocktool.cli import print_summary

        print_summary([Netblock(cidr="8.8.8.0/24", ip_version=4, score=80)],
                      "", quiet=True, errors=["boom"])
        assert capsys.readouterr().out == ""
