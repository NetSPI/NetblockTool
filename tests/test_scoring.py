"""Confidence scoring model."""

from __future__ import annotations

import pytest

from netblocktool.models import Confidence, Netblock, ObjectType
from netblocktool.scoring import (
    SCORE_MAX,
    SCORE_MIN,
    ScoringContext,
    address_frequency,
    band_for_score,
    mark_corroborated,
    score_all,
    score_netblock,
)


def netblock(**kwargs) -> Netblock:
    defaults = {"cidr": "8.8.8.0/24", "name": "Google LLC", "registry": "arin"}
    defaults.update(kwargs)
    return Netblock(**defaults)


class TestBands:
    @pytest.mark.parametrize("score,band", [
        (99, Confidence.CONFIRMED),
        (80, Confidence.CONFIRMED),
        (79, Confidence.PROBABLE),
        (55, Confidence.PROBABLE),
        (54, Confidence.WEAK),
        (25, Confidence.WEAK),
        (24, Confidence.UNLIKELY),
        (0, Confidence.UNLIKELY),
    ])
    def test_thresholds(self, score, band):
        assert band_for_score(score) is band


class TestNameMatching:
    def test_exact_match_scores_high(self):
        result = score_netblock(netblock(name="Google LLC"),
                                ScoringContext(company_name="Google"))
        assert result.score >= 55
        assert any(e.code == "NAME_EXACT" for e in result.evidence)

    def test_mismatch_is_penalised_to_zero(self):
        result = score_netblock(netblock(name="Acme Widgets"),
                                ScoringContext(company_name="Google"))
        assert result.score == SCORE_MIN
        assert result.confidence is Confidence.UNLIKELY
        assert any(e.code == "NAME_MISMATCH" for e in result.evidence)

    def test_org_handle_link_reaches_confirmed(self):
        context = ScoringContext(company_name="Google",
                                 org_handles=frozenset({"NET-8-8-8-0-1"}))
        result = score_netblock(
            netblock(name="GOOGLE-CLOUD", handle="NET-8-8-8-0-1",
                     organization="Google LLC"),
            context,
        )
        assert result.confidence is Confidence.CONFIRMED
        assert any(e.code == "ORG_HANDLE_LINK" for e in result.evidence)

    def test_glued_letters_reduce_score(self):
        context = ScoringContext(company_name="Google")
        clean = score_netblock(netblock(cidr="1.1.1.0/24", name="Google Fiber"), context)
        glued = score_netblock(netblock(cidr="2.2.2.0/24", name="GOOGLEFIBER"), context)
        assert glued.score < clean.score
        assert any(e.code == "ALPHA_SUFFIX" for e in glued.evidence)

    def test_leading_wildcard_penalises_prefix_letters(self):
        context = ScoringContext(company_name="Google", leading_wildcard=True)
        result = score_netblock(netblock(name="NOTGOOGLE NET"), context)
        assert any(e.code == "ALPHA_PREFIX" for e in result.evidence)

    def test_no_penalty_without_leading_wildcard(self):
        context = ScoringContext(company_name="Google", leading_wildcard=False)
        result = score_netblock(netblock(name="NOTGOOGLE NET"), context)
        assert not any(e.code == "ALPHA_PREFIX" for e in result.evidence)


class TestBaselines:
    def test_search_only_never_reaches_confirmed(self):
        # Search-engine evidence alone must never be presented as confirmed
        # ownership, even with a perfect name match.
        result = score_netblock(
            netblock(name="Google", object_type=ObjectType.SEARCH, registry=""),
            ScoringContext(company_name="Google"),
        )
        assert result.confidence is not Confidence.CONFIRMED

    def test_asn_baseline_below_org_direct(self):
        context = ScoringContext(company_name="Google")
        asn = score_netblock(
            netblock(cidr="1.1.1.0/24", name="Google LLC", asn="AS15169",
                     object_type=ObjectType.ASN, organization="Google LLC"),
            context)
        direct = score_netblock(
            netblock(cidr="2.2.2.0/24", name="Google LLC", organization="Google LLC"),
            context)
        assert asn.score < direct.score

    def test_customer_type_recognised(self):
        result = score_netblock(
            netblock(name="GOOGLE INC-040731031303",
                     object_type=ObjectType.CUSTOMER),
            ScoringContext(company_name="Google"))
        assert any(e.code == "BASE_CUSTOMER" for e in result.evidence)


class TestAddressScoring:
    def test_dominant_address_adds_points(self):
        frequency = address_frequency(["1600 Amphitheatre Parkway"] * 3)
        context = ScoringContext(company_name="Google", address_frequency=frequency)
        with_address = score_netblock(
            netblock(cidr="1.1.1.0/24", address="1600 Amphitheatre Parkway"), context)
        without = score_netblock(netblock(cidr="2.2.2.0/24"), context)
        assert with_address.score > without.score
        assert any(e.code == "ADDRESS_MATCH" for e in with_address.evidence)

    def test_frequency_computation(self):
        result = address_frequency(["A", "A", "A", "B"])
        assert result["A"] == pytest.approx(0.75)
        assert result["B"] == pytest.approx(0.25)

    def test_empty_addresses(self):
        assert address_frequency([]) == {}
        assert address_frequency(["", "  ", None]) == {}


class TestInvalidAndPrivate:
    def test_no_valid_cidr_scores_zero(self):
        result = score_netblock(netblock(cidr="Error: no network information"),
                                ScoringContext(company_name="Google"))
        assert result.score == SCORE_MIN
        assert any(e.code == "NO_CIDR" for e in result.evidence)

    @pytest.mark.parametrize("cidr", ["10.0.0.0/8", "192.168.1.0/24", "127.0.0.0/8"])
    def test_private_space_scores_zero(self, cidr):
        result = score_netblock(netblock(cidr=cidr, name="Google LLC"),
                                ScoringContext(company_name="Google"))
        assert result.score == SCORE_MIN

    def test_ip_version_is_set(self):
        context = ScoringContext(company_name="Google")
        assert score_netblock(netblock(cidr="8.8.8.0/24"), context).ip_version == 4
        assert score_netblock(netblock(cidr="2001:db8::/32"), context).ip_version == 6


class TestClamping:
    def test_score_never_exceeds_max(self):
        context = ScoringContext(
            company_name="Google",
            org_handles=frozenset({"H1"}),
            address_frequency={"addr": 1.0},
            subsidiary_keys=frozenset({"youtube"}),
        )
        result = score_netblock(
            netblock(name="Google", handle="H1", organization="Google",
                     address="addr", subsidiary="YouTube"),
            context)
        assert SCORE_MIN <= result.score <= SCORE_MAX

    def test_score_never_below_zero(self):
        result = score_netblock(
            netblock(cidr="10.0.0.0/8", name="Totally Different Co"),
            ScoringContext(company_name="Google"))
        assert result.score == SCORE_MIN


class TestEvidenceOutput:
    def test_every_result_carries_evidence(self):
        result = score_netblock(netblock(), ScoringContext(company_name="Google"))
        assert result.evidence
        assert result.evidence_text()

    def test_evidence_text_is_readable(self):
        result = score_netblock(netblock(name="Google LLC"),
                                ScoringContext(company_name="Google"))
        text = result.evidence_text()
        assert "NAME_EXACT" in text
        assert "+" in text


class TestScoreAll:
    def test_sorted_by_descending_score(self):
        context = ScoringContext(company_name="Google")
        results = score_all([
            netblock(cidr="1.1.1.0/24", name="Unrelated Corp"),
            netblock(cidr="2.2.2.0/24", name="Google LLC"),
        ], context)
        assert results[0].score >= results[1].score
        assert results[0].name == "Google LLC"

    def test_empty_input(self):
        assert score_all([], ScoringContext(company_name="Google")) == []


class TestCorroboration:
    def test_multiple_source_types_boost_score(self):
        context = ScoringContext(company_name="Google")
        blocks = score_all([
            netblock(cidr="8.8.8.0/24", name="Google LLC"),
            netblock(cidr="8.8.8.0/24", name="Google LLC",
                     object_type=ObjectType.ASN, asn="AS15169"),
        ], context)
        before = [b.score for b in blocks]
        mark_corroborated(blocks)
        assert all(a >= b for a, b in zip([b.score for b in blocks], before, strict=True))
        assert any(e.code == "CORROBORATED" for b in blocks for e in b.evidence)

    def test_single_source_not_corroborated(self):
        context = ScoringContext(company_name="Google")
        blocks = score_all([netblock(name="Google LLC")], context)
        mark_corroborated(blocks)
        assert not any(e.code == "CORROBORATED"
                       for b in blocks for e in b.evidence)

    def test_zero_scored_blocks_not_boosted(self):
        context = ScoringContext(company_name="Google")
        blocks = score_all([
            netblock(cidr="10.0.0.0/8", name="Google LLC"),
            netblock(cidr="10.0.0.0/8", name="Google LLC",
                     object_type=ObjectType.ASN),
        ], context)
        mark_corroborated(blocks)
        assert all(b.score == 0 for b in blocks)


class TestOrgHandleLinkRegression:
    """Regression: networks registered to a matched org must reach 'confirmed'.

    Observed against live ARIN data for PayPal: 46 results sat at 'probable'
    and only 2 at 'confirmed', because ORG_HANDLE_LINK compared a NET handle
    against a set of ORG handles and never matched.
    """

    def test_org_registered_net_reaches_confirmed(self):
        context = ScoringContext(company_name="Paypal",
                                 org_handles=frozenset({"PAYPA"}))
        result = score_netblock(
            netblock(cidr="66.211.168.0/22", name="PAYPAL-INC",
                     handle="NET-66-211-168-0-1", org_handle="PAYPA",
                     organization="PayPal, Inc."),
            context)
        assert any(e.code == "ORG_HANDLE_LINK" for e in result.evidence)
        assert result.confidence is Confidence.CONFIRMED

    def test_unmatched_org_handle_does_not_link(self):
        context = ScoringContext(company_name="Paypal",
                                 org_handles=frozenset({"PAYPA"}))
        result = score_netblock(
            netblock(cidr="1.1.1.0/24", name="PAYPAL-INC",
                     handle="NET-1-1-1-0-1", org_handle="SOMEONEELSE"),
            context)
        assert not any(e.code == "ORG_HANDLE_LINK" for e in result.evidence)

    def test_falls_back_to_handle_for_registries_sharing_a_namespace(self):
        # RDAP entity and network handles can coincide; the fallback preserves
        # linking for those registries.
        context = ScoringContext(company_name="Example",
                                 org_handles=frozenset({"ORG-EX1-RIPE"}))
        result = score_netblock(
            netblock(cidr="193.0.0.0/21", name="Example Networks",
                     handle="ORG-EX1-RIPE", registry="ripe"),
            context)
        assert any(e.code == "ORG_HANDLE_LINK" for e in result.evidence)


class TestContactBaseline:
    """A registry contact reference is much weaker than an org: reference."""

    def test_contact_scores_below_network(self):
        ctx = ScoringContext(company_name="Paypal")
        contact = score_netblock(
            netblock(cidr="185.1.1.0/24", name="PAYPAL-IN", registry="ripe",
                     object_type=ObjectType.CONTACT), ctx)
        network = score_netblock(
            netblock(cidr="185.1.2.0/24", name="PAYPAL-IN", registry="ripe"), ctx)
        assert contact.score < network.score
        assert any(e.code == "BASE_CONTACT" for e in contact.evidence)

    def test_unrelated_network_via_contact_is_unlikely(self):
        # An ISP network where a company employee happens to be tech-c.
        result = score_netblock(
            netblock(cidr="185.1.3.0/24", name="SOME-ISP-NET", registry="ripe",
                     object_type=ObjectType.CONTACT),
            ScoringContext(company_name="Paypal"))
        assert result.confidence is Confidence.UNLIKELY

    def test_contact_never_reaches_confirmed(self):
        result = score_netblock(
            netblock(cidr="185.1.4.0/24", name="Paypal", registry="ripe",
                     object_type=ObjectType.CONTACT),
            ScoringContext(company_name="Paypal"))
        assert result.confidence is not Confidence.CONFIRMED
