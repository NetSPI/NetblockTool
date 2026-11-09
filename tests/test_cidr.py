"""CIDR parsing, IP version handling and deduplication."""

from __future__ import annotations

import pytest

from netblocktool.cidr import (
    collapse_cidrs,
    count_addresses,
    dedupe_cidrs,
    filter_by_version,
    find_subsumed,
    ip_version,
    is_public,
    normalize_cidr,
    parse_cidr,
    range_to_cidrs,
)


class TestParseCidr:
    @pytest.mark.parametrize("value,expected", [
        ("8.8.8.0/24", "8.8.8.0/24"),
        ("  8.8.8.0/24  ", "8.8.8.0/24"),
        ("8.8.8.8", "8.8.8.8/32"),
        ("8.8.8.5/24", "8.8.8.0/24"),          # host bits tolerated
        ("2001:4860::/32", "2001:4860::/32"),
        ("2001:4860::1", "2001:4860::1/128"),
        ("2001:DB8::/32", "2001:db8::/32"),    # normalised case
    ])
    def test_valid(self, value, expected):
        assert normalize_cidr(value) == expected

    @pytest.mark.parametrize("value", [
        None, "", "   ", "not-a-network", "Error: no network information",
        "999.999.999.999/24", "8.8.8.0/33", "2001:db8::/129", "8.8.8.0/",
        "/24", "8.8.8.0-8.8.8.255",
    ])
    def test_invalid_returns_none(self, value):
        assert parse_cidr(value) is None
        assert normalize_cidr(value) is None

    def test_never_raises_on_garbage(self):
        # Registry data is untrusted; parsing must degrade, not explode.
        for value in [object(), 12345, b"bytes", ["list"]]:
            assert parse_cidr(value) is None  # type: ignore[arg-type]


class TestIpVersion:
    def test_ipv4(self):
        assert ip_version("8.8.8.0/24") == 4

    def test_ipv6(self):
        assert ip_version("2001:4860::/32") == 6

    def test_invalid(self):
        assert ip_version("garbage") is None

    def test_filter_ipv4_only(self):
        mixed = ["8.8.8.0/24", "2001:4860::/32", "1.1.1.0/24", "bad"]
        assert filter_by_version(mixed, 4) == ["8.8.8.0/24", "1.1.1.0/24"]

    def test_filter_ipv6_only(self):
        mixed = ["8.8.8.0/24", "2001:4860::/32", "bad"]
        assert filter_by_version(mixed, 6) == ["2001:4860::/32"]

    def test_filter_none_keeps_both_but_drops_invalid(self):
        mixed = ["8.8.8.0/24", "2001:4860::/32", "bad"]
        assert filter_by_version(mixed, None) == ["8.8.8.0/24", "2001:4860::/32"]


class TestPublicSpace:
    @pytest.mark.parametrize("cidr", [
        "10.0.0.0/8", "192.168.1.0/24", "172.16.0.0/12", "127.0.0.0/8",
        "169.254.0.0/16", "224.0.0.0/4", "fe80::/10", "::1/128",
    ])
    def test_non_public(self, cidr):
        assert is_public(cidr) is False

    @pytest.mark.parametrize("cidr", ["8.8.8.0/24", "1.1.1.0/24", "2001:4860::/32"])
    def test_public(self, cidr):
        assert is_public(cidr) is True

    def test_invalid_is_not_public(self):
        assert is_public("garbage") is False
        assert is_public(None) is False


class TestRangeToCidrs:
    def test_exact_block(self):
        assert [str(c) for c in range_to_cidrs("8.8.8.0", "8.8.8.255")] == ["8.8.8.0/24"]

    def test_non_aligned_range_splits(self):
        result = [str(c) for c in range_to_cidrs("69.224.21.208", "69.224.21.215")]
        assert result == ["69.224.21.208/29"]

    def test_ipv6_range(self):
        # 2001:4860:4860:: - ...:ffff:ffff:ffff:ffff:ffff varies the low 80
        # bits, which is a /48, not a /64.
        result = [str(c) for c in range_to_cidrs(
            "2001:4860:4860::", "2001:4860:4860:ffff:ffff:ffff:ffff:ffff")]
        assert result == ["2001:4860:4860::/48"]

    @pytest.mark.parametrize("start,end", [
        ("8.8.8.255", "8.8.8.0"),        # reversed
        ("8.8.8.0", "2001:db8::"),       # mixed families
        ("garbage", "8.8.8.255"),
        ("", ""),
    ])
    def test_invalid_returns_empty(self, start, end):
        assert range_to_cidrs(start, end) == []


class TestDeduplication:
    def test_exact_duplicates_removed(self):
        assert dedupe_cidrs(["8.8.8.0/24", "8.8.8.0/24"]) == ["8.8.8.0/24"]

    def test_normalises_before_comparing(self):
        # Same network written three ways collapses to one entry.
        assert dedupe_cidrs(["8.8.8.0/24", "8.8.8.5/24", " 8.8.8.0/24 "]) == \
            ["8.8.8.0/24"]

    def test_preserves_order(self):
        assert dedupe_cidrs(["1.1.1.0/24", "8.8.8.0/24", "1.1.1.0/24"]) == \
            ["1.1.1.0/24", "8.8.8.0/24"]

    def test_drops_invalid(self):
        assert dedupe_cidrs(["8.8.8.0/24", "garbage", None]) == ["8.8.8.0/24"]


class TestFindSubsumed:
    def test_finds_contained_ipv4(self):
        assert find_subsumed(["10.0.0.0/8", "10.1.0.0/16"]) == {"10.1.0.0/16"}

    def test_finds_contained_ipv6(self):
        assert find_subsumed(["2001:db8::/32", "2001:db8:1::/48"]) == \
            {"2001:db8:1::/48"}

    def test_disjoint_networks_are_kept(self):
        assert find_subsumed(["8.8.8.0/24", "1.1.1.0/24"]) == set()

    def test_equal_networks_not_reported(self):
        # Exact duplicates are dedupe_cidrs' job, not this function's.
        assert find_subsumed(["8.8.8.0/24", "8.8.8.0/24"]) == set()

    def test_does_not_mix_ip_families(self):
        assert find_subsumed(["0.0.0.0/0", "2001:db8::/32"]) == set()

    def test_deeply_nested(self):
        result = find_subsumed(["10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24"])
        assert result == {"10.1.0.0/16", "10.1.1.0/24"}

    def test_ignores_invalid(self):
        assert find_subsumed(["10.0.0.0/8", "garbage", "10.1.0.0/16"]) == \
            {"10.1.0.0/16"}

    def test_empty(self):
        assert find_subsumed([]) == set()


class TestCollapse:
    def test_merges_adjacent(self):
        assert collapse_cidrs(["10.0.0.0/9", "10.128.0.0/9"]) == ["10.0.0.0/8"]

    def test_merges_overlapping(self):
        assert collapse_cidrs(["10.0.0.0/8", "10.1.0.0/16"]) == ["10.0.0.0/8"]

    def test_keeps_families_separate(self):
        result = collapse_cidrs(["8.8.8.0/24", "2001:db8::/32"])
        assert set(result) == {"8.8.8.0/24", "2001:db8::/32"}


class TestCountAddresses:
    def test_counts_ipv4_without_double_counting(self):
        # /24 contains the /25, so the union is 256 addresses, not 384.
        assert count_addresses(["8.8.8.0/24", "8.8.8.0/25"], 4) == 256

    def test_counts_ipv6(self):
        assert count_addresses(["2001:db8::/126"], 6) == 4

    def test_version_filter_applies(self):
        assert count_addresses(["8.8.8.0/24", "2001:db8::/126"], 4) == 256

    def test_empty(self):
        assert count_addresses([], 4) == 0
