"""Company-name normalisation and deduplication."""

from __future__ import annotations

import pytest

from netblocktool.normalize import (
    dedupe_names,
    is_jurisdiction,
    name_key,
    name_variants,
    normalize_company_name,
    strip_accents,
    strip_legal_suffix,
)


class TestNormalizeCompanyName:
    @pytest.mark.parametrize("raw,expected", [
        ("Google", "google"),
        ("Google LLC", "google"),
        ("Google, Inc.", "google"),
        ("GOOGLE INC-040731031303", "google"),      # ARIN discriminator
        ("The Coca-Cola Company", "coca cola"),
        ("Acme Holdings Inc", "acme"),              # repeated suffix stripping
        ("Nestlé S.A.", "nestle"),                  # accents + dotted suffix
        ("Fiat S.p.A.", "fiat"),
        ("A.B.C. Widgets LLC", "abc widgets"),
        ("GOOGLE-CLOUD", "google cloud"),
        ("Smith & Sons Ltd", "smith and sons"),
        ("  Extra   Spaces  Corp ", "extra spaces"),
    ])
    def test_normalisation(self, raw, expected):
        assert normalize_company_name(raw) == expected

    @pytest.mark.parametrize("value", [None, "", "   ", ",,,", "..."])
    def test_unusable_input_gives_empty_string(self, value):
        assert normalize_company_name(value) == ""

    def test_different_spellings_converge(self):
        spellings = ["Google LLC", "Google, Inc.", "GOOGLE INC-040731031303",
                     "google", "  Google  "]
        assert len({normalize_company_name(s) for s in spellings}) == 1

    def test_distinct_companies_stay_distinct(self):
        assert normalize_company_name("Google") != normalize_company_name("Googol")
        assert normalize_company_name("Apple") != normalize_company_name("Apple Bank")


class TestStripAccents:
    def test_folds_to_ascii(self):
        assert strip_accents("Nestlé") == "Nestle"
        assert strip_accents("México") == "Mexico"

    def test_leaves_ascii_alone(self):
        assert strip_accents("Google") == "Google"


class TestNameKey:
    def test_removes_all_separators(self):
        assert name_key("Coca-Cola Company") == "cocacola"

    def test_matches_across_punctuation(self):
        assert name_key("Wal-Mart") == name_key("Wal Mart") == name_key("WalMart")


class TestNameVariants:
    def test_includes_base_and_suffixed_forms(self):
        variants = name_variants("Google")
        assert "google" in variants
        assert "google llc" in variants
        assert "google inc" in variants

    def test_empty_name_gives_no_variants(self):
        assert name_variants("") == frozenset()


class TestStripLegalSuffix:
    def test_preserves_original_casing(self):
        assert strip_legal_suffix("Google LLC") == "Google"
        assert strip_legal_suffix("Acme Holdings Inc.") == "Acme"

    def test_no_suffix_is_unchanged(self):
        assert strip_legal_suffix("Google") == "Google"

    def test_empty(self):
        assert strip_legal_suffix("") == ""


class TestIsJurisdiction:
    @pytest.mark.parametrize("value", [
        "Delaware", "delaware", "United States", "DE", "Ireland",
        "United Kingdom", "Nevada", "  Delaware  ",
    ])
    def test_recognises_jurisdictions(self, value):
        assert is_jurisdiction(value) is True

    @pytest.mark.parametrize("value", [
        "Google LLC", "YouTube", "DeepMind Technologies Limited", "", None,
    ])
    def test_rejects_companies(self, value):
        assert is_jurisdiction(value) is False


class TestDedupeNames:
    def test_collapses_spelling_variants(self):
        result = dedupe_names(["Google LLC", "GOOGLE INC", "google", "YouTube"])
        assert result == ["Google LLC", "YouTube"]

    def test_keeps_first_spelling(self):
        assert dedupe_names(["GOOGLE INC", "Google LLC"]) == ["GOOGLE INC"]

    def test_drops_blank_entries(self):
        assert dedupe_names(["Google", "", "   ", None]) == ["Google"]

    def test_empty_input(self):
        assert dedupe_names([]) == []

    def test_result_is_sorted_case_insensitively(self):
        assert dedupe_names(["zebra corp", "Alpha Inc"]) == ["Alpha Inc", "zebra corp"]


class TestLiveDataSuffixes:
    """Suffixes observed in live RIPE/APNIC records."""

    @pytest.mark.parametrize("raw,expected", [
        ("PayPal Pvt Ltd", "paypal"),          # was "paypal pvt" -> scored weak
        ("Acme Private Limited", "acme"),
        ("Widget Pte Ltd", "widget"),
        ("Beta Pty Ltd", "beta"),
        ("Gamma Co Ltd", "gamma"),
    ])
    def test_legal_suffixes_stripped(self, raw, expected):
        assert normalize_company_name(raw) == expected

    @pytest.mark.parametrize("raw,expected", [
        # Descriptive words are NOT legal suffixes: stripping them would
        # conflate genuinely different companies and invent matches.
        ("Acme Technologies Ltd", "acme technologies"),
        ("Amazon Web Services", "amazon web services"),
        ("PayPal Network", "paypal network"),
        ("Contoso Solutions Inc", "contoso solutions"),
    ])
    def test_descriptive_words_preserved(self, raw, expected):
        assert normalize_company_name(raw) == expected

    def test_distinct_companies_do_not_collide(self):
        assert normalize_company_name("Acme") != \
            normalize_company_name("Acme Technologies")
