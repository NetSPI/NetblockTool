"""SEC EDGAR client and Exhibit 21 subsidiary extraction."""

from __future__ import annotations

import pytest
from fixtures import (
    EDGAR_COMPANY_TICKERS,
    EDGAR_FILING_INDEX,
    EDGAR_FILING_INDEX_NO_EX21,
    EDGAR_SUBMISSIONS,
    EX21_EMPTY,
    EX21_HTML_TABLE,
    EX21_HTML_THREE_COLUMN,
    EX21_TEXT,
)

from netblocktool.edgar_client import EdgarClient, EdgarCompany, Filing
from netblocktool.http import HttpError
from netblocktool.subsidiaries import (
    discover_subsidiaries,
    extract_from_tables,
    extract_from_text,
    looks_like_company,
    merge_targets,
    parse_exhibit21,
    subsidiary_keys,
)


def edgar_routes() -> dict:
    return {
        "company_tickers.json": EDGAR_COMPANY_TICKERS,
        "/submissions/CIK": EDGAR_SUBMISSIONS,
        "000165204424000022/index.json": EDGAR_FILING_INDEX,
        "000165204423000016/index.json": EDGAR_FILING_INDEX_NO_EX21,
        "goog-ex211_2023.htm": EX21_HTML_TABLE,
    }


# -- company lookup ---------------------------------------------------------


class TestFindCompanies:
    def test_exact_match_first(self, make_client):
        client = EdgarClient(make_client(edgar_routes()))
        results = client.find_companies("Alphabet")
        assert results
        assert results[0].name == "Alphabet Inc."
        assert results[0].cik == "1652044"

    def test_suffix_insensitive(self, make_client):
        client = EdgarClient(make_client(edgar_routes()))
        assert client.find_companies("Alphabet Inc.")[0].cik == "1652044"

    def test_case_insensitive(self, make_client):
        client = EdgarClient(make_client(edgar_routes()))
        assert client.find_companies("microsoft")[0].cik == "789019"

    def test_no_match_returns_empty(self, make_client):
        client = EdgarClient(make_client(edgar_routes()))
        assert client.find_companies("Nonexistent Widget Co") == []

    def test_directory_downloaded_only_once(self, make_client):
        # The old edgar package re-downloaded a 10 MB file per company.
        fake = make_client(edgar_routes())
        client = EdgarClient(fake)
        for name in ("Alphabet", "Apple", "Microsoft", "Alphabet"):
            client.find_companies(name)
        assert fake.call_count("company_tickers.json") == 1

    def test_directory_failure_is_graceful(self, make_client):
        client = EdgarClient(make_client({"company_tickers.json": HttpError("403")}))
        assert client.find_companies("Alphabet") == []

    def test_malformed_directory_tolerated(self, make_client):
        client = EdgarClient(make_client({"company_tickers.json": ["not", "a", "dict"]}))
        assert client.find_companies("Alphabet") == []

    def test_padded_cik(self):
        assert EdgarCompany(cik="1652044", name="X").padded_cik == "0001652044"


# -- filings ----------------------------------------------------------------


class TestFilings:
    def test_filters_to_subsidiary_bearing_forms(self, make_client):
        client = EdgarClient(make_client(edgar_routes()))
        company = EdgarCompany(cik="1652044", name="Alphabet Inc.")
        filings = client.recent_filings(company)
        assert all(f.form in ("10-K", "20-F", "40-F", "10-K405", "10-KSB",
                              "S-1", "S-4") for f in filings)
        assert len(filings) == 2  # the 8-K is excluded

    def test_submissions_failure_returns_empty(self, make_client):
        routes = edgar_routes()
        routes["/submissions/CIK"] = HttpError("timeout")
        client = EdgarClient(make_client(routes))
        assert client.recent_filings(EdgarCompany(cik="1", name="X")) == []

    def test_missing_filings_block(self, make_client):
        routes = edgar_routes()
        routes["/submissions/CIK"] = {"cik": "1", "name": "X"}
        client = EdgarClient(make_client(routes))
        assert client.recent_filings(EdgarCompany(cik="1", name="X")) == []

    def test_accession_url_construction(self):
        filing = Filing(accession="0001652044-24-000022", form="10-K",
                        filing_date="2024-01-31", cik="1652044")
        assert filing.accession_nodash == "000165204424000022"
        assert "1652044/000165204424000022/index.json" in filing.index_url


class TestFindExhibit21:
    def test_locates_ex21_document(self, make_client):
        client = EdgarClient(make_client(edgar_routes()))
        filing = Filing(accession="0001652044-24-000022", form="10-K",
                        filing_date="2024-01-31", cik="1652044")
        located = client.find_exhibit21(filing)
        assert located is not None
        url, name = located
        assert name == "goog-ex211_2023.htm"
        assert url.startswith("https://www.sec.gov/Archives/edgar/data/1652044/")

    def test_filing_without_ex21_returns_none(self, make_client):
        client = EdgarClient(make_client(edgar_routes()))
        filing = Filing(accession="0001652044-23-000016", form="10-K",
                        filing_date="2023-02-03", cik="1652044")
        assert client.find_exhibit21(filing) is None

    def test_index_failure_returns_none(self, make_client):
        routes = edgar_routes()
        routes["000165204424000022/index.json"] = HttpError("500")
        client = EdgarClient(make_client(routes))
        filing = Filing(accession="0001652044-24-000022", form="10-K",
                        filing_date="", cik="1652044")
        assert client.find_exhibit21(filing) is None

    def test_filename_fallback_when_type_missing(self, make_client):
        routes = edgar_routes()
        routes["000165204424000022/index.json"] = {"directory": {"item": [
            {"name": "acme-ex21.htm", "type": ""},
        ]}}
        client = EdgarClient(make_client(routes))
        filing = Filing(accession="0001652044-24-000022", form="10-K",
                        filing_date="", cik="1652044")
        located = client.find_exhibit21(filing)
        assert located is not None and located[1] == "acme-ex21.htm"


# -- Exhibit 21 parsing -----------------------------------------------------


class TestLooksLikeCompany:
    @pytest.mark.parametrize("value", [
        "Google LLC", "YouTube, LLC", "DeepMind Technologies Limited",
        "Acme Manufacturing Inc.", "Widget Europe Limited",
    ])
    def test_accepts_company_names(self, value):
        assert looks_like_company(value) is not None

    @pytest.mark.parametrize("value", [
        "Delaware", "United Kingdom", "Jurisdiction of Incorporation",
        "Legal Name", "Exhibit 21.1", "100%", "  ", "", None, "1", "(1)",
        "December 31, 2023", "***", "State or Other Jurisdiction",
        "Percentage Owned", "Name of Subsidiary", "table of contents",
    ])
    def test_rejects_non_companies(self, value):
        assert looks_like_company(value) is None

    def test_strips_footnote_markers(self):
        assert looks_like_company("Acme Corp (1)") == "Acme Corp"
        assert looks_like_company("Acme Corp (a)") == "Acme Corp"

    def test_normalises_whitespace_and_nbsp(self):
        assert looks_like_company("Acme\xa0 Corp\n") == "Acme Corp"

    def test_rejects_parent_company_itself(self):
        assert looks_like_company("Alphabet Inc.", parent_name="Alphabet Inc.") is None
        assert looks_like_company("Google LLC", parent_name="Alphabet Inc.") is not None

    def test_rejects_urls(self):
        assert looks_like_company("https://www.sec.gov/index.htm") is None

    def test_rejects_overlong_strings(self):
        assert looks_like_company("A" * 200) is None


class TestParseExhibit21:
    def test_two_column_table(self):
        names = parse_exhibit21(EX21_HTML_TABLE, "Alphabet Inc.")
        assert "Google LLC" in names
        assert "YouTube, LLC" in names
        assert "DeepMind Technologies Limited" in names
        # The jurisdiction column must not leak into the results.
        assert "Delaware" not in names
        assert "Ireland" not in names

    def test_header_row_excluded(self):
        names = parse_exhibit21(EX21_HTML_TABLE, "Alphabet Inc.")
        assert "Legal Name" not in names

    def test_three_column_with_percentages(self):
        names = parse_exhibit21(EX21_HTML_THREE_COLUMN, "Acme Corp")
        assert "Acme Manufacturing Inc." in names   # footnote stripped
        assert "Acme Logistics GmbH" in names
        assert not any("%" in n for n in names)
        assert "Germany" not in names

    def test_plain_text_exhibit(self):
        names = parse_exhibit21(EX21_TEXT, "Widget Holdings")
        assert "Widget Industries Inc." in names
        assert "Widget Europe Limited" in names
        assert "Delaware" not in names

    def test_empty_exhibit_yields_nothing(self):
        assert parse_exhibit21(EX21_EMPTY, "Acme") == []

    @pytest.mark.parametrize("document", ["", "   ", None])
    def test_blank_document(self, document):
        assert parse_exhibit21(document, "Acme") == []

    def test_malformed_html_does_not_raise(self):
        broken = "<html><table><tr><td>Acme Widgets Inc<table><tr></html"
        assert isinstance(parse_exhibit21(broken, "Parent"), list)

    def test_results_are_deduplicated(self):
        document = """<table>
          <tr><td>Acme Widgets LLC</td><td>Delaware</td></tr>
          <tr><td>ACME WIDGETS INC</td><td>Delaware</td></tr>
          <tr><td>Beta Corp</td><td>Nevada</td></tr>
        </table>"""
        names = parse_exhibit21(document, "Parent")
        assert len(names) == 2

    def test_table_extraction_helper(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(EX21_HTML_TABLE, "html.parser")
        names = extract_from_tables(soup, "Alphabet Inc.")
        assert "Google LLC" in names

    def test_text_extraction_helper(self):
        names = extract_from_text(EX21_TEXT, "Widget Holdings")
        assert "Widget Industries Inc." in names


# -- discovery pipeline -----------------------------------------------------


class TestDiscoverSubsidiaries:
    def test_end_to_end(self, make_client):
        client = EdgarClient(make_client(edgar_routes()))
        subsidiaries = discover_subsidiaries(client, "Alphabet")
        names = {s.name for s in subsidiaries}
        assert "Google LLC" in names
        assert "YouTube, LLC" in names
        assert all(s.parent == "Alphabet Inc." for s in subsidiaries)
        assert all(s.source_url for s in subsidiaries)

    def test_unknown_company_returns_empty(self, make_client):
        client = EdgarClient(make_client(edgar_routes()))
        assert discover_subsidiaries(client, "Totally Private Ltd") == []

    def test_no_filings_returns_empty(self, make_client):
        routes = edgar_routes()
        routes["/submissions/CIK"] = {"cik": "1652044", "filings": {"recent": {
            "accessionNumber": [], "form": [], "filingDate": []}}}
        client = EdgarClient(make_client(routes))
        assert discover_subsidiaries(client, "Alphabet") == []

    def test_no_exhibit21_returns_empty(self, make_client):
        routes = edgar_routes()
        routes["000165204424000022/index.json"] = EDGAR_FILING_INDEX_NO_EX21
        client = EdgarClient(make_client(routes))
        assert discover_subsidiaries(client, "Alphabet") == []

    def test_document_download_failure_is_graceful(self, make_client):
        routes = edgar_routes()
        routes["goog-ex211_2023.htm"] = HttpError("connection reset")
        client = EdgarClient(make_client(routes))
        assert discover_subsidiaries(client, "Alphabet") == []

    def test_results_are_deduplicated_by_normalised_name(self, make_client):
        routes = edgar_routes()
        routes["goog-ex211_2023.htm"] = """<table>
            <tr><td>Google LLC</td><td>Delaware</td></tr>
            <tr><td>GOOGLE INC</td><td>Delaware</td></tr>
        </table>"""
        client = EdgarClient(make_client(routes))
        assert len(discover_subsidiaries(client, "Alphabet")) == 1


class TestMergeTargets:
    def test_target_comes_first(self):
        from netblocktool.models import Subsidiary
        subs = [Subsidiary(name="YouTube", parent="Alphabet")]
        assert merge_targets("Alphabet", subs) == ["Alphabet", "YouTube"]

    def test_no_duplicate_queries(self):
        from netblocktool.models import Subsidiary
        subs = [Subsidiary(name="Alphabet Inc.", parent="Alphabet"),
                Subsidiary(name="YouTube LLC", parent="Alphabet"),
                Subsidiary(name="YouTube, Inc.", parent="Alphabet")]
        result = merge_targets("Alphabet", subs)
        assert result == ["Alphabet", "YouTube LLC"]

    def test_no_subsidiaries(self):
        assert merge_targets("Alphabet", []) == ["Alphabet"]

    def test_subsidiary_keys_normalised(self):
        from netblocktool.models import Subsidiary
        keys = subsidiary_keys([Subsidiary(name="YouTube, LLC", parent="X")])
        assert "youtube" in keys
