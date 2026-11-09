"""Search providers and the HTTP client's retry/backoff/safety behaviour."""

from __future__ import annotations

import pytest
from fixtures import (
    GOOGLE_CAPTCHA_HTML,
    GOOGLE_NO_RESULTS_HTML,
    GOOGLE_RESULTS_HTML,
)

from netblocktool.http import BlockedError, HttpError, Response, validate_url
from netblocktool.models import ObjectType
from netblocktool.search import (
    NullSearchProvider,
    SearchOutcome,
    available_providers,
    get_provider,
)
from netblocktool.search.google import (
    GoogleSearchProvider,
    _is_blocked,
    _resolve_href,
    _result_name,
)


def html_response(body: str, status: int = 200, url: str = "https://www.google.com/search"):
    return Response(url=url, status_code=status, text=body,
                    content=body.encode(), headers={})


# -- provider selection -----------------------------------------------------


class TestProviderSelection:
    def test_google_by_name(self, fake_client):
        assert isinstance(get_provider("google", fake_client), GoogleSearchProvider)

    def test_none_disables_search(self, fake_client):
        assert isinstance(get_provider("none", fake_client), NullSearchProvider)

    def test_unknown_falls_back_to_null(self, fake_client):
        assert isinstance(get_provider("bing-o-matic", fake_client), NullSearchProvider)

    def test_null_input_falls_back(self, fake_client):
        assert isinstance(get_provider(None, fake_client), NullSearchProvider)

    def test_available_providers_listed(self):
        assert "none" in available_providers()
        assert "google" in available_providers()


class TestNullProvider:
    def test_produces_nothing_and_makes_no_requests(self, fake_client):
        outcome = NullSearchProvider(fake_client).find_netblocks("Google")
        assert outcome.netblocks == []
        assert outcome.completed is True
        assert outcome.blocked is False
        assert fake_client.calls == []


# -- Google parsing ---------------------------------------------------------


class TestGoogleParsing:
    def test_extracts_cidrs_from_results(self, make_client):
        client = make_client({"/search": html_response(GOOGLE_RESULTS_HTML)})
        outcome = GoogleSearchProvider(client).find_netblocks("Google", max_pages=1)
        cidrs = {n.cidr for n in outcome.netblocks}
        assert "8.8.8.0/24" in cidrs
        assert "8.8.4.0/24" in cidrs
        assert "2001:4860::/32" in cidrs

    def test_results_marked_as_search_type(self, make_client):
        client = make_client({"/search": html_response(GOOGLE_RESULTS_HTML)})
        outcome = GoogleSearchProvider(client).find_netblocks("Google", max_pages=1)
        assert all(n.object_type is ObjectType.SEARCH for n in outcome.netblocks)

    def test_unrelated_results_ignored(self, make_client):
        client = make_client({"/search": html_response(GOOGLE_RESULTS_HTML)})
        outcome = GoogleSearchProvider(client).find_netblocks("Google", max_pages=1)
        assert all("ipinfo.io" in n.source_url for n in outcome.netblocks)

    def test_no_results_page(self, make_client):
        client = make_client({"/search": html_response(GOOGLE_NO_RESULTS_HTML)})
        outcome = GoogleSearchProvider(client).find_netblocks("Nothing", max_pages=3)
        assert outcome.netblocks == []
        assert outcome.completed is True
        assert outcome.blocked is False

    def test_malformed_html_does_not_raise(self, make_client):
        client = make_client({"/search": html_response("<html><a href=<<>")})
        outcome = GoogleSearchProvider(client).find_netblocks("Google", max_pages=1)
        assert outcome.completed is True

    def test_private_space_filtered_out(self, make_client):
        body = ('<a href="https://ipinfo.io/x">10.0.0.0/8 Netblock Details - '
                'Acme</a>')
        client = make_client({"/search": html_response(body)})
        outcome = GoogleSearchProvider(client).find_netblocks("Acme", max_pages=1)
        assert outcome.netblocks == []


class TestGoogleBlocking:
    def test_captcha_detected_and_reported(self, make_client):
        client = make_client({"/search": html_response(GOOGLE_CAPTCHA_HTML)})
        outcome = GoogleSearchProvider(client).find_netblocks("Google", max_pages=5)
        assert outcome.blocked is True
        assert outcome.completed is True
        assert any("CAPTCHA" in d for d in outcome.diagnostics)

    def test_captcha_stops_immediately(self, make_client):
        # Must not keep hammering after being blocked.
        client = make_client({"/search": html_response(GOOGLE_CAPTCHA_HTML)})
        GoogleSearchProvider(client).find_netblocks("Google", max_pages=10)
        assert client.call_count("/search") == 1

    def test_sorry_redirect_detected(self, make_client):
        response = html_response("<html>anything</html>",
                                 url="https://www.google.com/sorry/index?continue=x")
        client = make_client({"/search": response})
        outcome = GoogleSearchProvider(client).find_netblocks("Google", max_pages=1)
        assert outcome.blocked is True

    @pytest.mark.parametrize("status", [429, 503])
    def test_rate_limit_status_stops_cleanly(self, make_client, status):
        client = make_client({"/search": html_response("", status=status)})
        outcome = GoogleSearchProvider(client).find_netblocks("Google", max_pages=5)
        assert outcome.blocked is True
        assert client.call_count("/search") == 1

    def test_network_error_is_not_fatal(self, make_client):
        client = make_client({"/search": HttpError("connection reset")})
        outcome = GoogleSearchProvider(client).find_netblocks("Google", max_pages=3)
        assert outcome.completed is True
        assert outcome.netblocks == []
        assert outcome.diagnostics

    def test_page_count_is_bounded(self, make_client):
        # Even if every page returns results, max_pages caps the requests.
        client = make_client({"/search": html_response(GOOGLE_RESULTS_HTML)})
        provider = GoogleSearchProvider(client)
        provider.find_netblocks("Google", max_pages=2)
        assert client.call_count("/search") <= 2

    def test_max_pages_hard_ceiling(self, make_client):
        client = make_client({"/search": html_response(GOOGLE_RESULTS_HTML)})
        GoogleSearchProvider(client).find_netblocks("Google", max_pages=999)
        assert client.call_count("/search") <= 30


class TestGoogleHelpers:
    @pytest.mark.parametrize("body,url,expected", [
        (GOOGLE_CAPTCHA_HTML, "https://www.google.com/search", True),
        ("<html>normal results</html>", "https://www.google.com/search", False),
        ("<html>x</html>", "https://www.google.com/sorry/index", True),
        ("please solve this reCAPTCHA", "https://www.google.com/search", True),
    ])
    def test_is_blocked(self, body, url, expected):
        assert _is_blocked(body, url) is expected

    def test_resolve_href_unwraps_redirector(self):
        assert _resolve_href("/url?q=https://ipinfo.io/AS15169&sa=U") == \
            "https://ipinfo.io/AS15169"

    def test_resolve_href_passes_through_absolute(self):
        assert _resolve_href("https://ipinfo.io/x") == "https://ipinfo.io/x"

    @pytest.mark.parametrize("href", [
        "/search?q=x", "javascript:alert(1)", "", "#anchor", "ftp://host/file",
    ])
    def test_resolve_href_rejects_non_http(self, href):
        assert _resolve_href(href) == ""

    def test_result_name_extraction(self):
        assert _result_name("8.8.8.0/24 Netblock Details - Google LLC") == "Google LLC"
        assert _result_name("no marker here") == ""


# -- HTTP client safety -----------------------------------------------------


class TestUrlValidation:
    @pytest.mark.parametrize("url", [
        "https://whois.arin.net/rest/org/GOGL",
        "http://example.com/path",
    ])
    def test_accepts_http_urls(self, url):
        assert validate_url(url) == url

    @pytest.mark.parametrize("url", [
        "file:///etc/passwd",
        "ftp://host/file",
        "gopher://host",
        "javascript:alert(1)",
        "data:text/html,<script>",
        "https://",
    ])
    def test_rejects_dangerous_schemes(self, url):
        # External data can contain arbitrary URLs; we never fetch these.
        with pytest.raises(HttpError):
            validate_url(url)


class TestResponse:
    def test_json_parsing(self):
        response = Response(url="u", status_code=200, text='{"a": 1}',
                            content=b'{"a": 1}', headers={})
        assert response.json() == {"a": 1}
        assert response.ok is True

    def test_malformed_json_raises_http_error(self):
        response = Response(url="u", status_code=200, text="not json",
                            content=b"not json", headers={})
        with pytest.raises(HttpError):
            response.json()

    @pytest.mark.parametrize("status,ok", [
        (200, True), (204, True), (301, False), (404, False), (500, False),
    ])
    def test_ok_property(self, status, ok):
        assert Response(url="u", status_code=status, text="", content=b"",
                        headers={}).ok is ok


class TestSearchOutcome:
    def test_notes_accumulate(self):
        outcome = SearchOutcome(provider="test")
        outcome.note("first")
        outcome.note("second")
        assert outcome.diagnostics == ["first", "second"]

    def test_blocked_error_is_an_http_error(self):
        assert issubclass(BlockedError, HttpError)
