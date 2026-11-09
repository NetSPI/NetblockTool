"""Output serialisation, escaping and filename safety."""

from __future__ import annotations

import csv
import json

import pytest

from netblocktool.models import Confidence, Contact, Evidence, Netblock, ObjectType, Subsidiary
from netblocktool.output import (
    CSV_HEADERS,
    LEGACY_CSV_HEADERS,
    escape_csv_value,
    resolve_output_path,
    sanitize_filename,
    summarize,
    write_contacts,
    write_csv,
    write_json,
    write_subsidiaries,
)


@pytest.fixture
def sample_netblocks() -> list[Netblock]:
    return [
        Netblock(
            cidr="8.8.8.0/24", name="GOOGLE-CLOUD", handle="NET-8-8-8-0-1",
            object_type=ObjectType.NETWORK, registry="arin", company="Google",
            organization="Google LLC", ip_version=4, score=85,
            confidence=Confidence.CONFIRMED, address="1600 Amphitheatre Parkway",
            country="United States", city="Mountain View", state="CA",
            source_url="https://whois.arin.net/rest/net/NET-8-8-8-0-1",
            evidence=[Evidence("NAME_EXACT", 35, "matches")],
        ),
        Netblock(
            cidr="2001:4860::/32", name="GOOGLE-IPV6", handle="NET6-1",
            object_type=ObjectType.NETWORK, registry="arin", company="Google",
            subsidiary="YouTube", ip_version=6, score=60,
            confidence=Confidence.PROBABLE,
        ),
    ]


class TestSanitizeFilename:
    @pytest.mark.parametrize("raw,expected", [
        ("Google", "Google"),
        ("../../etc/passwd", "passwd"),
        ("..\\..\\windows\\system32", "system32"),
        ("my company", "my_company"),
        ("a/b/c", "c"),
        ("....", "netblocktool"),
        ("", "netblocktool"),
        ("  spaced  ", "spaced"),
    ])
    def test_sanitisation(self, raw, expected):
        assert sanitize_filename(raw) == expected

    def test_never_contains_separators(self):
        for raw in ["../../../etc/shadow", "a/b", "a\\b", "/absolute/path"]:
            result = sanitize_filename(raw)
            assert "/" not in result and "\\" not in result
            assert ".." not in result

    def test_windows_reserved_names_are_prefixed(self):
        assert sanitize_filename("CON").startswith("_")
        assert sanitize_filename("nul").startswith("_")

    def test_length_is_bounded(self):
        assert len(sanitize_filename("A" * 500)) <= 120

    def test_path_traversal_cannot_escape_directory(self, tmp_path):
        # The historical bug: -o ../../etc/cron.d/x wrote outside the cwd.
        resolved = resolve_output_path("../../etc/evil", ".csv", tmp_path)
        assert resolved.parent == tmp_path.resolve()
        assert resolved.name == "evil.csv"


class TestCsvInjection:
    @pytest.mark.parametrize("payload", [
        "=cmd|'/c calc'!A1",
        "+1+1",
        "-2+3",
        "@SUM(1+1)",
        "=HYPERLINK(\"http://evil\",\"click\")",
        "\tleading tab",
        "\rcarriage return",
    ])
    def test_dangerous_prefixes_are_neutralised(self, payload):
        assert escape_csv_value(payload).startswith("'")

    @pytest.mark.parametrize("value", [
        "Google LLC", "8.8.8.0/24", "United States", "NET-8-8-8-0-1", "85",
    ])
    def test_safe_values_untouched(self, value):
        assert escape_csv_value(value) == value

    def test_none_becomes_empty(self):
        assert escape_csv_value(None) == ""

    def test_injection_survives_round_trip(self, tmp_path):
        # An ARIN customer object can legitimately be named anything.
        malicious = Netblock(cidr="8.8.8.0/24", name="=cmd|'/c calc'!A1",
                             company="=1+1", ip_version=4)
        path = tmp_path / "out.csv"
        write_csv([malicious], path)
        rows = list(csv.reader(path.open(encoding="utf-8")))
        assert rows[1][0].startswith("'")
        assert not any(cell.startswith("=") for cell in rows[1])


class TestWriteCsv:
    def test_default_schema_headers(self, sample_netblocks, tmp_path):
        path = tmp_path / "out.csv"
        write_csv(sample_netblocks, path)
        rows = list(csv.reader(path.open(encoding="utf-8")))
        assert rows[0] == list(CSV_HEADERS)
        assert len(rows) == 3

    def test_required_fields_present(self, sample_netblocks, tmp_path):
        path = tmp_path / "out.csv"
        write_csv(sample_netblocks, path)
        header = next(iter(csv.reader(path.open(encoding="utf-8"))))
        for field in ("company", "subsidiary", "cidr", "ip_version", "registry",
                      "asn", "asn_holder", "organization", "confidence",
                      "confidence_score", "evidence", "source", "address",
                      "country", "city", "state", "poc", "discovered_at"):
            assert field in header

    def test_legacy_schema_preserved(self, sample_netblocks, tmp_path):
        path = tmp_path / "legacy.csv"
        write_csv(sample_netblocks, path, legacy=True)
        rows = list(csv.reader(path.open(encoding="utf-8")))
        assert rows[0] == list(LEGACY_CSV_HEADERS)
        assert rows[1][0] == "8.8.8.0/24"
        assert rows[1][1] == "GOOGLE-CLOUD"

    def test_legacy_optional_columns(self, sample_netblocks, tmp_path):
        path = tmp_path / "legacy2.csv"
        write_csv(sample_netblocks, path, legacy=True,
                  include_address=True, include_geolocation=True)
        header = next(iter(csv.reader(path.open(encoding="utf-8"))))
        assert header[-2:] == ["Registered Address", "Geolocation Information"]

    def test_values_with_commas_are_quoted(self, tmp_path):
        block = Netblock(cidr="8.8.8.0/24", address="123 Main St, Springfield, US",
                         ip_version=4)
        path = tmp_path / "q.csv"
        write_csv([block], path)
        rows = list(csv.reader(path.open(encoding="utf-8")))
        # Look the column up by name so adding a field cannot break this test.
        address_column = rows[0].index("address")
        assert rows[1][address_column] == "123 Main St, Springfield, US"

    def test_empty_list_writes_header_only(self, tmp_path):
        path = tmp_path / "empty.csv"
        write_csv([], path)
        rows = list(csv.reader(path.open(encoding="utf-8")))
        assert len(rows) == 1

    def test_creates_missing_directory(self, tmp_path):
        path = tmp_path / "nested" / "deep" / "out.csv"
        write_csv([], path)
        assert path.exists()


class TestWriteJson:
    def test_structure(self, sample_netblocks, tmp_path):
        path = tmp_path / "out.json"
        write_json(sample_netblocks, path, metadata={"target": "Google"})
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["count"] == 2
        assert payload["metadata"]["target"] == "Google"
        assert len(payload["netblocks"]) == 2

    def test_evidence_is_structured(self, sample_netblocks, tmp_path):
        path = tmp_path / "out.json"
        write_json(sample_netblocks, path)
        first = json.loads(path.read_text(encoding="utf-8"))["netblocks"][0]
        assert first["evidence"][0]["code"] == "NAME_EXACT"
        assert first["evidence"][0]["points"] == 35

    def test_is_valid_json_with_unicode(self, tmp_path):
        block = Netblock(cidr="8.8.8.0/24", name="Nestlé S.A.", ip_version=4)
        path = tmp_path / "u.json"
        write_json([block], path)
        assert json.loads(path.read_text(encoding="utf-8"))["netblocks"][0]["name"] \
            == "Nestlé S.A."


class TestWriteContactsAndSubsidiaries:
    def test_contacts_written(self, tmp_path):
        contacts = [Contact(name="Jane Doe", company="Google LLC",
                            emails="noc@example.com")]
        path = write_contacts(contacts, tmp_path / "c.csv")
        assert path is not None
        rows = list(csv.reader(path.open(encoding="utf-8")))
        assert rows[1][0] == "Jane Doe"

    def test_no_contacts_writes_nothing(self, tmp_path):
        assert write_contacts([], tmp_path / "c.csv") is None
        assert not (tmp_path / "c.csv").exists()

    def test_contacts_escape_injection(self, tmp_path):
        path = write_contacts([Contact(name="=EVIL()")], tmp_path / "c.csv")
        rows = list(csv.reader(path.open(encoding="utf-8")))
        assert rows[1][0].startswith("'")

    def test_subsidiaries_written_one_per_line(self, tmp_path):
        subs = [Subsidiary(name="YouTube, LLC", parent="Alphabet"),
                Subsidiary(name="Fitbit LLC", parent="Alphabet")]
        path = write_subsidiaries(subs, tmp_path / "s.txt")
        assert path.read_text(encoding="utf-8").splitlines() == \
            ["YouTube, LLC", "Fitbit LLC"]

    def test_no_subsidiaries_writes_nothing(self, tmp_path):
        assert write_subsidiaries([], tmp_path / "s.txt") is None


class TestSummarize:
    def test_counts_by_band_and_version(self, sample_netblocks):
        counts = summarize(sample_netblocks)
        assert counts["total"] == 2
        assert counts["confirmed"] == 1
        assert counts["probable"] == 1
        assert counts["ipv4_blocks"] == 1
        assert counts["ipv6_blocks"] == 1

    def test_address_counts_do_not_double_count(self):
        blocks = [
            Netblock(cidr="8.8.8.0/24", ip_version=4, score=90),
            Netblock(cidr="8.8.8.0/25", ip_version=4, score=80),
        ]
        assert summarize(blocks)["ipv4_addresses"] == 256

    def test_empty(self):
        counts = summarize([])
        assert counts["total"] == 0
        assert counts["ipv4_addresses"] == 0


class TestSummaryReconciles:
    """The source breakdown must account for every reported netblock.

    Regression: the summary listed network/customer/contact records but not
    ASN-derived ones, and printed distinct AS numbers under a heading that
    looked like a row count. On a real run 16 of 76 rows were unaccounted for.
    """

    def test_type_counts_sum_to_total(self):
        blocks = [
            Netblock(cidr="8.8.8.0/24", object_type=ObjectType.NETWORK),
            Netblock(cidr="8.8.4.0/24", object_type=ObjectType.CUSTOMER),
            Netblock(cidr="1.1.1.0/24", object_type=ObjectType.CONTACT),
            Netblock(cidr="2.2.2.0/24", object_type=ObjectType.ASN, asn="AS15169"),
            Netblock(cidr="3.3.3.0/24", object_type=ObjectType.SEARCH),
            Netblock(cidr="4.4.4.0/24", object_type=ObjectType.ORG),
        ]
        counts = summarize(blocks)
        breakdown = (counts["network"] + counts["customer"] + counts["contact"]
                     + counts["asn_records"] + counts["search"]
                     + counts["org_records"])
        assert breakdown == counts["total"] == 6

    def test_asn_records_distinct_from_asn_count(self):
        # Three netblocks, all announced by one AS: 3 rows, 1 ASN.
        blocks = [
            Netblock(cidr=f"8.8.{i}.0/24", object_type=ObjectType.ASN,
                     asn="AS15169")
            for i in range(3)
        ]
        counts = summarize(blocks)
        assert counts["asn_records"] == 3
        assert counts["asn"] == 1

    def test_empty_breakdown(self):
        counts = summarize([])
        assert counts["asn_records"] == 0
        assert counts["org_records"] == 0
