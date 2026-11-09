"""Company-name normalisation.

Registry and filing data spell the same company a dozen different ways:
``Google LLC``, ``GOOGLE-INC``, ``Google, Inc.``, ``GOOGLE INC-040731031303``.
Normalising before comparison is what makes confidence scoring meaningful.
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

#: Legal-entity suffixes stripped during normalisation. Kept from the original
#: tool and extended; order matters only in that longer forms are tried first.
LEGAL_SUFFIXES: frozenset[str] = frozenset({
    "ab", "ag", "aeie", "aps", "as", "bhd", "bv", "bvba", "co", "companies",
    "company", "corp", "corporation", "cust", "cv", "dba", "dwc-llc", "fzco",
    "gk", "gmbh", "group", "holding", "holdings", "inc", "incorporated", "jv",
    "kft", "kk", "lda", "limitada", "limited", "llc", "llp", "lllp", "lp",
    "ltd", "ltda", "nv", "oy", "oyj", "pc", "plc", "pllc", "private", "pte",
    "pty", "s de rl de cv", "sa", "sa de cv", "sarl", "sas", "scs", "sdn bhd",
    "sl", "sl unipersonal", "snc", "sp z oo", "sp zoo", "spa", "srl", "sro",
    "ua", "ulc", "sàrl", "sà rl", "-cust",
    # Additional legal-entity forms observed in live RIPE/APNIC records.
    # Strictly legal suffixes only: descriptive words such as "Technologies"
    # or "Services" are NOT stripped, because "Acme Technologies" is a
    # different company from "Acme" and collapsing them invents matches.
    "pvt", "pvt ltd", "private limited", "pte ltd", "pty ltd", "co ltd",
    "kg", "ohg", "ev", "asa", "doo", "dd", "zrt", "nyrt", "ky", "eurl",
    "sasu", "sca", "sce", "unlimited",
})

#: Suffixes stripped only when they trail the name, used for scoring variants.
_SUFFIX_PATTERN = re.compile(
    r"[\s,.\-]+(?:" + "|".join(sorted((re.escape(s) for s in LEGAL_SUFFIXES),
                                      key=len, reverse=True)) + r")\.?$",
    re.IGNORECASE,
)

#: States, provinces and countries. Used to recognise the "jurisdiction"
#: column of an EX-21 subsidiary table so it is not mistaken for a company.
JURISDICTIONS: frozenset[str] = frozenset({
    "afghanistan", "ak", "al", "alabama", "alaska", "albania", "alberta",
    "algeria", "american samoa", "andorra", "angola", "antigua & deps", "ar",
    "argentina", "arizona", "arkansas", "armenia", "as", "australia",
    "austria", "az", "azerbaijan", "bahamas", "bahrain", "bangladesh",
    "barbados", "belarus", "belgium", "belize", "benin", "bermuda", "bhutan",
    "bolivia", "bosnia & herzogovina", "bosnia and herzogovina",
    "bosnia herzegovina", "botswana", "brazil", "british columbia",
    "british virgin islands", "brunei", "bulgaria", "burkina", "burma",
    "burundi", "ca", "california", "cambodia", "cameroon", "canada",
    "cape verde", "cayman islands", "central african rep", "chad", "chile",
    "china", "co", "colombia", "colorado", "comoros", "congo", "connecticut",
    "costa rica", "croatia", "ct", "cuba", "cyprus", "czech republic", "dc",
    "de", "delaware", "delaware usa", "democratic republic of the congo",
    "denmark", "district of columbia", "djibouti", "dominica",
    "dominican republic", "east timor", "ecuador", "egypt", "el salvador",
    "england", "england and wales", "equatorial guinea", "eritrea", "espana",
    "estonia", "ethiopia", "federated states of micronesia", "fiji",
    "finland", "fl", "florida", "fm", "france", "ga", "gabon", "gambia",
    "georgia", "germany", "ghana", "greece", "grenada", "gu", "guam",
    "guatemala", "guinea", "guinea-bissau", "guyana", "haiti", "hawaii", "hi",
    "honduras", "hong kong", "hungary", "ia", "iceland", "id", "idaho", "il",
    "illinois", "in", "india", "indiana", "indonesia", "iowa", "iran", "iraq",
    "ireland", "isle of man", "israel", "italy", "ivory coast", "jamaica",
    "japan", "jordan", "kansas", "kazakhstan", "kentucky", "kenya",
    "kiribati", "korea", "korea north", "korea republic of", "korea south",
    "kosovo", "ks", "kuwait", "ky", "kyrgyzstan", "la", "laos", "latvia",
    "lebanon", "lesotho", "liberia", "libya", "liechtenstein", "lithuania",
    "louisiana", "luxembourg", "ma", "macedonia", "madagascar", "maine",
    "malawi", "malaysia", "maldives", "mali", "malta", "manitoba",
    "marshall islands", "maryland", "massachusetts", "mauritania",
    "mauritius", "md", "me", "mexico", "mh", "mi", "michigan", "micronesia",
    "minnesota", "mississippi", "missouri", "mn", "mo", "moldova", "monaco",
    "mongolia", "montana", "montenegro", "morocco", "mozambique", "mp", "ms",
    "mt", "myanmar", "méxico", "namibia", "nauru", "nc", "nd", "ne",
    "nebraska", "nederland", "nepal", "netherlands", "nevada",
    "new brunswick", "new hampshire", "new jersey", "new mexico", "new york",
    "new zealand", "newfoundland and labrador", "nh", "nicaragua", "niger",
    "nigeria", "nj", "nm", "north carolina", "north dakota", "north ireland",
    "northern mariana islands", "norway", "nova scotia", "nv", "ny", "of",
    "oh", "ohio", "ok", "oklahoma", "oman", "ontario", "or", "oregon", "pa",
    "pakistan", "palau", "panama", "papua new guinea", "paraguay",
    "pennsylvania", "people's republic of china", "peru", "philippines",
    "poland", "portugal", "pr", "prince edward island", "puerto rico", "pw",
    "qatar", "quebec", "republic of ireland", "republic of korea",
    "rhode island", "ri", "romania", "russia", "russia/kazakhstan",
    "russian federation", "rwanda", "saint vincent & the grenadines", "samoa",
    "san marino", "sao tome & principe", "saskatchewan", "saudi arabia", "sc",
    "sd", "senegal", "serbia", "serbia & montenegro", "serbia and montenegro",
    "seychelles", "sierra leone", "singapore", "slovakia", "slovenia",
    "solomon islands", "somalia", "south africa", "south carolina",
    "south dakota", "south korea", "south sudan", "spain", "sri lanka",
    "st kitts & nevis", "st lucia", "sudan", "suriname", "swaziland",
    "sweden", "switzerland", "syria", "taiwan", "taiwan province of china",
    "tajikistan", "tanzania", "tennessee", "texas", "thailand",
    "the bahamas & eleuthera island", "the netherlands", "tn", "togo",
    "tonga", "trinidad & tobago", "tunisia", "turkey", "turkmenistan",
    "tuvalu", "tx", "uganda", "uk", "ukraine", "united arab emirates",
    "united kingdom", "united states",
    "usaunited kingdom & northern ireland", "ut", "utah", "uzbekistan", "va",
    "vanuatu", "vatican city", "venezuela", "vermont", "vietnam",
    "virgin islands", "virginia", "vt", "wa", "washington", "west virginia",
    "wi", "wisconsin", "wv", "wy", "wyoming", "yemen", "zambia", "zimbabwe",
})

#: Trailing ARIN-style numeric discriminators, e.g. "GOOGLE INC-040731031303".
_ARIN_DISCRIMINATOR = re.compile(r"[-\s]+\d{4,}$")

#: Collapse runs of any non-alphanumeric characters.
_SEPARATORS = re.compile(r"[^0-9a-z]+")

#: Joins dotted initialisms so "S.A." becomes "sa" and can be matched as a
#: legal suffix. Applied repeatedly to handle "S.p.A." and similar.
_DOTTED_INITIALS = re.compile(r"(?<=\b[a-z])\.\s?(?=[a-z]\b|[a-z]\.)")


def strip_accents(text: str) -> str:
    """Fold accented characters to ASCII so ``Nestlé`` matches ``Nestle``."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


@lru_cache(maxsize=4096)
def normalize_company_name(name: str | None) -> str:
    """Reduce a company name to a comparable canonical form.

    ``"GOOGLE INC-040731031303"`` and ``"Google, Inc."`` both become ``"google"``.
    Returns an empty string for unusable input.
    """
    if not name:
        return ""
    text = strip_accents(str(name)).lower().strip()
    text = _ARIN_DISCRIMINATOR.sub("", text)
    text = text.replace("&", " and ")
    previous_dots = None
    while previous_dots != text:
        previous_dots = text
        text = _DOTTED_INITIALS.sub("", text)
    # Repeatedly strip trailing legal suffixes: "Foo Holdings Inc" -> "foo".
    previous = None
    while previous != text:
        previous = text
        text = _SUFFIX_PATTERN.sub("", text).strip()
        if text.startswith("the "):
            text = text[4:].strip()
    text = _SEPARATORS.sub(" ", text).strip()
    return text


@lru_cache(maxsize=4096)
def name_key(name: str | None) -> str:
    """An aggressive key with all separators removed, for near-match testing."""
    return normalize_company_name(name).replace(" ", "")


def name_variants(name: str) -> frozenset[str]:
    """Return the canonical name plus every ``name + legal suffix`` variant."""
    base = normalize_company_name(name)
    if not base:
        return frozenset()
    variants = {base}
    for suffix in LEGAL_SUFFIXES:
        variants.add(f"{base} {suffix}")
    return frozenset(variants)


def is_jurisdiction(text: str | None) -> bool:
    """True when the string is only a state/province/country name."""
    if not text:
        return False
    cleaned = strip_accents(str(text)).lower().strip().strip(".,;:")
    if cleaned in JURISDICTIONS:
        return True
    squashed = _SEPARATORS.sub("", cleaned)
    return any(_SEPARATORS.sub("", j) == squashed for j in JURISDICTIONS)


def strip_legal_suffix(name: str) -> str:
    """Remove trailing legal suffixes but preserve original casing/spacing."""
    if not name:
        return ""
    text = str(name).strip()
    previous = None
    while previous != text:
        previous = text
        text = _SUFFIX_PATTERN.sub("", text).strip().rstrip(",.")
    return text


def dedupe_names(names) -> list[str]:
    """Deduplicate company names case- and suffix-insensitively.

    Keeps the first spelling encountered for each distinct company and returns
    the result sorted, so ``["Google LLC", "GOOGLE INC", "YouTube"]`` collapses
    to ``["Google LLC", "YouTube"]``.
    """
    seen: dict[str, str] = {}
    for name in names:
        if not name or not str(name).strip():
            continue
        key = name_key(name)
        if not key:
            continue
        if key not in seen:
            seen[key] = str(name).strip()
    return sorted(seen.values(), key=str.lower)
