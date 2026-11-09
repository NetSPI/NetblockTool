"""Command-line interface.

Every flag from NetblockTool 2.x is preserved. New options are added alongside
them, and ``-h``/``--help`` now actually works (the old parser used
``add_help=False`` without defining a replacement, so ``-h`` produced
"the following arguments are required: target").
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import Config
from .logging_setup import configure, get_logger
from .models import Netblock
from .output import (
    resolve_output_path,
    sanitize_filename,
    summarize,
    write_contacts,
    write_csv,
    write_json,
    write_subsidiaries,
)
from .pipeline import Pipeline, RunOptions, RunResult
from .registries.rdap import RDAP_ENDPOINTS
from .search import available_providers

log = get_logger("cli")

BANNER = r"""  _   _      _   _     _            _    _____           _
 | \ | | ___| |_| |__ | | ___   ___| | _|_   _|__   ___ | |
 |  \| |/ _ \ __| '_ \| |/ _ \ / __| |/ / | |/ _ \ / _ \| |
 | |\  |  __/ |_| |_) | | (_) | (__|   <  | | (_) | (_) | |
 |_| \_|\___|\__|_.__/|_|\___/ \___|_|\_\ |_|\___/ \___/|_|
"""

EPILOG = """\
examples:
  NetblockTool.py Google
  NetblockTool.py -v Google
  NetblockTool.py -v -s Google
  NetblockTool.py -v -p Google
  NetblockTool.py -wpgav Facebook -so -o Results
  NetblockTool.py -gavl companies.txt
  NetblockTool.py -v -4 --json -o Results Google

All data gathering is passive. This tool never sends traffic to the target's
hosts; it only reads public registry, filing and search data.
"""


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="NetblockTool.py",
        description="Find public netblocks owned by a company and its subsidiaries.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?",
                        help='target company (exclude "Inc", "Corp", etc.), or a '
                             "file of company names when -l is used")
    parser.add_argument("--version", action="version",
                        version=f"NetblockTool {__version__}")

    common = parser.add_argument_group("common options")
    common.add_argument("-l", "--list", action="store_true",
                        help="list mode; target is a file with one company per line")
    common.add_argument("-o", "--output",
                        help="output file name (no extension; default is the target name)")
    common.add_argument("--output-dir", type=Path,
                        help="directory to write output files to (default: cwd)")
    verbosity = common.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", action="store_true",
                           help="verbose/debug logging")
    verbosity.add_argument("-q", "--quiet", action="store_true",
                           help="quiet mode; warnings and errors only")

    retrieval = parser.add_argument_group("data retrieval & processing")
    wildcard = retrieval.add_mutually_exclusive_group()
    wildcard.add_argument("-n", "--no-wildcard", action="store_true",
                          help="exact query (query = target)")
    wildcard.add_argument("-w", "--wildcard", action="store_true",
                          help="full wildcard query (query = *target*); many more "
                               "false positives")
    retrieval.add_argument("-ng", "--no-google", action="store_true",
                           help="skip search-engine discovery entirely")
    retrieval.add_argument("-c", "--company-name",
                           help="company name if different from the target; affects "
                                "confidence scoring")
    retrieval.add_argument("-e", "--threshold", type=int, metavar="SCORE",
                           help="only return results with a confidence score >= SCORE")
    retrieval.add_argument("-p", "--poc-out", action="store_true",
                           help="retrieve and write point-of-contact information")
    version_group = retrieval.add_mutually_exclusive_group()
    version_group.add_argument("-4", "--ipv4", action="store_true",
                               help="only return IPv4 netblocks")
    version_group.add_argument("-6", "--ipv6", action="store_true",
                               help="only return IPv6 netblocks")
    retrieval.add_argument("--no-subsumed", action="store_true",
                           help="omit networks fully contained inside another "
                                "reported network")
    retrieval.add_argument("--no-asn-expansion", action="store_true",
                           help="do not expand ASNs into their announced prefixes")
    retrieval.add_argument("--registries", metavar="LIST",
                           default="arin,ripe,apnic,afrinic,lacnic",
                           help="comma-separated registries to query "
                                f"(available: {', '.join(sorted(RDAP_ENDPOINTS))})")
    retrieval.add_argument("--search-provider", metavar="NAME", default="google",
                           choices=list(available_providers()),
                           help="passive search provider "
                                f"(choices: {', '.join(available_providers())})")

    subsidiary = parser.add_argument_group("company subsidiaries")
    subsidiary.add_argument("-s", "--subsidiary", action="store_true",
                            help="discover subsidiaries via SEC EDGAR and include "
                                 "their netblocks")
    subsidiary.add_argument("-sn", "--subsidiary-name",
                            help="company name to use when fetching subsidiaries")
    subsidiary.add_argument("-sp", "--subsidiary-parse-alt", action="store_true",
                            help="alternate Exhibit 21 parsing (deprecated; the "
                                 "current parser tries every strategy automatically)")
    subsidiary.add_argument("-so", "--subsidiary-out", action="store_true",
                            help="write subsidiary names to Company_subsidiaries.txt")
    subsidiary.add_argument("-u", "--user-agent",
                            help="identification string sent to the SEC and other "
                                 "sources; see https://www.sec.gov/os/accessing-edgar-data")

    location = parser.add_argument_group("physical location")
    location.add_argument("-g", "--geolocation", action="store_true",
                          help="retrieve geolocation data where available")
    location.add_argument("-a", "--address-out", action="store_true",
                          help="include registered address information in the output")
    location.add_argument("-ag", "--address-grep", metavar="TEXT",
                          help="only return netblocks whose address contains TEXT")

    output = parser.add_argument_group("output format")
    output.add_argument("--json", action="store_true",
                        help="also write machine-readable JSON output")
    output.add_argument("--json-only", action="store_true",
                        help="write only JSON, no CSV")
    output.add_argument("--legacy-csv", action="store_true",
                        help="use the NetblockTool 2.x CSV column layout")

    network = parser.add_argument_group("network behaviour")
    network.add_argument("--timeout", type=float, metavar="SECONDS",
                         help="per-request timeout (env: NETBLOCKTOOL_TIMEOUT)")
    network.add_argument("--workers", type=int, metavar="N",
                         help="maximum concurrent lookups (env: NETBLOCKTOOL_MAX_WORKERS)")
    network.add_argument("--retries", type=int, metavar="N",
                         help="retry attempts per request (env: NETBLOCKTOOL_MAX_RETRIES)")
    network.add_argument("--rate-limit", type=float, metavar="RPS",
                         help="requests per second per host (env: NETBLOCKTOOL_RATE_LIMIT)")
    network.add_argument("--max-objects", type=int, metavar="N",
                         help="cap on registry objects expanded per company")

    return parser


def config_from_args(args: argparse.Namespace) -> Config:
    """Build a :class:`Config` from parsed arguments and the environment."""
    config = Config()
    if args.user_agent:
        config.user_agent = str(args.user_agent)
    if args.timeout is not None:
        config.timeout = args.timeout
    if args.workers is not None:
        config.max_workers = args.workers
    if args.retries is not None:
        config.max_retries = args.retries
    if args.rate_limit is not None:
        config.rate_limit = args.rate_limit
    if args.max_objects is not None:
        config.max_objects = args.max_objects

    config.registries = tuple(
        part.strip().lower() for part in str(args.registries).split(",") if part.strip()
    )
    config.search_provider = "none" if args.no_google else args.search_provider
    if args.ipv4:
        config.ip_version = 4
    elif args.ipv6:
        config.ip_version = 6

    config.__post_init__()
    return config


def options_from_args(args: argparse.Namespace, target: str) -> RunOptions:
    """Build per-run options for one target company."""
    if args.no_wildcard:
        mode = "exact"
    elif args.wildcard:
        mode = "full"
    else:
        mode = "prefix"

    address_grep = (args.address_grep or "").strip().lower()
    return RunOptions(
        target=target,
        company_name=args.company_name,
        query_mode=mode,
        with_subsidiaries=bool(args.subsidiary),
        subsidiary_name=args.subsidiary_name,
        fetch_pocs=bool(args.poc_out),
        geolocation=bool(args.geolocation),
        threshold=args.threshold,
        address_grep=address_grep,
        include_address=bool(args.address_out) or bool(address_grep),
        exclude_subsumed=bool(args.no_subsumed),
        expand_asns=not args.no_asn_expansion,
    )


def validate(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Reject argument combinations that cannot work."""
    if not args.target:
        parser.error("a target company (or, with -l, a file of company names) is required")

    if args.subsidiary_parse_alt and not args.subsidiary:
        args.subsidiary = True
    if args.subsidiary_out and not args.subsidiary:
        args.subsidiary = True
    if args.subsidiary_name and not args.subsidiary:
        args.subsidiary = True

    if args.list and args.subsidiary_name:
        parser.error("cannot use a custom subsidiary name (-sn) with list mode (-l)")
    if args.list and args.company_name:
        parser.error("cannot use a custom company name (-c) with list mode (-l)")
    if args.threshold is not None and not 0 <= args.threshold <= 99:
        parser.error("confidence threshold (-e) must be between 0 and 99")
    if args.json_only:
        args.json = True
    if args.subsidiary_parse_alt:
        log.warning("-sp is deprecated: the Exhibit 21 parser now tries table "
                    "extraction and text extraction automatically")

    unknown = set(args.registries.split(",")) - set(RDAP_ENDPOINTS) - {""}
    unknown = {u.strip().lower() for u in unknown if u.strip()} - set(RDAP_ENDPOINTS)
    if unknown:
        parser.error(f"unknown registr{'y' if len(unknown) == 1 else 'ies'}: "
                     f"{', '.join(sorted(unknown))}")


def read_company_list(path: str) -> list[str]:
    """Read a newline-delimited company list."""
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise SystemExit(f"[ERROR] Could not read company list {path!r}: {exc}") from exc
    companies = [line.strip() for line in text.splitlines() if line.strip()]
    if not companies:
        raise SystemExit(f"[ERROR] Company list {path!r} is empty")
    return companies


def write_results(result: RunResult, args: argparse.Namespace,
                  output_name: str) -> list[Path]:
    """Write all requested output files. Returns the paths written."""
    directory = args.output_dir
    written: list[Path] = []

    if not result.netblocks:
        log.warning("No netblocks to write for %r", result.target)
    else:
        if not args.json_only:
            csv_path = resolve_output_path(output_name, ".csv", directory)
            write_csv(
                result.netblocks, csv_path,
                legacy=args.legacy_csv,
                include_address=bool(args.address_out) or bool(args.address_grep),
                include_geolocation=bool(args.geolocation),
            )
            written.append(csv_path)
        if args.json:
            json_path = resolve_output_path(output_name, ".json", directory)
            write_json(result.netblocks, json_path, metadata={
                "tool": "NetblockTool",
                "version": __version__,
                "target": result.target,
                "search_provider": result.search_outcome.provider
                if result.search_outcome else None,
                "search_blocked": result.search_outcome.blocked
                if result.search_outcome else None,
                "errors": result.errors,
            })
            written.append(json_path)

    if args.poc_out:
        if result.contacts:
            contacts_path = resolve_output_path(
                f"{output_name}_contacts", ".csv", directory)
            if write_contacts(result.contacts, contacts_path):
                written.append(contacts_path)
        else:
            log.warning(
                "-p was requested but no point-of-contact records were "
                "retrieved; the registry may not publish contacts for this "
                "organisation, or the lookups failed (see errors above)"
            )

    if args.subsidiary_out:
        if result.subsidiaries:
            subs_path = resolve_output_path(
                f"{output_name}_subsidiaries", ".txt", directory)
            if write_subsidiaries(result.subsidiaries, subs_path):
                written.append(subs_path)
        else:
            log.warning("-so was requested but no subsidiaries were discovered")

    return written


def report_errors(errors: list[str]) -> None:
    """Log a consolidated view of everything that failed during the run.

    Individual failures are already logged where they happen, but by the end of
    a long run they have scrolled away. Repeating a de-duplicated summary makes
    silent degradation visible: if a run returns fewer results than expected,
    the reason is on screen rather than buried in the JSON.
    """
    if not errors:
        return
    counts: dict[str, int] = {}
    for message in errors:
        counts[message] = counts.get(message, 0) + 1
    log.warning("%d source error(s) occurred; results may be incomplete",
                len(errors))
    for message, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        suffix = f" (x{count})" if count > 1 else ""
        log.warning("  %s%s", message, suffix)


def print_summary(netblocks: list[Netblock], label: str, quiet: bool,
                  errors: list[str] | None = None) -> None:
    """Print the end-of-run statistics block."""
    if quiet:
        return
    counts = summarize(netblocks)
    lines = [
        "",
        f"[*] SUMMARY {label}",
        f"  [*] Unique netblocks: {counts['total']}",
        f"  [*] Confirmed:        {counts['confirmed']}",
        f"  [*] Probable:         {counts['probable']}",
        f"  [*] Weak:             {counts['weak']}",
        f"  [*] Unlikely:         {counts['unlikely']}",
        f"  [*] Contained in a larger block: {counts['subsumed']}",
        f"  [*] ASNs (company):   {counts['asn']}",
        f"  [*] ASNs (3rd party): {counts['asn_third_party']}",
        f"  [*] Network records:  {counts['network']}",
        f"  [*] Customer records: {counts['customer']}",
        f"  [*] Contact records:  {counts['contact']}",
        f"  [*] ASN-derived:      {counts['asn_records']}",
        f"  [*] Search results:   {counts['search']}",
        (f"  [*] IPv4 blocks:      {counts['ipv4_blocks']} "
         f"({counts['ipv4_addresses']} addresses)"),
        (f"  [*] IPv6 blocks:      {counts['ipv6_blocks']} "
         f"({counts['ipv6_addresses']} addresses)"),
    ]
    if errors:
        lines.append(f"  [!] Source errors:    {len(errors)} "
                     f"(results may be incomplete)")
    lines.append("")
    print("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    validate(args, parser)

    configure(verbose=args.verbose, quiet=args.quiet)

    if not args.quiet:
        print(BANNER)

    config = config_from_args(args)
    targets = read_company_list(args.target) if args.list else [args.target]

    pipeline = Pipeline(config)
    exit_code = 0
    try:
        combined: list[Netblock] = []
        all_errors: list[str] = []
        for index, target in enumerate(targets, start=1):
            if len(targets) > 1:
                log.info("Overall status: %d/%d - %s", index, len(targets), target)
            options = options_from_args(args, target)
            try:
                result = pipeline.run(options)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                log.error("Run failed for %r: %s", target, exc)
                if args.verbose:
                    log.debug("Traceback", exc_info=True)
                exit_code = 1
                continue

            base = args.output if (args.output and len(targets) == 1) else target
            if args.subsidiary:
                base = f"{sanitize_filename(base)}_subsidiaries" \
                    if not args.output else base
            write_results(result, args, base)
            combined.extend(result.netblocks)
            all_errors.extend(result.errors)
            report_errors(result.errors)

            if not result.netblocks:
                log.warning("No netblocks found for %r", target)
                exit_code = max(exit_code, 0)

        label = "FOR ALL SUBSIDIARIES" if args.subsidiary else ""
        print_summary(combined, label, args.quiet, all_errors)
    except KeyboardInterrupt:
        log.warning("Interrupt received; stopping")
        return 130
    finally:
        pipeline.close()

    return exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
