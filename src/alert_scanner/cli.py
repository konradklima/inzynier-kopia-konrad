"""Command line entry point.

    (ZAP report | live scan) -> zap_parser -> risk_rules -> SQLite -> terminal / HTML

Examples:
    alert-scanner --report reports/zap-full-juiceshop.json --show-filtered
    alert-scanner --scan http://host.docker.internal:3000 --html reports/live.html
    alert-scanner --history
    alert-scanner --load 3
"""

from __future__ import annotations
import argparse
import os
import sys
from datetime import datetime
from pathlib import Path
from alert_scanner import catalog
from alert_scanner.domain import Finding, Severity, Verdict
from alert_scanner.known_vulnerabilities import KNOWN_APPS, Coverage
from alert_scanner.report_html import write_html_report
from alert_scanner.risk_rules import Assessment, assess
from alert_scanner.scanner import ScanError, ScanMode, ScanScope, discover_subpages, run_zap_scan
from alert_scanner.storage import Storage
from alert_scanner.zap_parser import (
    ZapReportError,
    foreign_sites,
    guess_target,
    load_report,
    parse_report,
)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    console = Console()
    try:
        if args.history:
            return _show_history(args, console)
        if args.load is not None:
            return _show_saved_scan(args, console)
        return _analyze(args, console)
    except (ZapReportError, ScanError, FileNotFoundError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


def print_assessment(console: Console, target: str, assessment: Assessment, *,
                     show_filtered: bool, scope_note: str = "") -> None:
    breakdown = ", ".join(
        console.color(f"{count} {severity.label}", _SEVERITY_COLOR[severity])
        for severity, count in assessment.count_by_severity().items() if count
    )
    console.line()
    console.line(console.bold(f"Scan result for {target}"))
    console.line(f"  Issues to fix: {console.bold(str(len(assessment.real)))}"
                 + (f" ({breakdown})" if breakdown else ""))
    console.line(f"  Filtered out:  {assessment.filtered_out} of {assessment.total} scanner alerts "
                 f"({assessment.filtered_out_pct:.0f}%)")
    if scope_note:
        console.line(console.dim(f"  {scope_note}"))
    console.line()

    if assessment.real:
        console.line(console.bold("Issues to fix, most urgent first"))
        for finding in assessment.real:
            _print_finding(console, finding)
    else:
        console.line("No issues to fix.")

    if show_filtered and assessment.filtered_out:
        console.line()
        console.line(console.bold("Filtered out"))
        for finding in (*assessment.noise, *assessment.false_positives):
            console.line(console.dim(f"  {finding.verdict.label:<15} {finding.name} "
                                     f"({finding.severity.label} risk, "
                                     f"{finding.confidence.label} confidence)"))
    console.line()


def print_coverage(console: Console, coverage: Coverage) -> None:
    detectable, detected, out_of_reach = coverage.detectable, coverage.detected, coverage.out_of_reach
    console.line(console.bold("Compared with the known Juice Shop vulnerabilities"))
    console.line(console.dim(f"  source: {coverage.source}"))
    console.line(f"  Detected {len(detected)} of {len(detectable)} categories a scanner can find "
                 f"({coverage.challenges_in(detected)} of {coverage.challenges_in(detectable)} challenges)")
    for row in detectable:
        mark = console.color("[x]", "32") if row.detected else console.color("[ ]", "31")
        found_via = console.dim(f"  via {', '.join(row.detected_by)}") if row.detected else ""
        console.line(f"    {mark} {row.category.name} ({row.category.challenges}){found_via}")
    console.line(f"  Out of reach for automated scanning: {len(out_of_reach)} categories "
                 f"({coverage.challenges_in(out_of_reach)} challenges)")
    for row in out_of_reach:
        console.line(console.dim(
            f"        {row.category.name} ({row.category.challenges}): {row.category.why_not}"
        ))
    console.line()


class Console:
    """Print with ANSI colors; plain text when redirected or when NO_COLOR is set."""

    def __init__(self, stream=None) -> None:
        self.stream = stream or sys.stdout
        if hasattr(self.stream, "reconfigure") and not self.stream.isatty():
            self.stream.reconfigure(encoding="utf-8")
        self.use_colors = self.stream.isatty() and "NO_COLOR" not in os.environ
        if self.use_colors and os.name == "nt":
            _enable_windows_ansi()

    def line(self, text: str = "") -> None:
        print(text, file=self.stream)

    def color(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.use_colors else text

    def bold(self, text: str) -> str:
        return self.color(text, "1")

    def dim(self, text: str) -> str:
        return self.color(text, "2")


def _analyze(args: argparse.Namespace, console: Console) -> int:
    if args.scan:
        scope = _resolve_scope(args.scope, console)
        seed_urls: list[str] | None = None
        if scope is ScanScope.SITE:
            console.line(console.dim(f"Discovering subpages on {args.scan} ..."))
            seed_urls = discover_subpages(args.scan)
            console.line(console.dim(f"Found {len(seed_urls)} URL(s) to scan"))
        report_path = Path(args.save_report or _default_report_path(args.mode))
        console.line(console.dim(
            f"Running OWASP ZAP ({args.mode}, scope: {scope.value}) against {args.scan} ..."
        ))
        run_zap_scan(
            args.scan, report_path, ScanMode(args.mode),
            scope=scope, ajax=args.ajax, spider_minutes=args.spider_minutes,
            max_scan_minutes=args.max_minutes, seed_urls=seed_urls,
        )
        console.line(console.dim(f"Raw ZAP report saved to {report_path}"))
    else:
        report_path = Path(args.report)

    report = load_report(report_path)
    target = args.scan or args.target or guess_target(report)
    scope_note = _scope_note(foreign_sites(report, target))
    assessment = assess(parse_report(report, target))

    print_assessment(console, target, assessment, show_filtered=args.show_filtered,
                     scope_note=scope_note)
    if args.compare:
        print_coverage(console, KNOWN_APPS[args.compare](assessment))
    if not args.no_store:
        with Storage(args.db) as db:
            scan_id = db.save_scan(target, assessment.all_findings())
        console.line(console.dim(f"Saved as scan #{scan_id} in {args.db}"))
    if args.html:
        _write_html(console, args.html, target, assessment, report_path.name, scope_note)
    return 0


def _show_history(args: argparse.Namespace, console: Console) -> int:
    with Storage(args.db) as db:
        scans = db.list_scans()
    if not scans:
        console.line("No saved scans.")
        return 0
    console.line(console.bold("Saved scans"))
    for scan in scans:
        counts = console.dim(f"{scan.real_count} real of {scan.finding_count}")
        console.line(f"  #{scan.id:<4} {scan.created_at}  {scan.target}  {counts}")
    return 0


def _show_saved_scan(args: argparse.Namespace, console: Console) -> int:
    with Storage(args.db) as db:
        target = db.scan_target(args.load)
        findings = db.load_findings(args.load)
    if target is None:
        print(f"Error: no scan #{args.load} in {args.db}", file=sys.stderr)
        return 2
    by_verdict = {
        verdict: [finding for finding in findings if finding.verdict == verdict]
        for verdict in Verdict
    }
    assessment = Assessment(
        real=by_verdict[Verdict.REAL],
        noise=by_verdict[Verdict.NOISE],
        false_positives=by_verdict[Verdict.FALSE_POSITIVE],
    )
    print_assessment(console, target, assessment, show_filtered=args.show_filtered)
    if args.compare:
        print_coverage(console, KNOWN_APPS[args.compare](assessment))
    if args.html:
        _write_html(console, args.html, target, assessment, f"{args.db}, scan #{args.load}")
    return 0


def _print_finding(console: Console, finding: Finding) -> None:
    indent = " " * 14
    badge = console.color(f"{finding.severity.label.upper():<6}", _SEVERITY_COLOR[finding.severity])
    console.line(f"  {finding.rank:>2}  {badge}  {console.bold(catalog.categorize(finding).title)}")
    details = [finding.name, finding.location.short_path()]
    if finding.cwe_id:
        details.append(f"CWE-{finding.cwe_id}")
    details += [f"{finding.confidence.label} confidence", f"{finding.occurrences}x"]
    console.line(indent + console.dim(" | ".join(details)))
    if finding.attack:
        proof = f"attack: {finding.attack}"
        if finding.evidence:
            proof += f" -> response: {finding.evidence}"
        console.line(indent + console.dim(_shorten(proof, 110)))


def _scope_note(foreign: dict[str, int]) -> str:
    with_alerts = {site: count for site, count in foreign.items() if count}
    if not with_alerts:
        return ""
    top_sites = ", ".join(sorted(with_alerts, key=with_alerts.get, reverse=True)[:3])
    return (f"Ignored {sum(with_alerts.values())} alert(s) from {len(with_alerts)} other site(s) "
            f"loaded during the scan, e.g. {top_sites}")


def _write_html(console: Console, path: str, target: str, assessment: Assessment, source: str,
                scope_note: str = "") -> None:
    written_path = write_html_report(path, target, assessment, source=source, scope_note=scope_note)
    console.line(console.dim(f"HTML report: {written_path.resolve()}"))


def _default_report_path(mode: str) -> str:
    return f"reports/zap-{mode}-{datetime.now():%Y%m%d-%H%M%S}.json"


def _resolve_scope(raw_scope: str | None, console: Console) -> ScanScope:
    if raw_scope:
        return ScanScope(raw_scope)
    if not sys.stdin.isatty():
        return ScanScope.SITE
    console.line("Choose scan scope:")
    console.line("  [1] All subpages (site) - default")
    console.line("  [2] Main page only (page)")
    try:
        choice = input("Scope [1/2]: ").strip().lower()
    except EOFError:
        return ScanScope.SITE
    if choice in ("2", "page", "main"):
        return ScanScope.PAGE
    return ScanScope.SITE


def _shorten(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _enable_windows_ansi() -> None:
    # The classic Windows console needs ANSI escape processing switched on.
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass  # no colors is fine


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alert-scanner",
        description="Scan a website with OWASP ZAP, filter out the noise and list the real issues.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--report", metavar="FILE", help="analyze an existing ZAP JSON report (no Docker)")
    source.add_argument("--scan", metavar="URL", help="scan a live site with OWASP ZAP in Docker")
    source.add_argument("--history", action="store_true", help="list saved scans")
    source.add_argument("--load", metavar="ID", type=int, help="show a saved scan")

    live_scan = parser.add_argument_group("live scan")
    live_scan.add_argument("--mode", choices=[mode.value for mode in ScanMode],
                           default=ScanMode.BASELINE.value,
                           help="baseline: passive, fast; full: active, all rules, slow; "
                                "focused: active, catalog rules only")
    live_scan.add_argument("--scope", choices=[scope.value for scope in ScanScope],
                           help="site: main page and all subpages; page: only the given URL")
    live_scan.add_argument("--ajax", action="store_true",
                           help="use the AJAX spider (needed for single-page apps such as Juice Shop)")
    live_scan.add_argument("--spider-minutes", type=int, metavar="N", help="time limit for the spider")
    live_scan.add_argument("--max-minutes", type=int, metavar="N", help="time limit for the active scan")
    live_scan.add_argument("--save-report", metavar="FILE",
                           help="where to save the raw ZAP report (default reports/zap-<mode>-<time>.json)")

    parser.add_argument("--target", metavar="URL",
                        help="with --report: the scanned site (default: the site with the most alerts)")
    parser.add_argument("--compare", choices=sorted(KNOWN_APPS),
                        help="compare the result with the known vulnerabilities of a training app")
    parser.add_argument("--db", default=_DEFAULT_DB, help=f"SQLite file (default {_DEFAULT_DB})")
    parser.add_argument("--no-store", action="store_true", help="do not save the result")
    parser.add_argument("--show-filtered", action="store_true", help="also list the filtered alerts")
    parser.add_argument("--html", metavar="FILE", help="write an HTML report")
    return parser


_DEFAULT_DB = "scans.db"
_SEVERITY_COLOR = {
    Severity.HIGH: "31",    # red
    Severity.MEDIUM: "33",  # yellow
    Severity.LOW: "36",     # cyan
    Severity.INFO: "90",    # grey
}


if __name__ == "__main__":
    raise SystemExit(main())
