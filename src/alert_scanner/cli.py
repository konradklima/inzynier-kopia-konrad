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
from alert_scanner.scanner import ScanError, ScanMode, run_zap_scan
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
        print(f"Błąd: {error}", file=sys.stderr)
        return 2


def print_assessment(console: Console, target: str, assessment: Assessment, *,
                     show_filtered: bool, scope_note: str = "") -> None:
    breakdown = ", ".join(
        console.color(f"{count} {severity.pl}", _SEVERITY_COLOR[severity])
        for severity, count in assessment.count_by_severity().items() if count
    )
    console.line()
    console.line(console.bold(f"Wynik skanu dla {target}"))
    console.line(f"  Do naprawienia: {console.bold(str(len(assessment.real)))}"
                 + (f" ({breakdown})" if breakdown else ""))
    console.line(f"  Odrzucone:      {assessment.filtered_out} z {assessment.total} alertów skanera "
                 f"({assessment.filtered_out_pct:.0f}%)")
    if scope_note:
        console.line(console.dim(f"  {scope_note}"))
    console.line()

    if assessment.real:
        console.line(console.bold("Do naprawienia, od najpilniejszych"))
        for finding in assessment.real:
            _print_finding(console, finding)
    else:
        console.line("Nie ma nic do naprawienia.")

    if show_filtered and assessment.filtered_out:
        console.line()
        console.line(console.bold("Odrzucone"))
        for finding in (*assessment.noise, *assessment.false_positives):
            console.line(console.dim(f"  {finding.verdict.pl:<15} {finding.name} "
                                     f"(ryzyko {finding.severity.pl}, "
                                     f"pewność {finding.confidence.pl})"))
    console.line()


def print_coverage(console: Console, coverage: Coverage) -> None:
    detectable, detected, out_of_reach = coverage.detectable, coverage.detected, coverage.out_of_reach
    console.line(console.bold("Porównanie ze znanymi podatnościami Juice Shopa"))
    console.line(console.dim(f"  źródło: {coverage.source}"))
    console.line(f"  Wykryto {len(detected)} z {len(detectable)} kategorii, które skaner może znaleźć "
                 f"({coverage.challenges_in(detected)} z {coverage.challenges_in(detectable)} wyzwań)")
    for row in detectable:
        mark = console.color("[x]", "32") if row.detected else console.color("[ ]", "31")
        found_via = console.dim(f"  przez {', '.join(row.detected_by)}") if row.detected else ""
        console.line(f"    {mark} {row.category.name} ({row.category.challenges}){found_via}")
    console.line(f"  Poza zasięgiem automatycznego skanowania: {len(out_of_reach)} kategorii "
                 f"({coverage.challenges_in(out_of_reach)} wyzwań)")
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
        report_path = Path(args.save_report or _default_report_path(args.mode))
        console.line(console.dim(f"Uruchamiam OWASP ZAP ({args.mode}) dla {args.scan} ..."))
        run_zap_scan(
            args.scan, report_path, ScanMode(args.mode),
            ajax=args.ajax, spider_minutes=args.spider_minutes, max_scan_minutes=args.max_minutes,
        )
        console.line(console.dim(f"Surowy raport ZAP zapisano w {report_path}"))
    else:
        report_path = Path(args.report)

    report = load_report(report_path)
    target = args.scan or args.target or guess_target(report)
    scope_note = _scope_note(foreign_sites(report, target))
    classifier = _classifier(args, console)
    assessment = assess(parse_report(report, target), classifier)

    print_assessment(console, target, assessment, show_filtered=args.show_filtered,
                     scope_note=scope_note)
    if args.compare:
        print_coverage(console, KNOWN_APPS[args.compare](assessment))
    if not args.no_store:
        with Storage(args.db) as db:
            scan_id = db.save_scan(target, assessment.all_findings())
        console.line(console.dim(f"Zapisano jako skan #{scan_id} w {args.db}"))
    if args.html:
        _write_html(console, args.html, target, assessment, report_path.name, scope_note, classifier)
    return 0


def _classifier(args: argparse.Namespace, console: Console):
    """None means the rules in risk_rules.py."""
    if args.classifier == "rules":
        return None
    from alert_scanner.ml.model import MlClassifier

    if not Path(args.model).exists():
        raise FileNotFoundError(f"brak wytrenowanego modelu w {args.model} (uruchom: alert-scanner-ml train)")
    console.line(console.dim(f"Klasyfikator: wytrenowany model {args.model}"))
    return MlClassifier.load(args.model, mode=args.mode)


def _show_history(args: argparse.Namespace, console: Console) -> int:
    with Storage(args.db) as db:
        scans = db.list_scans()
    if not scans:
        console.line("Brak zapisanych skanów.")
        return 0
    console.line(console.bold("Zapisane skany"))
    for scan in scans:
        counts = console.dim(f"{scan.real_count} realnych z {scan.finding_count}")
        console.line(f"  #{scan.id:<4} {scan.created_at}  {scan.target}  {counts}")
    return 0


def _show_saved_scan(args: argparse.Namespace, console: Console) -> int:
    with Storage(args.db) as db:
        target = db.scan_target(args.load)
        findings = db.load_findings(args.load)
    if target is None:
        print(f"Błąd: nie ma skanu #{args.load} w {args.db}", file=sys.stderr)
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
        _write_html(console, args.html, target, assessment, f"{args.db}, skan #{args.load}")
    return 0


def _print_finding(console: Console, finding: Finding) -> None:
    indent = " " * 19
    badge = console.color(f"{finding.severity.pl.upper():<11}", _SEVERITY_COLOR[finding.severity])
    console.line(f"  {finding.rank:>2}  {badge}  {console.bold(catalog.categorize(finding).title)}")
    details = [finding.name, finding.location.short_path()]
    if finding.cwe_id:
        details.append(f"CWE-{finding.cwe_id}")
    details += [f"pewność {finding.confidence.pl}", f"{finding.occurrences}x"]
    console.line(indent + console.dim(" | ".join(details)))
    if finding.attack:
        proof = f"atak: {finding.attack}"
        if finding.evidence:
            proof += f" -> odpowiedź: {finding.evidence}"
        console.line(indent + console.dim(_shorten(proof, 110)))


def _scope_note(foreign: dict[str, int]) -> str:
    with_alerts = {site: count for site, count in foreign.items() if count}
    if not with_alerts:
        return ""
    top_sites = ", ".join(sorted(with_alerts, key=with_alerts.get, reverse=True)[:3])
    return (f"Pominięto {sum(with_alerts.values())} alertów z {len(with_alerts)} innych stron "
            f"załadowanych podczas skanu, np. {top_sites}")


def _write_html(console: Console, path: str, target: str, assessment: Assessment, source: str,
                scope_note: str = "", classifier=None) -> None:
    written_path = write_html_report(path, target, assessment, source=source, scope_note=scope_note,
                                     classifier=classifier)
    console.line(console.dim(f"Raport HTML: {written_path.resolve()}"))


def _default_report_path(mode: str) -> str:
    return f"reports/zap-{mode}-{datetime.now():%Y%m%d-%H%M%S}.json"


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
        description="Skanuje stronę internetową skanerem OWASP ZAP, odrzuca szum i wypisuje realne problemy.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--report", metavar="FILE", help="analizuje gotowy raport JSON z ZAP-a (bez Dockera)")
    source.add_argument("--scan", metavar="URL", help="skanuje działającą stronę skanerem OWASP ZAP w Dockerze")
    source.add_argument("--history", action="store_true", help="wypisuje zapisane skany")
    source.add_argument("--load", metavar="ID", type=int, help="pokazuje zapisany skan")

    live_scan = parser.add_argument_group("live scan")
    live_scan.add_argument("--mode", choices=[mode.value for mode in ScanMode],
                           default=ScanMode.BASELINE.value,
                           help="baseline: pasywny, szybki; full: aktywny, wszystkie reguły, wolny; "
                                "focused: aktywny, tylko reguły z katalogu")
    live_scan.add_argument("--ajax", action="store_true",
                           help="używa pająka AJAX (potrzebny przy aplikacjach jednostronicowych, np. Juice Shop)")
    live_scan.add_argument("--spider-minutes", type=int, metavar="N", help="limit czasu dla pająka")
    live_scan.add_argument("--max-minutes", type=int, metavar="N", help="limit czasu dla skanu aktywnego")
    live_scan.add_argument("--save-report", metavar="FILE",
                           help="gdzie zapisać surowy raport ZAP (domyślnie reports/zap-<tryb>-<czas>.json)")

    parser.add_argument("--target", metavar="URL",
                        help="z --report: skanowana strona (domyślnie ta z największą liczbą alertów)")
    parser.add_argument("--classifier", choices=["rules", "ml"], default="rules",
                        help="rules: waga + pewność (domyślnie); ml: wytrenowany model")
    parser.add_argument("--model", default="models/classifier.joblib",
                        help="plik modelu dla --classifier ml")
    parser.add_argument("--compare", choices=sorted(KNOWN_APPS),
                        help="porównuje wynik ze znanymi podatnościami aplikacji treningowej")
    parser.add_argument("--db", default=_DEFAULT_DB, help=f"plik SQLite (domyślnie {_DEFAULT_DB})")
    parser.add_argument("--no-store", action="store_true", help="nie zapisuje wyniku")
    parser.add_argument("--show-filtered", action="store_true", help="wypisuje też odrzucone alerty")
    parser.add_argument("--html", metavar="FILE", help="zapisuje raport HTML")
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
