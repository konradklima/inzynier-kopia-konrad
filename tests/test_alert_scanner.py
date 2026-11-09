"""Checks of the most important behavior. None of them needs Docker."""

from pathlib import Path
import pytest
from alert_scanner import catalog
from alert_scanner.cli import main
from alert_scanner.domain import Confidence, Finding, Location, Severity, Verdict
from alert_scanner.known_vulnerabilities import juice_shop_coverage
from alert_scanner.risk_rules import assess, classify
from alert_scanner.scanner import ScanMode, ScanScope, build_docker_command, build_focused_plan, discover_subpages
from alert_scanner.storage import Storage
from alert_scanner.zap_parser import ZapReportError, parse_report, same_origin

TARGET = "http://target:3000"
FULL_SCAN_REPORT = Path(__file__).parent.parent / "reports" / "zap-full-juiceshop.json"


def test_parser_turns_a_zap_alert_into_a_finding():
    report = {"site": [{"@name": TARGET, "alerts": [_zap_alert()]}]}

    [finding] = parse_report(report)

    assert finding.rule_id == "40018"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.MEDIUM
    assert finding.cwe_id == 89
    assert finding.wasc_id is None
    assert finding.occurrences == 4
    assert finding.location.short_path() == "/rest/search [q]"
    assert finding.attack == "'("
    assert finding.description == "Database injection"


def test_parser_keeps_only_the_target_site():
    report = {"site": [
        {"@name": TARGET, "alerts": [_zap_alert("Ours")]},
        {"@name": "https://github.com", "alerts": [_zap_alert("Foreign")]},
    ]}

    assert [finding.name for finding in parse_report(report, TARGET)] == ["Ours"]


def test_parser_rejects_a_file_that_is_not_a_zap_report():
    with pytest.raises(ZapReportError):
        parse_report({"something": "else"})


def test_rules_separate_real_issues_from_noise():
    assert classify(_finding(Severity.HIGH, Confidence.LOW)) == Verdict.REAL
    assert classify(_finding(Severity.LOW, Confidence.MEDIUM)) == Verdict.REAL
    assert classify(_finding(Severity.LOW, Confidence.LOW)) == Verdict.NOISE
    assert classify(_finding(Severity.INFO, Confidence.HIGH)) == Verdict.NOISE
    assert classify(_finding(Severity.HIGH, Confidence.FALSE_POSITIVE)) == Verdict.FALSE_POSITIVE


def test_real_issues_are_ranked_by_severity_then_confidence():
    assessment = assess([
        _finding(Severity.LOW, Confidence.HIGH, name="Low"),
        _finding(Severity.HIGH, Confidence.LOW, name="High, unsure"),
        _finding(Severity.HIGH, Confidence.HIGH, name="High, sure"),
        _finding(Severity.INFO, Confidence.HIGH, name="Info"),
    ])

    assert [(finding.rank, finding.name) for finding in assessment.real] == [
        (1, "High, sure"), (2, "High, unsure"), (3, "Low"),
    ]
    assert [finding.name for finding in assessment.noise] == ["Info"]
    assert assessment.filtered_out_pct == 25


def test_catalog_matches_by_rule_then_by_cwe():
    assert catalog.categorize(_finding(rule_id="40018")).key == "injection"
    assert catalog.categorize(_finding(rule_id="unknown", cwe_id=79)).key == "xss"
    assert catalog.categorize(_finding(rule_id="unknown")) is catalog.OTHER


def test_coverage_counts_only_real_findings():
    real_injection = _finding(Severity.HIGH, Confidence.MEDIUM, rule_id="40018")
    noisy_xss = _finding(Severity.INFO, Confidence.MEDIUM, rule_id="40012")

    coverage = juice_shop_coverage(assess([real_injection, noisy_xss]))

    assert [row.category.name for row in coverage.detected] == ["Injection"]
    assert coverage.total_challenges == 116


def test_storage_keeps_the_assessment(tmp_path):
    findings = assess([
        _finding(Severity.HIGH, Confidence.HIGH, name="Real"),
        _finding(Severity.INFO, Confidence.HIGH, name="Noise"),
    ]).all_findings()

    with Storage(tmp_path / "scans.db") as db:
        scan_id = db.save_scan(TARGET, findings)
        saved_findings = db.load_findings(scan_id)
        summary = db.list_scans()[0]

    assert saved_findings == findings
    assert (summary.finding_count, summary.real_count) == (2, 1)


def test_scan_modes_run_the_right_zap_commands():
    assert "zap-baseline.py" in build_docker_command(TARGET, ScanMode.BASELINE, "workdir")
    assert "zap-full-scan.py" in build_docker_command(TARGET, ScanMode.FULL, "workdir")

    plan = build_focused_plan(TARGET)
    assert 'defaultThreshold: "off"' in plan  # every rule is off unless listed below
    for rule in catalog.focused_scan_rules():
        assert f"- id: {rule}\n" in plan


def test_scan_scope_page_skips_spider_and_limits_depth():
    page_cmd = build_docker_command(TARGET, ScanMode.BASELINE, "workdir", scope=ScanScope.PAGE)
    assert "spider.maxDepth=1" in " ".join(page_cmd)

    page_plan = build_focused_plan(TARGET, scope=ScanScope.PAGE)
    assert "type: requestor" in page_plan
    assert "type: spider" not in page_plan

    site_plan = build_focused_plan(
        TARGET, scope=ScanScope.SITE, seed_urls=[TARGET, f"{TARGET}/about"]
    )
    assert "type: spider" in site_plan
    assert f"'{TARGET}/about'" in site_plan


def test_discover_subpages_reads_sitemap_and_links(monkeypatch):
    responses = {
        f"{TARGET}/robots.txt": ("Sitemap: http://target:3000/sitemap.xml", f"{TARGET}/robots.txt"),
        f"{TARGET}/sitemap.xml": (
            "<urlset><url><loc>http://target:3000/contact</loc></url></urlset>",
            f"{TARGET}/sitemap.xml",
        ),
        f"{TARGET}/": (
            '<a href="/offer">Offer</a><a href="https://external.example/x">Out</a>',
            f"{TARGET}/",
        ),
    }
    monkeypatch.setattr(
        "alert_scanner.scanner._fetch_raw",
        lambda url, timeout, *, accept: responses.get(url, ("", url)),
    )

    urls = discover_subpages(TARGET)

    assert f"{TARGET}/" in urls
    assert f"{TARGET}/contact" in urls
    assert f"{TARGET}/offer" in urls
    assert not any("external.example" in url for url in urls)


def test_same_origin_matches_www_and_subdomains():
    assert same_origin("https://example.com", "https://www.example.com")
    assert same_origin("https://example.com", "https://shop.example.com")
    assert not same_origin("https://example.com", "https://other.org")


def test_real_full_scan_report_end_to_end(tmp_path, capsys):
    database = tmp_path / "scans.db"
    html_report = tmp_path / "report.html"

    exit_code = main([
        "--report", str(FULL_SCAN_REPORT),
        "--target", "http://host.docker.internal:3000",
        "--compare", "juice-shop",
        "--db", str(database),
        "--html", str(html_report),
    ])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Issues to fix: 13 (3 high, 4 medium, 6 low)" in output
    assert "Filtered out:  7 of 20 scanner alerts (35%)" in output
    assert "Someone can get into your database" in output
    assert "Detected 5 of 8 categories" in output
    assert "SQL Injection" in html_report.read_text(encoding="utf-8")
    with Storage(database) as db:
        assert db.list_scans()[0].real_count == 13


def _finding(severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, *, name="Test",
             rule_id="99999", cwe_id=None):
    return Finding(
        rule_id=rule_id,
        name=name,
        severity=severity,
        confidence=confidence,
        location=Location(f"{TARGET}/login", "POST", "email"),
        cwe_id=cwe_id,
    )


def _zap_alert(name="SQL Injection"):
    return {
        "pluginid": "40018",
        "name": name,
        "riskcode": "3",
        "confidence": "2",
        "cweid": "89",
        "wascid": "-1",
        "count": "4",
        "desc": "<p>Database <b>injection</b></p>",
        "instances": [{
            "uri": f"{TARGET}/rest/search?q=x",
            "method": "GET",
            "param": "q",
            "attack": "'(",
            "evidence": "HTTP/1.1 500",
        }],
    }
