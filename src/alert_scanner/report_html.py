"""HTML report: one self-contained file with a summary and two tables.

Temporary: the dashboard will replace this module.
"""

from __future__ import annotations
from datetime import datetime
from html import escape
from pathlib import Path
from alert_scanner import catalog
from alert_scanner.domain import Finding
from alert_scanner.risk_rules import Assessment, classify_with_reason


def write_html_report(path: str | Path, target: str, assessment: Assessment, *,
                      source: str = "", scope_note: str = "") -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(target, assessment, source=source, scope_note=scope_note), encoding="utf-8")
    return path


def render_html(target: str, assessment: Assessment, *, source: str = "",
                generated_at: datetime | None = None, scope_note: str = "") -> str:
    generated_at = generated_at or datetime.now()
    meta = [f"Target: {escape(target)}", f"Generated: {generated_at:%Y-%m-%d %H:%M}"]
    if source:
        meta.insert(1, f"Source: {escape(source)}")
    return _PAGE_TEMPLATE.format(
        css=_CSS,
        title=escape(target),
        meta=" &middot; ".join(meta),
        summary=_summary(assessment),
        scope=f'<p class="note">{escape(scope_note)}</p>' if scope_note else "",
        findings=_findings_table(assessment.real),
        by_page=_by_page_table(assessment.real),
        filtered=_filtered_table([*assessment.noise, *assessment.false_positives]),
    )


def _summary(assessment: Assessment) -> str:
    counts = [
        f"{count} {severity.label}"
        for severity, count in assessment.count_by_severity().items() if count
    ]
    issues = f"<strong>{len(assessment.real)}</strong> issue(s) to fix"
    if counts:
        issues += f" ({', '.join(counts)})"
    return (f"{issues}. {assessment.filtered_out} of {assessment.total} scanner alerts filtered out "
            f"({assessment.filtered_out_pct:.0f}%).")


def _findings_table(findings: list[Finding]) -> str:
    if not findings:
        return '<p class="note">No issues to fix.</p>'
    rows = "".join(_finding_row(finding) for finding in findings)
    return (
        '<div class="wrap"><table><thead><tr>'
        '<th class="num">#</th><th>Risk</th><th>Issue</th><th>Where</th><th class="num">Count</th>'
        f"</tr></thead><tbody>{rows}</tbody></table></div>"
    )


def _finding_row(finding: Finding) -> str:
    category = catalog.categorize(finding)
    technical_details = [finding.name]
    if finding.cwe_id:
        technical_details.append(f"CWE-{finding.cwe_id}")
    if category.owasp != "-":
        technical_details.append(category.owasp)
    severity = finding.severity.label
    return (
        '<tr class="finding">'
        f'<td class="num">{finding.rank}</td>'
        f'<td><span class="risk risk-{severity}">{severity}</span></td>'
        f"<td><strong>{escape(category.title)}</strong>"
        f'<div class="tech">{escape(" | ".join(technical_details))}</div></td>'
        f"<td>{_format_locations(finding)}</td>"
        f'<td class="num">{finding.occurrences}</td>'
        "</tr>"
    )


def _format_locations(finding: Finding) -> str:
    paths = list(dict.fromkeys(loc.short_path() for loc in finding.all_locations()))
    visible = [f"<div><code>{escape(path)}</code></div>" for path in paths[:4]]
    if len(paths) > 4:
        more = "".join(f"<div><code>{escape(path)}</code></div>" for path in paths[4:])
        visible.append(
            f'<details class="more-pages"><summary>+{len(paths) - 4} more page(s)</summary>'
            f"{more}</details>"
        )
    return "".join(visible)


def _by_page_table(findings: list[Finding]) -> str:
    if not findings:
        return '<p class="note">No issues found on any page.</p>'
    pages: dict[str, list[Finding]] = {}
    for finding in findings:
        for page in dict.fromkeys(loc.page_path() for loc in finding.all_locations()):
            pages.setdefault(page, []).append(finding)
    rows = []
    for page, page_findings in sorted(pages.items(), key=lambda item: (-len(item[1]), item[0])):
        items = "".join(
            f'<div class="page-issue"><span class="risk risk-{f.severity.label}">{f.severity.label}</span> '
            f"<strong>{escape(catalog.categorize(f).title)}</strong> "
            f'<span class="tech">({escape(f.name)})</span></div>'
            for f in page_findings
        )
        rows.append(
            f"<tr><td><code>{escape(page)}</code></td>"
            f"<td>{items}</td>"
            f'<td class="num">{len(page_findings)}</td></tr>'
        )
    return (
        '<div class="wrap"><table><thead><tr>'
        '<th>Page</th><th>Issues on this page</th><th class="num">Count</th>'
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
    )


def _filtered_table(findings: list[Finding]) -> str:
    if not findings:
        return '<p class="note">Nothing was filtered out.</p>'
    rows = "".join(
        f"<tr><td>{escape(finding.name)}</td><td>{finding.verdict.label}</td>"
        f"<td>{escape(classify_with_reason(finding)[1])}</td></tr>"
        for finding in findings
    )
    return (
        '<div class="wrap"><table><thead><tr><th>Alert</th><th>Verdict</th><th>Reason</th>'
        f"</tr></thead><tbody>{rows}</tbody></table></div>"
    )


_PAGE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan report: {title}</title>
<style>{css}</style>
</head>
<body>
<main>
<h1>Scan report</h1>
<p class="note">{meta}</p>
<p class="summary">{summary}</p>
{scope}
<h2>Issues to fix</h2>
{findings}
<h2>Issues by page</h2>
{by_page}
<h2>Filtered out</h2>
{filtered}
</main>
</body>
</html>
"""

_CSS = """
:root {
  --bg: #ffffff; --fg: #1d1d1f; --muted: #6e6e73; --line: #e5e5ea;
  --high: #c62828; --medium: #a65f00; --low: #1565c0;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1c1c1e; --fg: #f5f5f7; --muted: #a1a1a6; --line: #3a3a3c;
    --high: #ff6b6b; --medium: #ffb340; --low: #64b5f6;
  }
}
body {
  margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 980px; margin: 0 auto; padding: 32px 16px 48px; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 32px 0 8px; }
.note, .tech { color: var(--muted); font-size: 13px; }
.summary { font-size: 17px; margin: 16px 0 4px; }
.wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; vertical-align: top; padding: 10px 8px; border-bottom: 1px solid var(--line); }
th { font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
code { font: 13px ui-monospace, SFMono-Regular, Consolas, monospace; word-break: break-all; }
.risk {
  font-size: 12px; font-weight: 600; text-transform: capitalize; white-space: nowrap;
  padding: 1px 8px; border: 1px solid currentColor; border-radius: 999px;
}
.risk-high { color: var(--high); }
.risk-medium { color: var(--medium); }
.risk-low { color: var(--low); }
.page-issue { margin: 4px 0; }
.more-pages summary { cursor: pointer; color: var(--muted); font-size: 12px; margin-top: 2px; }
"""
