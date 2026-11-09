"""OWASP ZAP adapter: ZAP JSON report -> list of Finding.

This is the only module that knows the ZAP report format. Supporting another
scanner means adding another adapter next to this one.

Report layout ("traditional JSON", the -J option of the ZAP scripts):
    {"site": [{"@name": "http://host:3000", "alerts": [{...}, ...]}, ...]}

One alert is one issue type on one site, with sample `instances` and a total `count`.
"""

from __future__ import annotations
import html
import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from alert_scanner.domain import Confidence, Finding, Location, Severity


def parse_report(report: dict[str, Any], target: str | None = None) -> list[Finding]:
    """Convert a loaded ZAP report into findings.

    If `target` is given, only alerts for that origin are kept. ZAP also lists other
    sites that its browser loaded while crawling (links to GitHub, Facebook and so on),
    and those are not the site we were asked to scan.
    """
    by_key: dict[tuple[str, str], Finding] = {}
    for site in _sites(report):
        site_name = site.get("@name", "")
        if target and not same_origin(site_name, target):
            continue
        for alert in site.get("alerts") or []:
            finding = _parse_alert(alert, site_name)
            key = (finding.rule_id, finding.name)
            if key in by_key:
                by_key[key] = _merge_findings(by_key[key], finding)
            else:
                by_key[key] = finding
    return list(by_key.values())


def parse_report_file(path: str | Path, target: str | None = None) -> list[Finding]:
    return parse_report(load_report(path), target)


def load_report(path: str | Path) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as report_file:
            return json.load(report_file)
    except json.JSONDecodeError as error:
        raise ZapReportError(f"{path} is not valid JSON: {error}") from error


def guess_target(report: dict[str, Any]) -> str:
    """Guess the scanned site: the one with the most alerts.

    The report does not store the scan target, and the site order is not reliable
    (a third-party site can come first).
    """
    sites = _sites(report)
    if not sites:
        return "unknown target"
    busiest_site = max(sites, key=lambda site: len(site.get("alerts") or []))
    return busiest_site.get("@name", "unknown target")


def foreign_sites(report: dict[str, Any], target: str) -> dict[str, int]:
    """Sites in the report other than the target, with their alert counts."""
    return {
        site.get("@name", ""): len(site.get("alerts") or [])
        for site in _sites(report)
        if not same_origin(site.get("@name", ""), target)
    }


def same_origin(first_url: str, second_url: str) -> bool:
    """True when both URLs belong to the same site (including www. and subdomains)."""
    first_scheme, first_host, first_port = _origin(first_url)
    second_scheme, second_host, second_port = _origin(second_url)
    if not first_host or not second_host:
        return False
    same_host = (
        first_host == second_host
        or first_host.endswith("." + second_host)
        or second_host.endswith("." + first_host)
    )
    if not same_host:
        return False
    # Allow http <-> https redirects on standard ports (80/443), but keep custom ports distinct.
    if {first_port, second_port} <= {80, 443, None}:
        return True
    return first_scheme == second_scheme and first_port == second_port


def strip_html(text: str) -> str:
    """ZAP writes descriptions as HTML. Keep the paragraphs, drop the tags."""
    if not text:
        return ""
    text = html.unescape(_HTML_TAGS.sub("", _PARAGRAPH_BREAKS.sub("\n", text)))
    lines = (" ".join(line.split()) for line in text.splitlines())
    return "\n".join(line for line in lines if line)


class ZapReportError(ValueError):
    """The file does not look like a ZAP JSON report."""


def _sites(report: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(report, dict) or "site" not in report:
        raise ZapReportError("Missing 'site' key, this is not a ZAP JSON report.")
    sites = report["site"]
    # Older ZAP versions wrote a single site as an object instead of a list.
    return [sites] if isinstance(sites, dict) else list(sites)


def _parse_alert(alert: dict[str, Any], site_name: str) -> Finding:
    instances = alert.get("instances") or []
    first_instance = instances[0] if instances else {}
    locations = tuple(
        dict.fromkeys(
            Location(
                uri=instance.get("uri") or site_name,
                method=instance.get("method") or "GET",
                param=instance.get("param") or "",
            )
            for instance in (instances or [{}])
        )
    )
    return Finding(
        rule_id=str(alert.get("pluginid", "")),
        name=alert.get("name") or alert.get("alert") or "Unknown alert",
        severity=_to_enum(Severity, alert.get("riskcode"), "riskcode"),
        confidence=_to_enum(Confidence, alert.get("confidence"), "confidence"),
        location=locations[0],
        cwe_id=_positive_int(alert.get("cweid")),
        wasc_id=_positive_int(alert.get("wascid")),
        description=strip_html(alert.get("desc", "")),
        solution=strip_html(alert.get("solution", "")),
        occurrences=_positive_int(alert.get("count")) or max(len(instances), 1),
        attack=_truncate(first_instance.get("attack")),
        evidence=_truncate(first_instance.get("evidence")),
        locations=locations,
    )


def _merge_findings(first: Finding, second: Finding) -> Finding:
    merged_locations = tuple(dict.fromkeys((*first.all_locations(), *second.all_locations())))
    return replace(
        first,
        severity=max(first.severity, second.severity),
        confidence=max(first.confidence, second.confidence),
        occurrences=first.occurrences + second.occurrences,
        locations=merged_locations,
    )


def _to_enum(enum_class, raw_value: Any, field: str):
    try:
        return enum_class(int(raw_value))
    except (TypeError, ValueError) as error:
        raise ZapReportError(f"Invalid value for '{field}': {raw_value!r}") from error


def _positive_int(raw_value: Any) -> int | None:
    # ZAP uses "-1" or "0" when there is no CWE / WASC id.
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _truncate(text: str | None, limit: int = 500) -> str:
    # Evidence can be a large chunk of the response body.
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    return scheme, (parts.hostname or "").lower(), parts.port or _DEFAULT_PORTS.get(scheme)


_DEFAULT_PORTS = {"http": 80, "https": 443}
_PARAGRAPH_BREAKS = re.compile(r"</p>\s*<p>|<br\s*/?>|</li>\s*<li>", re.IGNORECASE)
_HTML_TAGS = re.compile(r"<[^>]+>")
