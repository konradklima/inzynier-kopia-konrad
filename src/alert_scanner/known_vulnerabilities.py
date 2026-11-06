"""Compare a scan with the known vulnerabilities of a training app.

OWASP Juice Shop documents its vulnerabilities as challenges grouped in categories
(data/static/challenges.yml in the juice-shop repository). So we know what is really
there and can measure which categories a scan finds and which ones no automated
scanner can reach.

Coverage is counted per category: detecting "Injection" means the scan found at
least one injection issue, not all 14 injection challenges.
"""

from __future__ import annotations
from dataclasses import dataclass
from alert_scanner import catalog
from alert_scanner.risk_rules import Assessment


def juice_shop_coverage(assessment: Assessment) -> Coverage:
    """Only real findings count; filtered noise cannot confirm a category."""
    found = {catalog.categorize(finding).key for finding in assessment.real}
    rows = tuple(
        CoverageRow(category, tuple(sorted(category.detectable_as & found)))
        for category in JUICE_SHOP_CATEGORIES
    )
    return Coverage(rows, JUICE_SHOP_SOURCE)


KNOWN_APPS = {"juice-shop": juice_shop_coverage}


@dataclass(frozen=True, slots=True)
class Coverage:
    rows: tuple[CoverageRow, ...]
    source: str

    @property
    def detectable(self) -> list[CoverageRow]:
        return [row for row in self.rows if row.detectable]

    @property
    def detected(self) -> list[CoverageRow]:
        return [row for row in self.rows if row.detected]

    @property
    def out_of_reach(self) -> list[CoverageRow]:
        return [row for row in self.rows if not row.detectable]

    @property
    def total_challenges(self) -> int:
        return sum(row.category.challenges for row in self.rows)

    def challenges_in(self, rows: list[CoverageRow]) -> int:
        return sum(row.category.challenges for row in rows)


@dataclass(frozen=True, slots=True)
class CoverageRow:
    category: KnownCategory
    detected_by: tuple[str, ...]  # catalog keys that matched in this scan

    @property
    def detectable(self) -> bool:
        return bool(self.category.detectable_as)

    @property
    def detected(self) -> bool:
        return bool(self.detected_by)


@dataclass(frozen=True, slots=True)
class KnownCategory:
    name: str                       # category name used by Juice Shop
    challenges: int
    detectable_as: frozenset[str]   # catalog keys; empty means out of reach for a scanner
    why_not: str = ""


def _known(name: str, challenges: int, catalog_keys: set[str] | None = None,
           why_not: str = "") -> KnownCategory:
    return KnownCategory(name, challenges, frozenset(catalog_keys or ()), why_not)


JUICE_SHOP_SOURCE = "juice-shop/juice-shop data/static/challenges.yml (master, 2026-11-01, 116 challenges)"

JUICE_SHOP_CATEGORIES: tuple[KnownCategory, ...] = (
    _known("Injection", 14, {"injection"}),
    _known("XSS", 9, {"xss"}),
    _known("Broken Access Control", 12, {"files", "cross_site"}),
    _known("Sensitive Data Exposure", 17, {"info_leak", "files"}),
    _known("Vulnerable Components", 9, {"outdated"}),
    _known("Security Misconfiguration", 5, {"headers", "clickjacking"}),
    _known("Cryptographic Issues", 5, {"transport"}),
    _known("Unvalidated Redirects", 2, {"redirect"}),
    _known("Improper Input Validation", 12, why_not="business logic (e.g. negative quantity in the basket)"),
    _known("Broken Authentication", 9, why_not="weak passwords, password reset; needs knowledge of the accounts"),
    _known("Miscellaneous", 6, why_not="mixed tasks, most need a human"),
    _known("Observability Failures", 4, why_not="access to logs and metrics behind unlinked paths"),
    _known("Broken Anti Automation", 4, why_not="missing CAPTCHA or rate limits; needs an abuse scenario"),
    _known("Security through Obscurity", 3, why_not="hidden content; needs manual analysis"),
    _known("Insecure Deserialization", 3, why_not="needs payloads built for a specific technology"),
    _known("XXE", 2, why_not="needs an uploaded, crafted XML file"),
)
