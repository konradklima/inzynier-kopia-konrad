"""Kategorie zagrożeń z tytułami prostym językiem.

The scanner reports technical names such as "SQL Injection - SQLite" (CWE-89).
This module maps every finding to a category with a title a non-specialist can
understand. Matching order: ZAP rule id, then CWE id, then "other". CWE ids are
scanner-independent, so the mapping keeps working if the scanner changes.
"""

from __future__ import annotations
from dataclasses import dataclass
from alert_scanner.domain import Finding


def categorize(finding: Finding) -> Category:
    if finding.rule_id in _CATEGORY_BY_RULE:
        return _CATEGORY_BY_RULE[finding.rule_id]
    if finding.cwe_id is not None and finding.cwe_id in _CATEGORY_BY_CWE:
        return _CATEGORY_BY_CWE[finding.cwe_id]
    return OTHER


def focused_scan_rules() -> list[str]:
    """All active-scan rules from the catalog, sorted numerically."""
    return sorted({rule for category in CATEGORIES for rule in category.active_rules}, key=int)


@dataclass(frozen=True, slots=True)
class Category:
    key: str
    title: str
    owasp: str
    cwes: frozenset[int] = frozenset()
    # ZAP rules whose alerts belong to this category.
    alert_rules: frozenset[str] = frozenset()
    # Active-scan rules that look for this category. --mode focused runs only these.
    active_rules: frozenset[str] = frozenset()


CATEGORIES: tuple[Category, ...] = (
    Category(
        key="injection",
        title="Ktoś może włamać się do Twojej bazy danych",
        owasp="A03:2021 Injection",
        cwes=frozenset({89, 90, 78, 94, 643, 917, 943}),
        alert_rules=frozenset({"40018", "40019", "40020", "40021", "40022", "40024", "40027",
                           "90018", "90019", "90020", "90021", "40033"}),
        # Generic SQLi, SQLite, OS command and server-side code injection. The time-based
        # tests for specific databases (Oracle, MSSQL, ...) are left out: they are the slowest.
        active_rules=frozenset({"40018", "40024", "90019", "90020"}),
    ),
    Category(
        key="xss",
        title="Ktoś może uruchomić złośliwy kod w przeglądarkach Twoich odwiedzających",
        owasp="A03:2021 Injection",
        cwes=frozenset({79, 80}),
        alert_rules=frozenset({"40012", "40014", "40016", "40017", "40026"}),
        active_rules=frozenset({"40012", "40014", "40026"}),  # reflected, persistent, DOM
    ),
    Category(
        key="files",
        title="Ktoś może odczytać pliki, które powinny być prywatne",
        owasp="A01:2021 Broken Access Control",
        cwes=frozenset({22, 23, 36, 98, 527, 528, 530, 538, 548}),
        alert_rules=frozenset({"0", "6", "7", "40034", "40035", "10045", "10095"}),
        active_rules=frozenset({"0", "6", "7"}),  # directory listing, path traversal, remote file include
    ),
    Category(
        key="redirect",
        title="Ktoś może przekierować Twoich odwiedzających na fałszywą stronę",
        owasp="A01:2021 Broken Access Control",
        cwes=frozenset({601}),
        alert_rules=frozenset({"20019", "10028"}),
        active_rules=frozenset({"20019"}),
    ),
    Category(
        key="clickjacking",
        title="Ktoś może nakłonić odwiedzających do kliknięcia ukrytych przycisków",
        owasp="A05:2021 Security Misconfiguration",
        cwes=frozenset({1021}),
        alert_rules=frozenset({"10020"}),
    ),
    Category(
        key="cookies",
        title="Logowanie użytkowników jest słabo chronione",
        owasp="A07:2021 Identification and Authentication Failures",
        cwes=frozenset({614, 1004, 1275, 565, 315, 598, 384, 613}),
        alert_rules=frozenset({"10010", "10011", "10054", "90033", "3"}),
    ),
    Category(
        key="cross_site",
        title="Inna strona może działać w imieniu Twoich odwiedzających",
        owasp="A01:2021 Broken Access Control",
        cwes=frozenset({352, 942, 264, 346}),
        alert_rules=frozenset({"10098", "40040", "10202", "20012"}),
    ),
    Category(
        key="outdated",
        title="Strona używa przestarzałych składników ze znanymi lukami",
        owasp="A06:2021 Vulnerable and Outdated Components",
        cwes=frozenset({1395, 1104, 937, 1035}),
        alert_rules=frozenset({"10003"}),
    ),
    Category(
        key="headers",
        title="Zabezpieczenia przeglądarki nie są włączone",
        owasp="A05:2021 Security Misconfiguration",
        cwes=frozenset({693, 16}),
        alert_rules=frozenset({"10038", "10055", "10021", "10063", "90004"}),
    ),
    Category(
        key="info_leak",
        title="Strona ujawnia zbyt wiele informacji o sobie",
        owasp="A05:2021 Security Misconfiguration",
        cwes=frozenset({200, 209, 359, 497, 550, 615, 540, 541}),
        alert_rules=frozenset({"10036", "10037", "10096", "10027", "10023", "90022", "10024", "10062", "2"}),
    ),
    Category(
        key="third_party",
        title="Strona ufa skryptom z innych serwerów",
        owasp="A08:2021 Software and Data Integrity Failures",
        cwes=frozenset({829, 830, 345, 353}),
        alert_rules=frozenset({"10017", "90003"}),
    ),
    Category(
        key="transport",
        title="Ruch do strony nie jest w pełni szyfrowany",
        owasp="A02:2021 Cryptographic Failures",
        cwes=frozenset({311, 319, 326, 523}),
        alert_rules=frozenset({"10035", "10040", "10047"}),
    ),
)

OTHER = Category(key="other", title="Inny problem z konfiguracją", owasp="-")

_CATEGORY_BY_RULE = {rule: category for category in CATEGORIES for rule in category.alert_rules}
_CATEGORY_BY_CWE = {cwe: category for category in CATEGORIES for cwe in category.cwes}
