"""Scanner-independent data model.

A scanner adapter (currently zap_parser) turns its report into Finding objects.
The rest of the code works only with this model, never with the scanner format.
"""

from __future__ import annotations
from dataclasses import dataclass, field, replace
from enum import IntEnum
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class Finding:
    """One issue type found on the target.

    `rule_id` is the id of the scanner rule that raised the alert.
    `attack` and `evidence` come from the first occurrence: the payload the scanner
    sent and the part of the response that confirmed the issue.
    `verdict` and `rank` stay None until risk_rules.assess() runs. `rank` is the place
    on the list (1 = fix first) and stays None for filtered findings.
    """

    rule_id: str
    name: str
    severity: Severity
    confidence: Confidence
    location: Location
    cwe_id: int | None = None
    wasc_id: int | None = None
    description: str = ""
    solution: str = ""
    occurrences: int = 1
    attack: str = ""
    evidence: str = ""
    verdict: Verdict | None = None
    rank: int | None = None
    locations: tuple[Location, ...] = field(default=(), compare=False)

    def with_assessment(self, verdict: Verdict, rank: int | None) -> Finding:
        return replace(self, verdict=verdict, rank=rank)

    def all_locations(self) -> tuple[Location, ...]:
        return self.locations if self.locations else (self.location,)


@dataclass(frozen=True, slots=True)
class Location:
    uri: str
    method: str = "GET"
    param: str = ""

    def page_path(self) -> str:
        """Page path without query or parameter, e.g. '/zamow-probki/'."""
        parts = urlsplit(self.uri)
        path = parts.path or "/"
        if parts.fragment.startswith("/"):
            path = path.rstrip("/") + "/#" + parts.fragment.split("?")[0]
        return path

    def short_path(self) -> str:
        """Path without scheme and host, e.g. '/api/login [email]'."""
        path = self.page_path()
        return f"{path} [{self.param}]" if self.param else path


class Severity(IntEnum):
    """How dangerous the issue is. Same scale as ZAP `riskcode`."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.lower()


class Confidence(IntEnum):
    """How sure the scanner is that the issue is real. Same scale as ZAP `confidence`."""

    FALSE_POSITIVE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CONFIRMED = 4

    @property
    def label(self) -> str:
        return self.name.lower().replace("_", " ")


class Verdict(IntEnum):
    """Our decision about a finding, made in risk_rules (not by the scanner)."""

    REAL = 0
    NOISE = 1
    FALSE_POSITIVE = 2

    @property
    def label(self) -> str:
        return self.name.lower().replace("_", " ")
