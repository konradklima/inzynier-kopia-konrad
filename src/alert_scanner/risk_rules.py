"""Rule-based risk assessment.

Two jobs: decide if a finding is real, noise or a false positive, and rank the real
ones. The rules only use the scanner's own severity and confidence. They are the
baseline that the planned ML classifier will be measured against.

Called from cli.py right after parsing: assess(parse_report(report, target)).
"""

from __future__ import annotations
from collections import Counter
from dataclasses import dataclass, field
from alert_scanner.domain import Confidence, Finding, Severity, Verdict

# TODO: ML classifier trained on labeled findings. It replaces classify_with_reason(),
#       assess() stays as it is. Compare it with these rules (precision, recall, F1).
# TODO: use the content of a finding (evidence, response code, path), not only severity
#       and confidence. Now an open redirect ranks above SQL injection only because
#       ZAP is more confident about it.
# TODO: merge duplicates, e.g. External Redirect and Off-site Redirect on the same URL.
# TODO: agent pipeline: pass the ranked findings to the agents that fill in the
#       animation templates (one writes the texts, the other reviews them).


def assess(findings: list[Finding]) -> Assessment:
    """Classify every finding and rank the real ones (rank 1 = most urgent)."""
    by_verdict: dict[Verdict, list[Finding]] = {verdict: [] for verdict in Verdict}
    for finding in findings:
        by_verdict[classify(finding)].append(finding)

    # Ties: more occurrences first, then the name so the order is stable.
    ranked = sorted(
        by_verdict[Verdict.REAL],
        key=lambda finding: (-priority_score(finding), -finding.occurrences, finding.name),
    )
    return Assessment(
        real=[
            finding.with_assessment(Verdict.REAL, rank)
            for rank, finding in enumerate(ranked, start=1)
        ],
        noise=[finding.with_assessment(Verdict.NOISE, None) for finding in by_verdict[Verdict.NOISE]],
        false_positives=[
            finding.with_assessment(Verdict.FALSE_POSITIVE, None)
            for finding in by_verdict[Verdict.FALSE_POSITIVE]
        ],
    )


def classify(finding: Finding) -> Verdict:
    return classify_with_reason(finding)[0]


def classify_with_reason(finding: Finding) -> tuple[Verdict, str]:
    """The first matching rule wins."""
    if finding.confidence == Confidence.FALSE_POSITIVE:
        return Verdict.FALSE_POSITIVE, "marked as a false positive by the scanner"
    if finding.severity == Severity.INFO:
        return Verdict.NOISE, "informational, not a threat by itself"
    if finding.severity == Severity.LOW and finding.confidence == Confidence.LOW:
        return Verdict.NOISE, "low risk and low scanner confidence"
    return Verdict.REAL, f"{finding.severity.label} risk, {finding.confidence.label} confidence"


def priority_score(finding: Finding) -> int:
    """0-34. Severity decides, confidence breaks ties within the same severity."""
    return int(finding.severity) * 10 + int(finding.confidence)


@dataclass(frozen=True, slots=True)
class Assessment:
    real: list[Finding] = field(default_factory=list)
    noise: list[Finding] = field(default_factory=list)
    false_positives: list[Finding] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.real) + self.filtered_out

    @property
    def filtered_out(self) -> int:
        return len(self.noise) + len(self.false_positives)

    @property
    def filtered_out_pct(self) -> float:
        return 100.0 * self.filtered_out / self.total if self.total else 0.0

    def count_by_severity(self) -> dict[Severity, int]:
        """Real findings per severity, highest first, zeros included."""
        counts = Counter(finding.severity for finding in self.real)
        return {severity: counts.get(severity, 0) for severity in sorted(Severity, reverse=True)}

    def all_findings(self) -> list[Finding]:
        return [*self.real, *self.noise, *self.false_positives]
