"""Training samples from the saved ZAP reports plus our hand-made labels.

One sample is one instance of a finding (a URL and parameter where the scanner
saw the issue). The reports in reports/ are named zap-<mode>-<app>[-ajax].json,
so the file name tells us the scan mode and the target app.

Labels live in data/labels/<person>.csv, one file per team member. todo.csv and
calibration.csv in the same folder are empty templates and are never read as labels.
prelabels.csv holds pre-labels: they count only for rows that no team member has
labeled, so a team label always wins.
A sample is matched to its label by a fingerprint (app, rule, method, path, param),
so a label survives rescans: the same hole on the same page keeps its label.
"""

from __future__ import annotations
import csv
import hashlib
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
from alert_scanner import catalog
from alert_scanner.domain import Finding, Instance, Verdict
from alert_scanner.zap_parser import guess_target, load_report, parse_report

LABEL_TO_VERDICT = {
    "real": Verdict.REAL,
    "noise": Verdict.NOISE,
    "false_positive": Verdict.FALSE_POSITIVE,
}
TEMPLATE_SHEETS = frozenset({"todo", "calibration"})
PRELABEL_SHEETS = frozenset({"prelabels"})
LABEL_COLUMNS = ("fingerprint", "app", "mode", "rule_id", "name", "severity", "confidence",
                 "method", "path", "param", "attack", "evidence", "other_info", "label", "note",
                 "url")  # url last, so rows from a newer sheet still line up with an older copy


@dataclass(frozen=True, slots=True)
class Sample:
    app: str
    mode: str
    finding: Finding
    instance: Instance

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.app, self.finding, self.instance)

    @property
    def path(self) -> str:
        return normalized_path(self.instance.location.uri)


@dataclass(frozen=True, slots=True)
class LabeledSample:
    sample: Sample
    verdict: Verdict
    votes: dict[Verdict, int]
    human_checked: bool = True

    @property
    def agreed(self) -> bool:
        return len(self.votes) == 1


def load_samples(reports_dir: str | Path) -> list[Sample]:
    """All instances from every zap-<mode>-<app>.json report, sorted for stable output."""
    samples = []
    for report_path in sorted(Path(reports_dir).glob("zap-*.json")):
        samples.extend(samples_from_report(report_path))
    return samples


def samples_from_report(report_path: str | Path) -> list[Sample]:
    report_path = Path(report_path)
    mode, app = _mode_and_app(report_path.name)
    report = load_report(report_path)
    findings = parse_report(report, guess_target(report))
    return [
        Sample(app, mode, finding, instance)
        for finding in findings
        for instance in finding.instances
    ]


def fingerprint(app: str, finding: Finding, instance: Instance) -> str:
    key = "|".join([
        app, finding.rule_id, instance.location.method.upper(),
        normalized_path(instance.location.uri), instance.location.param,
    ])
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]


def normalized_path(uri: str) -> str:
    """Path without host and query values; numeric ids become {id}.

    /rest/products/42/reviews?limit=5 -> /rest/products/{id}/reviews?limit
    """
    parts = urlsplit(uri)
    path = _NUMERIC_SEGMENT.sub("/{id}", parts.path or "/")
    if parts.fragment.startswith("/"):
        path = path.rstrip("/") + "/#" + parts.fragment.split("?")[0]
    query_keys = sorted({pair.split("=")[0] for pair in parts.query.split("&") if pair})
    return path + ("?" + "&".join(query_keys) if query_keys else "")


def write_label_sheet(samples: list[Sample], path: str | Path) -> int:
    """CSV with one row per unique fingerprint; `label` is left empty to fill in by hand."""
    rows = {sample.fingerprint: _sheet_row(sample) for sample in unique_samples(samples)}
    ordered = sorted(rows.values(), key=lambda row: (row["app"], -int(row["severity"]), row["rule_id"], row["path"]))
    with open(path, "w", newline="", encoding="utf-8") as sheet:
        writer = csv.DictWriter(sheet, fieldnames=LABEL_COLUMNS)
        writer.writeheader()
        writer.writerows(ordered)
    return len(ordered)


def read_labels(labels_dir: str | Path) -> dict[str, dict[str, Verdict]]:
    """fingerprint -> {person: verdict}, from every CSV in the labels directory."""
    labels: dict[str, dict[str, Verdict]] = {}
    for sheet_path in sorted(Path(labels_dir).glob("*.csv")):
        person = sheet_path.stem
        if person in TEMPLATE_SHEETS:
            continue
        with open(sheet_path, newline="", encoding="utf-8") as sheet:
            for row in csv.DictReader(sheet):
                # "false-positive" and "false positive" are typos of the same label.
                label = (row.get("label") or "").strip().lower().replace("-", "_").replace(" ", "_")
                if not label:
                    continue
                if label not in LABEL_TO_VERDICT:
                    raise ValueError(f"{sheet_path}: unknown label {label!r} for {row.get('fingerprint')}")
                labels.setdefault(row["fingerprint"], {})[person] = LABEL_TO_VERDICT[label]
    return labels


def labeled_samples(samples: list[Sample], labels: dict[str, dict[str, Verdict]]) -> list[LabeledSample]:
    """One labeled sample per fingerprint. The majority vote wins; ties go to the
    more cautious verdict (real before noise before false positive).

    If any team member labeled the row, only the team's votes count; the pre-label is
    used only for rows nobody has checked yet.
    """
    result = []
    for sample in unique_samples(samples):
        votes = labels.get(sample.fingerprint)
        if not votes:
            continue
        human_votes = {person: v for person, v in votes.items() if person not in PRELABEL_SHEETS}
        counts = Counter((human_votes or votes).values())
        verdict = min(counts, key=lambda v: (-counts[v], int(v)))
        result.append(LabeledSample(sample, verdict, dict(counts), human_checked=bool(human_votes)))
    return result


def unique_samples(samples: list[Sample]) -> list[Sample]:
    """One sample per fingerprint, so a page seen in several scans counts once.

    Without this the same row would be trained on and scored several times. We keep
    the copy from the most thorough scan: an active scan carries the attack and the
    evidence, a passive one does not.
    """
    best: dict[str, Sample] = {}
    for sample in samples:
        current = best.get(sample.fingerprint)
        if current is None or _thoroughness(sample) < _thoroughness(current):
            best[sample.fingerprint] = sample
    return list(best.values())


def calibration_samples(samples: list[Sample], size: int) -> list[Sample]:
    """A spread-out subset for the whole team to label, to measure agreement.

    Takes one sample at a time from each (app, category) group in turn, so the
    subset covers every app and every kind of alert instead of the first rows.
    """
    groups: dict[tuple[str, str], list[Sample]] = {}
    for sample in sorted(unique_samples(samples), key=lambda s: (s.finding.rule_id, s.path, s.fingerprint)):
        groups.setdefault((sample.app, catalog.categorize(sample.finding).key), []).append(sample)
    queues = [groups[key] for key in sorted(groups)]
    picked: list[Sample] = []
    while len(picked) < size and any(queues):
        for queue in queues:
            if queue and len(picked) < size:
                picked.append(queue.pop(0))
    return picked


def _thoroughness(sample: Sample) -> tuple[int, int]:
    """Lower is better: full scan first, then a sample that has an attack payload."""
    return _MODE_ORDER.get(sample.mode, len(_MODE_ORDER)), int(not sample.instance.attack)


def _sheet_row(sample: Sample) -> dict[str, str]:
    finding, instance = sample.finding, sample.instance
    return {
        "fingerprint": sample.fingerprint,
        "app": sample.app,
        "mode": sample.mode,
        "rule_id": finding.rule_id,
        "name": finding.name,
        "severity": str(int(finding.severity)),
        "confidence": str(int(finding.confidence)),
        "method": instance.location.method,
        "path": sample.path,
        "param": instance.location.param,
        "attack": _one_line(instance.attack, 120),
        "evidence": _one_line(instance.evidence, 160),
        "other_info": _one_line(instance.other_info, 160),
        "label": "",
        "note": "",
        # ZAP scans from a container; on our own machine the same app is on localhost.
        "url": instance.location.uri.replace("host.docker.internal", "localhost"),
    }


def _mode_and_app(file_name: str) -> tuple[str, str]:
    match = _REPORT_NAME.match(file_name)
    if not match:
        raise ValueError(f"{file_name}: expected zap-<mode>-<app>.json")
    mode, app = match.group("mode"), match.group("app")
    return mode, app.removesuffix("-ajax")


def _one_line(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


_MODE_ORDER = {"full": 0, "focused": 1, "baseline": 2}
_REPORT_NAME = re.compile(r"^zap-(?P<mode>baseline|full|focused)-(?P<app>[a-z0-9-]+)\.json$")
_NUMERIC_SEGMENT = re.compile(r"/\d+(?=/|$)")
