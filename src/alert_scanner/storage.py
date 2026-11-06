"""Scan history in SQLite (standard library only).

Two tables: `scans` (one scanner run) and `findings` (its findings after the risk
assessment). The stored findings are also the training data for the ML classifier.
"""

from __future__ import annotations
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from alert_scanner.domain import Confidence, Finding, Location, Severity, Verdict


class Storage:
    """Usage: with Storage("scans.db") as db: scan_id = db.save_scan(target, findings)"""

    def __init__(self, path: str | Path) -> None:
        self._connection = sqlite3.connect(str(path))
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.executescript(_SCHEMA)

    def save_scan(self, target: str, findings: list[Finding]) -> int:
        """Save the scan and its findings in one transaction. Returns the scan id."""
        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._connection:
            cursor = self._connection.execute(
                "INSERT INTO scans (target, created_at) VALUES (?, ?)", (target, created_at)
            )
            scan_id = cursor.lastrowid
            placeholders = ", ".join("?" * (len(_FINDING_COLUMNS) + 1))
            self._connection.executemany(
                f"INSERT INTO findings (scan_id, {_COLUMN_LIST}) VALUES ({placeholders})",
                [(scan_id, *_finding_to_row(finding)) for finding in findings],
            )
        return scan_id

    def load_findings(self, scan_id: int) -> list[Finding]:
        """Real findings by rank first, then the filtered ones."""
        rows = self._connection.execute(
            f"SELECT {_COLUMN_LIST} FROM findings WHERE scan_id = ? "
            "ORDER BY rank IS NULL, rank, id",
            (scan_id,),
        ).fetchall()
        return [_row_to_finding(row) for row in rows]

    def scan_target(self, scan_id: int) -> str | None:
        row = self._connection.execute(
            "SELECT target FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        return row[0] if row else None

    def list_scans(self) -> list[ScanSummary]:
        """Newest first."""
        rows = self._connection.execute(
            """
            SELECT s.id, s.target, s.created_at,
                   COUNT(f.id),
                   COALESCE(SUM(f.verdict = ?), 0)
            FROM scans s LEFT JOIN findings f ON f.scan_id = s.id
            GROUP BY s.id ORDER BY s.id DESC
            """,
            (int(Verdict.REAL),),
        ).fetchall()
        return [ScanSummary(*row) for row in rows]

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> Storage:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class ScanSummary:
    id: int
    target: str
    created_at: str
    finding_count: int
    real_count: int


def _finding_to_row(finding: Finding) -> tuple:
    return (
        finding.rule_id, finding.name, int(finding.severity), int(finding.confidence),
        finding.location.uri, finding.location.method, finding.location.param,
        finding.cwe_id, finding.wasc_id, finding.description, finding.solution,
        finding.occurrences, finding.attack, finding.evidence,
        None if finding.verdict is None else int(finding.verdict), finding.rank,
    )


def _row_to_finding(row: tuple) -> Finding:
    (rule_id, name, severity, confidence, uri, method, param, cwe_id, wasc_id,
     description, solution, occurrences, attack, evidence, verdict, rank) = row
    return Finding(
        rule_id=rule_id,
        name=name,
        severity=Severity(severity),
        confidence=Confidence(confidence),
        location=Location(uri=uri, method=method, param=param),
        cwe_id=cwe_id,
        wasc_id=wasc_id,
        description=description,
        solution=solution,
        occurrences=occurrences,
        attack=attack,
        evidence=evidence,
        verdict=None if verdict is None else Verdict(verdict),
        rank=rank,
    )


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id     TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    severity    INTEGER NOT NULL,
    confidence  INTEGER NOT NULL,
    uri         TEXT    NOT NULL,
    method      TEXT    NOT NULL,
    param       TEXT    NOT NULL,
    cwe_id      INTEGER,
    wasc_id     INTEGER,
    description TEXT    NOT NULL,
    solution    TEXT    NOT NULL,
    occurrences INTEGER NOT NULL,
    attack      TEXT    NOT NULL,
    evidence    TEXT    NOT NULL,
    verdict     INTEGER,
    rank        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""

_FINDING_COLUMNS = (
    "rule_id", "name", "severity", "confidence", "uri", "method", "param", "cwe_id", "wasc_id",
    "description", "solution", "occurrences", "attack", "evidence", "verdict", "rank",
)
_COLUMN_LIST = ", ".join(_FINDING_COLUMNS)
