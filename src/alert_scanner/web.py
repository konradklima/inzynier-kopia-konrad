"""Centrum sterowania: prosty pulpit w przeglądarce (tylko biblioteka standardowa).

    alert-scanner-web            # http://127.0.0.1:8000
    alert-scanner-web --port 9000 --db scans.db

Pole adresu przyjmuje dowolny adres strony. Skan działa w tle (ZAP w Dockerze),
wyniki trafiają do tej samej bazy SQLite co z linii poleceń.
"""

from __future__ import annotations
import argparse
import json
import re
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from alert_scanner import catalog, pl_texts
from alert_scanner.domain import Finding, Severity, Verdict
from alert_scanner.risk_rules import assess
from alert_scanner.scanner import ScanError, ScanMode, run_zap_scan
from alert_scanner.storage import Storage
from alert_scanner.web_page import PAGE
from alert_scanner.zap_parser import ZapReportError, load_report, parse_report

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


class InvalidAddress(ValueError):
    pass


def normalize_address(raw: str) -> str:
    """Zamienia dowolny wpis użytkownika na adres, który ZAP (w Dockerze) potrafi otworzyć.

    "przyklad.pl" -> "http://przyklad.pl"; "localhost:3000" -> "http://host.docker.internal:3000".
    """
    text = (raw or "").strip()
    if not text:
        raise InvalidAddress("Wpisz adres strony.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text):
        text = "http://" + text
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https"):
        raise InvalidAddress("Obsługiwane są tylko adresy http:// i https://.")
    try:
        host, _ = parts.hostname, parts.port
    except ValueError:
        raise InvalidAddress("Nieprawidłowy numer portu.") from None
    if not host:
        raise InvalidAddress("Nieprawidłowy adres.")
    if host in _LOCAL_HOSTS:
        netloc = "host.docker.internal" + (f":{parts.port}" if parts.port else "")
        text = parts._replace(netloc=netloc).geturl()
    return text


class ScanJob:
    """Jeden skan naraz. Stan jest czytany przez przeglądarkę co sekundę."""

    def __init__(self, db_path: str, reports_dir: Path) -> None:
        self.db_path = db_path
        self.reports_dir = reports_dir
        self._lock = threading.Lock()
        self._state: dict = {"state": "idle"}

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._state)

    def start(self, target: str, mode: ScanMode, ajax: bool) -> bool:
        with self._lock:
            if self._state.get("state") == "running":
                return False
            self._state = {"state": "running", "target": target, "mode": mode.value,
                           "started": datetime.now().isoformat(timespec="seconds")}
        threading.Thread(target=self._run, args=(target, mode, ajax), daemon=True).start()
        return True

    def _run(self, target: str, mode: ScanMode, ajax: bool) -> None:
        try:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            report_path = self.reports_dir / f"zap-{mode.value}-{stamp}.json"
            run_zap_scan(target, report_path, mode, ajax=ajax)
            assessment = assess(parse_report(load_report(report_path), target))
            with Storage(self.db_path) as db:
                scan_id = db.save_scan(target, assessment.all_findings())
            result = {"state": "done", "scan_id": scan_id}
        except (ScanError, ZapReportError, OSError) as error:
            result = {"state": "error", "error": str(error)}
        except Exception as error:  # wątek w tle nie może zginąć po cichu
            result = {"state": "error", "error": f"Nieoczekiwany błąd: {error}"}
        with self._lock:
            self._state = {**self._state, **result}


_TIER = {
    Severity.HIGH: ("Pilne", "high"),
    Severity.MEDIUM: ("Ważne", "medium"),
    Severity.LOW: ("Warto poprawić", "low"),
    Severity.INFO: ("Warto poprawić", "low"),
}


def finding_to_json(finding: Finding) -> dict:
    category = catalog.categorize(finding)
    label, tier = _TIER[finding.severity]
    return {
        "rank": finding.rank,
        "title": category.title,
        "name": pl_texts.alert_name(finding.rule_id, finding.name),
        "owasp": pl_texts.owasp(category.owasp),
        "cwe": finding.cwe_id,
        "path": finding.location.short_path(),
        "uri": finding.location.uri,
        "severity": finding.severity.pl,
        "tier": tier,
        "tier_label": label,
        "confidence": finding.confidence.pl,
        "occurrences": finding.occurrences,
        "description": pl_texts.category_texts(category.key)[0],
        "solution": pl_texts.category_texts(category.key)[1],
        "verdict": finding.verdict.pl if finding.verdict is not None else "",
    }


def scan_to_json(db: Storage, scan_id: int) -> dict | None:
    target = db.scan_target(scan_id)
    if target is None:
        return None
    findings = db.load_findings(scan_id)
    real = sorted((f for f in findings if f.verdict == Verdict.REAL), key=lambda f: f.rank or 0)
    noise = [f for f in findings if f.verdict != Verdict.REAL]
    summary = next((s for s in db.list_scans() if s.id == scan_id), None)
    return {
        "id": scan_id,
        "target": target,
        "created_at": summary.created_at if summary else "",
        "real": [finding_to_json(f) for f in real],
        "noise_count": len(noise),
        "history": [
            {"id": s.id, "target": s.target, "created_at": s.created_at, "real": s.real_count}
            for s in reversed(db.list_scans()[:12])
        ],
    }


def make_handler(db_path: str, job: ScanJob):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:
            pass

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, payload, status: int = 200) -> None:
            self._send(status, json.dumps(payload, ensure_ascii=False).encode(),
                       "application/json; charset=utf-8")

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/":
                self._send(200, PAGE.encode(), "text/html; charset=utf-8")
            elif path == "/api/job":
                self._json(job.snapshot())
            elif path == "/api/scans":
                with Storage(db_path) as db:
                    scans = db.list_scans()
                self._json([{"id": s.id, "target": s.target, "created_at": s.created_at,
                             "real": s.real_count} for s in scans])
            elif m := re.fullmatch(r"/api/scans/(\d+)", path):
                with Storage(db_path) as db:
                    data = scan_to_json(db, int(m.group(1)))
                self._json(data, 200) if data else self._json({"error": "Nie ma takiego skanu."}, 404)
            else:
                self._json({"error": "Nie znaleziono."}, 404)

        def do_POST(self) -> None:
            if urlsplit(self.path).path != "/api/scan":
                return self._json({"error": "Nie znaleziono."}, 404)
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                target = normalize_address(body.get("url", ""))
                mode = ScanMode(body.get("mode", "baseline"))
            except InvalidAddress as error:
                return self._json({"error": str(error)}, 400)
            except (ValueError, json.JSONDecodeError):
                return self._json({"error": "Nieprawidłowe dane skanu."}, 400)
            if body.get("consent") is not True:
                return self._json({"error": "Potwierdź, że strona należy do Ciebie albo masz zgodę jej właściciela."}, 400)
            if not job.start(target, mode, bool(body.get("ajax"))):
                return self._json({"error": "Inny skan jest jeszcze w toku."}, 409)
            self._json({"target": target}, 202)

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="alert-scanner-web", description="Centrum sterowania w przeglądarce.")
    parser.add_argument("--host", default="127.0.0.1", help="adres nasłuchu (domyślnie tylko ten komputer)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--db", default="scans.db")
    parser.add_argument("--reports-dir", default="reports")
    args = parser.parse_args(argv)
    job = ScanJob(args.db, Path(args.reports_dir))
    server = ThreadingHTTPServer((args.host, args.port), make_handler(args.db, job))
    print(f"Centrum sterowania: http://{args.host}:{args.port}  (Ctrl+C kończy)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
