import io
import json
import pytest
from alert_scanner.domain import Confidence, Finding, Instance, Location, Severity, Verdict
from alert_scanner.storage import Storage
from alert_scanner.web import InvalidAddress, ScanJob, make_handler, normalize_address


@pytest.mark.parametrize("raw, expected", [
    ("przyklad.pl", "http://przyklad.pl"),
    ("  https://moja-strona.com/sklep  ", "https://moja-strona.com/sklep"),
    ("localhost:3000", "http://host.docker.internal:3000"),
    ("http://127.0.0.1:8080/app", "http://host.docker.internal:8080/app"),
])
def test_normalize_address(raw, expected):
    assert normalize_address(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "ftp://example.com", "http://", "example.com:99999"])
def test_normalize_address_rejects_bad_input(raw):
    with pytest.raises(InvalidAddress):
        normalize_address(raw)


def test_delete_scan_via_storage_and_api(tmp_path):
    db_path = tmp_path / "test.db"
    finding = Finding(
        rule_id="40018",
        name="SQL Injection",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(uri="http://example.com/search", param="q"),
        instances=(Instance(location=Location(uri="http://example.com/search", param="q")),),
        verdict=Verdict.REAL,
        rank=1,
    )
    with Storage(db_path) as db:
        scan_id = db.save_scan("http://example.com", [finding])

    handler_cls = make_handler(str(db_path), ScanJob(str(db_path), tmp_path))

    def call_delete(path: str) -> tuple[int, dict]:
        handler = handler_cls.__new__(handler_cls)
        handler.path = path
        handler.wfile = io.BytesIO()
        statuses = []
        handler.send_response = lambda code: statuses.append(code)
        handler.send_header = lambda *args: None
        handler.end_headers = lambda: None
        handler.do_DELETE()
        return statuses[0], json.loads(handler.wfile.getvalue().decode("utf-8"))

    status, body = call_delete(f"/api/scans/{scan_id}")
    assert status == 200 and body == {"deleted": scan_id}

    status_missing, _ = call_delete(f"/api/scans/{scan_id}")
    assert status_missing == 404

    with Storage(db_path) as db:
        assert db.list_scans() == []
        assert db.load_findings(scan_id) == []
