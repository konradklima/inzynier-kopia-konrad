"""Features of one sample for the classifier.

The rules in risk_rules.py see only severity and confidence. The classifier also
sees what the finding looks like: where it is (an API endpoint or a static file),
whether the scanner actually attacked it, and what the response contained.
Every feature is a number or a short string; strings are one-hot encoded by the
model pipeline. No third-party code here, so the features are testable without ML.
"""

from __future__ import annotations
import re
from alert_scanner import catalog
from alert_scanner.ml.dataset import Sample

# Extensions of URLs that render a page; anything else with an extension is a file.
PAGE_EXTENSIONS = frozenset({"html", "htm", "php", "jsp", "asp", "aspx", "mvc", "do"})
STATIC_EXTENSIONS = frozenset({
    "js", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf",
    "eot", "mp3", "mp4", "pdf", "txt", "xml", "json", "webmanifest",
})


def extract(sample: Sample) -> dict[str, float | str]:
    finding, instance = sample.finding, sample.instance
    location = instance.location
    path = sample.path
    evidence = instance.evidence
    return {
        # what the scanner says
        "rule_id": finding.rule_id,
        "category": catalog.categorize(finding).key,
        "severity": float(finding.severity),
        "confidence": float(finding.confidence),
        "cwe": str(finding.cwe_id or 0),
        "scan_mode": sample.mode,
        "occurrences": float(finding.occurrences),
        "instances": float(len(finding.instances)),
        # where it is
        "method": location.method.upper(),
        "has_param": float(bool(location.param)),
        "param_kind": _param_kind(location.param),
        "path_depth": float(path.count("/")),
        "is_static_asset": float(_extension(path) in STATIC_EXTENSIONS),
        "is_file": float(_is_file(path)),
        "is_api_path": float(bool(_API_PATH.search(path))),
        "is_spa_route": float("/#/" in path),
        "is_root": float(path in ("/", "/#/")),
        # what proved it
        "has_attack": float(bool(instance.attack)),
        "attack_len": float(len(instance.attack)),
        "evidence_len": float(len(evidence)),
        "evidence_is_header": float(bool(_HEADER.match(evidence))),
        "evidence_is_number": float(evidence.strip().isdigit()),
        "evidence_sql_error": float(bool(_SQL_ERROR.search(evidence))),
        "evidence_server_error": float(bool(_SERVER_ERROR.search(evidence))),
        "evidence_has_html": float("<" in evidence and ">" in evidence),
        "evidence_has_url": float("http" in evidence.lower()),
        "has_other_info": float(bool(instance.other_info)),
    }


def feature_names() -> list[str]:
    return list(_EMPTY_FEATURES)


def _param_kind(param: str) -> str:
    if not param:
        return "none"
    lowered = param.lower()
    if lowered in _AUTH_PARAMS:
        return "auth"
    if lowered in _SEARCH_PARAMS:
        return "search"
    if lowered.endswith("id") or lowered == "id":
        return "id"
    if "-" in param or param.lower().startswith(("x-", "content-", "set-")):
        return "header"
    return "other"


def _is_file(path: str) -> bool:
    """A downloadable file (.bak, .pyc, .yml, .js...), not a page. A missing header
    matters on a page and hardly at all on a file, so this decides many labels.
    Stack-trace paths such as fileServer.js:52:13 are app routes, not files."""
    extension = _extension(path)
    return bool(extension) and extension not in PAGE_EXTENSIONS and ":" not in extension


def _extension(path: str) -> str:
    last_segment = path.split("?")[0].rsplit("/", 1)[-1]
    return last_segment.rsplit(".", 1)[-1].lower() if "." in last_segment else ""


_AUTH_PARAMS = frozenset({"email", "password", "username", "user", "login", "token", "passwd"})
_SEARCH_PARAMS = frozenset({"q", "query", "search", "s", "term", "filter"})
_API_PATH = re.compile(r"/(rest|api|graphql|json|v\d+)(/|$)")
_HEADER = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:\s")
_SQL_ERROR = re.compile(r"SQL|sqlite|syntax error|ORA-\d|mysql|postgres|unterminated|near \"", re.IGNORECASE)
_SERVER_ERROR = re.compile(r"HTTP/1\.[01] 5\d\d|Internal Server Error|stack ?trace|Exception", re.IGNORECASE)

_EMPTY_FEATURES = (
    "rule_id", "category", "severity", "confidence", "cwe", "scan_mode", "occurrences",
    "instances", "method", "has_param", "param_kind", "path_depth", "is_static_asset", "is_file",
    "is_api_path", "is_spa_route", "is_root", "has_attack", "attack_len", "evidence_len",
    "evidence_is_header", "evidence_is_number", "evidence_sql_error", "evidence_server_error",
    "evidence_has_html", "evidence_has_url", "has_other_info",
)
