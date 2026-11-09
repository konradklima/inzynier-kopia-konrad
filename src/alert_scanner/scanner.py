"""Run OWASP ZAP in Docker against a live target.

Modes:
  baseline  zap-baseline.py, passive. Crawls the site and only inspects the responses
            (headers, cookies, leaked information). A few minutes, safe for any site.
  full      zap-full-scan.py, active with every attack rule. Slow (about 25 minutes on
            Juice Shop) and runs many tests that do not apply to the target.
  focused   ZAP Automation Framework plan, active but limited to the rules listed in
            catalog.py, with the crawl kept inside the target and time limits per rule.

Scopes:
  site      Scan the main page and all subpages discovered on the target domain.
  page      Scan only the given URL without crawling subpages.

Active modes send attacks. Run them only against sites you own or have written
permission to test (here: the local Juice Shop container).
"""

from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
import os
import re
import shutil
import subprocess
import tempfile
from enum import StrEnum
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlsplit
from urllib.request import Request, urlopen
from alert_scanner import catalog

# Defined before the functions because they are used as default argument values.
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
FOCUSED_SPIDER_MINUTES = 2
FOCUSED_AJAX_MINUTES = 3
FOCUSED_SCAN_MINUTES = 15
SPIDER_THREADS = 10
DISCOVERY_WORKERS = 8
DISCOVERY_MAX_PAGES = 60
DISCOVERY_TIMEOUT = 4.0


class ScanMode(StrEnum):
    BASELINE = "baseline"
    FULL = "full"
    FOCUSED = "focused"


class ScanScope(StrEnum):
    SITE = "site"   # main page and all discovered subpages
    PAGE = "page"   # only the target URL itself


def run_zap_scan(
    target: str,
    report_path: str | Path,
    mode: ScanMode = ScanMode.BASELINE,
    *,
    scope: ScanScope = ScanScope.SITE,
    ajax: bool = False,
    spider_minutes: int | None = None,
    max_scan_minutes: int | None = None,
    seed_urls: list[str] | None = None,
) -> Path:
    """Run ZAP, wait for it to finish and copy the JSON report to `report_path`.

    The ZAP scripts exit with a non-zero code when they find warnings, so the exit
    code is not an error signal. A missing report file is.
    """
    if shutil.which("docker") is None:
        raise ScanError("'docker' not found. Install and start Docker Desktop.")

    if seed_urls is None and scope is ScanScope.SITE:
        seed_urls = discover_subpages(target)

    # A temp dir gives an ASCII-only path. Docker on Windows has trouble mounting
    # folders with non-ASCII names, and the project folder has one.
    with tempfile.TemporaryDirectory(prefix="alert-scanner-zap-") as workdir:
        os.chmod(workdir, 0o777)  # ZAP runs as a different user inside the container
        if mode is ScanMode.FOCUSED:
            # --spider-minutes caps both spiders in focused mode.
            plan = build_focused_plan(
                target,
                scope=scope,
                ajax=ajax,
                spider_minutes=spider_minutes or FOCUSED_SPIDER_MINUTES,
                ajax_minutes=spider_minutes or FOCUSED_AJAX_MINUTES,
                max_scan_minutes=max_scan_minutes or FOCUSED_SCAN_MINUTES,
                seed_urls=seed_urls,
            )
            (Path(workdir) / _PLAN_FILE).write_text(plan, encoding="utf-8")
        elif scope is ScanScope.SITE and seed_urls:
            (Path(workdir) / _HOOK_FILE).write_text(
                _build_seed_hook(seed_urls), encoding="utf-8"
            )
        command = build_docker_command(
            target, mode, workdir,
            scope=scope, ajax=ajax, spider_minutes=spider_minutes,
            max_scan_minutes=max_scan_minutes,
            use_seed_hook=bool(mode is not ScanMode.FOCUSED and scope is ScanScope.SITE and seed_urls),
        )
        result = subprocess.run(command, check=False)  # ZAP output goes straight to the console
        if result.returncode == _DOCKER_ERROR_EXIT_CODE:
            raise ScanError(
                "Docker could not start the ZAP container (see the Docker error above). "
                "Restart Docker Desktop and check that there is free disk space."
            )

        produced_report = Path(workdir) / _REPORT_FILE
        if not produced_report.exists():
            raise ScanError(
                f"ZAP exited with code {result.returncode} and wrote no report. "
                "Check that the target is reachable from the container "
                "(e.g. http://host.docker.internal:3000)."
            )
        report_path = Path(report_path)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(produced_report, report_path)
    return report_path


def discover_subpages(
    target: str,
    *,
    max_pages: int = DISCOVERY_MAX_PAGES,
    timeout: float = DISCOVERY_TIMEOUT,
    workers: int = DISCOVERY_WORKERS,
) -> list[str]:
    """Quickly find subpages on any `target` via sitemaps, robots.txt and parallel HTML crawling."""
    base = _normalize_url(target)
    if not base:
        return [target]

    discovered: dict[str, None] = {base: None}
    origins = [_origin_root(base)]

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        # Follow redirects on the main URL first so www./https origins are included too.
        first_links, final_url = _fetch_links_with_redirect(base, target, timeout)
        if final_url and _same_site(final_url, target):
            discovered[final_url] = None
            final_origin = _origin_root(final_url)
            if final_origin not in origins:
                origins.append(final_origin)

        # 1. Check robots.txt and common sitemaps in parallel for instant subpage lists.
        sitemap_candidates: list[str] = []
        for origin in origins:
            for path in ("/sitemap.xml", "/wp-sitemap.xml", "/sitemap_index.xml"):
                sitemap_candidates.append(f"{origin}{path}")
        for body in pool.map(lambda origin: _fetch_text(f"{origin}/robots.txt", timeout), origins):
            for line in body.splitlines():
                if line.lower().startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    if sitemap_url and sitemap_url not in sitemap_candidates:
                        sitemap_candidates.append(sitemap_url)

        for url in _collect_sitemap_urls(sitemap_candidates, target, pool, timeout, max_pages):
            if len(discovered) >= max_pages:
                break
            discovered[url] = None

        for link in first_links:
            if len(discovered) >= max_pages:
                break
            discovered[link] = None

        # 2. Crawl pages in parallel breadth-first batches to discover linked subpages fast.
        visited: set[str] = {base}
        if final_url:
            visited.add(final_url)
        frontier = [url for url in discovered if url not in visited][:max_pages]
        while frontier and len(discovered) < max_pages:
            batch = frontier[: max(1, workers * 2)]
            frontier = frontier[len(batch) :]
            visited.update(batch)

            futures = [pool.submit(_fetch_links, url, target, timeout) for url in batch]
            for future in futures:
                for link in future.result():
                    if len(discovered) >= max_pages:
                        break
                    if link not in discovered:
                        discovered[link] = None
                        if link not in visited:
                            frontier.append(link)

    return list(discovered)


def build_docker_command(
    target: str,
    mode: ScanMode,
    workdir: str | Path,
    *,
    scope: ScanScope = ScanScope.SITE,
    ajax: bool = False,
    spider_minutes: int | None = None,
    max_scan_minutes: int | None = None,
    use_seed_hook: bool = False,
    image: str = ZAP_IMAGE,
) -> list[str]:
    command = ["docker", "run", "--rm", "-v", f"{workdir}:/zap/wrk/:rw", image]
    if mode is ScanMode.FOCUSED:
        # The plan file is written to workdir by run_zap_scan().
        return command + ["zap.sh", "-cmd", "-autorun", f"/zap/wrk/{_PLAN_FILE}"]

    command += [_ZAP_SCRIPTS[mode], "-t", target, "-J", _REPORT_FILE]
    if ajax and scope is ScanScope.SITE:
        command.append("-j")
    if spider_minutes is not None and scope is ScanScope.SITE:
        command += ["-m", str(spider_minutes)]
    if use_seed_hook:
        command += ["--hook", f"/zap/wrk/{_HOOK_FILE}"]

    zap_options = _zap_config_options(mode, scope, max_scan_minutes)
    if zap_options:
        command += ["-z", " ".join(zap_options)]
    return command


def build_focused_plan(
    target: str,
    *,
    scope: ScanScope = ScanScope.SITE,
    rules: list[str] | None = None,
    ajax: bool = True,
    spider_minutes: int = FOCUSED_SPIDER_MINUTES,
    ajax_minutes: int = FOCUSED_AJAX_MINUTES,
    max_scan_minutes: int = FOCUSED_SCAN_MINUTES,
    seed_urls: list[str] | None = None,
) -> str:
    """YAML plan for the ZAP Automation Framework.

    The context covers only the target, so third-party sites are neither crawled
    nor attacked. All active rules are switched off except `rules`. Each rule gets
    at most half of the total time, so one slow rule cannot use it all.
    """
    rules = rules if rules is not None else catalog.focused_scan_rules()
    urls = [target] if scope is ScanScope.PAGE else (seed_urls or [target])
    url_lines = "\n".join(f"        - {_yaml_quote(url)}" for url in dict.fromkeys([target, *urls]))
    scope_regex = _page_scope_regex(target) if scope is ScanScope.PAGE else _site_scope_regex(target)
    rule_lines = "\n".join(
        f"        - id: {rule}\n          threshold: medium" for rule in rules
    )
    if scope is ScanScope.PAGE:
        spider_jobs = f"""  - type: requestor
    parameters:
      requests:
        - url: {_yaml_quote(target)}"""
    else:
        ajax_job = f"""
  - type: spiderAjax
    parameters:
      context: target
      maxDuration: {ajax_minutes}
      inScopeOnly: true
      browserId: firefox-headless""" if ajax else ""
        spider_jobs = f"""  - type: spider
    parameters:
      context: target
      maxDuration: {spider_minutes}
      threadCount: {SPIDER_THREADS}
      parseSitemapXml: true
      parseRobotsTxt: true{ajax_job}"""
    return f"""env:
  contexts:
    - name: target
      urls:
{url_lines}
      includePaths:
        - {_yaml_quote(scope_regex)}
  parameters:
    failOnError: false
    failOnWarning: false
    progressToStdout: true
jobs:
  - type: passiveScan-config
    parameters:
      scanOnlyInScope: true
      maxAlertsPerRule: 10
{spider_jobs}
  - type: passiveScan-wait
    parameters:
      maxDuration: 5
  - type: activeScan
    parameters:
      context: target
      maxScanDurationInMins: {max_scan_minutes}
      maxRuleDurationInMins: {max(2, max_scan_minutes // 2)}
    policyDefinition:
      defaultStrength: medium
      defaultThreshold: "off"
      rules:
{rule_lines}
  - type: report
    parameters:
      template: traditional-json
      reportDir: /zap/wrk
      reportFile: {_REPORT_FILE}
"""


class ScanError(RuntimeError):
    """Docker is missing or ZAP did not produce a report."""


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("a", "area"):
            for name, value in attrs:
                if name == "href" and value:
                    self.hrefs.append(value.strip())


def _zap_config_options(
    mode: ScanMode, scope: ScanScope, max_scan_minutes: int | None
) -> list[str]:
    options: list[str] = []
    if scope is ScanScope.PAGE:
        options += ["-config", "spider.maxDepth=1", "-config", "spider.maxChildren=1"]
    else:
        options += [
            "-config", f"spider.threadCount={SPIDER_THREADS}",
            "-config", "spider.parseSitemapXml=true",
            "-config", "spider.parseRobotsTxt=true",
        ]
    if mode is ScanMode.FULL and max_scan_minutes is not None:
        options += ["-config", f"scanner.maxScanDurationInMins={max_scan_minutes}"]
    return options


def _build_seed_hook(seed_urls: list[str]) -> str:
    urls_literal = repr(seed_urls)
    return f"""SEED_URLS = {urls_literal}

def zap_started(zap, target):
    for url in SEED_URLS:
        try:
            zap.core.access_url(url=url, followredirects=True)
        except Exception:
            pass
"""


def _site_scope_regex(target: str) -> str:
    parts = urlsplit(target)
    host = (parts.hostname or "").lower().removeprefix("www.")
    if not host:
        return re.escape(target.rstrip("/")) + ".*"
    port = f":{parts.port}" if parts.port else ""
    return rf"^https?://([a-z0-9-]+\.)*{re.escape(host)}{port}(/.*)?$"


def _page_scope_regex(target: str) -> str:
    base = re.escape(target.rstrip("/"))
    return rf"^{base}/?(\?.*)?$"


def _collect_sitemap_urls(
    sitemap_urls: list[str],
    target: str,
    pool: ThreadPoolExecutor,
    timeout: float,
    limit: int,
) -> list[str]:
    found: list[str] = []
    nested_sitemaps: list[str] = []
    for body in pool.map(lambda url: _fetch_text(url, timeout), sitemap_urls):
        for loc in _SITEMAP_LOC.findall(body):
            url = _normalize_url(loc.strip())
            if not url or not _same_site(url, target):
                continue
            if url.endswith(".xml"):
                nested_sitemaps.append(url)
            else:
                found.append(url)
    for body in pool.map(lambda url: _fetch_text(url, timeout), nested_sitemaps[:5]):
        for loc in _SITEMAP_LOC.findall(body):
            url = _normalize_url(loc.strip())
            if url and not url.endswith(".xml") and _same_site(url, target):
                found.append(url)
                if len(found) >= limit:
                    return found
    return found[:limit]


def _fetch_links(page_url: str, target: str, timeout: float) -> list[str]:
    links, _ = _fetch_links_with_redirect(page_url, target, timeout)
    return links


def _fetch_links_with_redirect(page_url: str, target: str, timeout: float) -> tuple[list[str], str]:
    body, final_url = _fetch_html(page_url, timeout)
    norm_final = _normalize_url(final_url) if final_url else ""
    if not body:
        return [], norm_final
    parser = _LinkExtractor()
    try:
        parser.feed(body)
    except Exception:
        return [], norm_final
    links: list[str] = []
    base_url = norm_final or page_url
    for href in parser.hrefs:
        if href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        resolved = _normalize_url(urljoin(base_url, href))
        if resolved and _same_site(resolved, target) and not _SKIP_EXTENSIONS.search(resolved):
            links.append(resolved)
    return links, norm_final


def _fetch_text(url: str, timeout: float) -> str:
    body, _ = _fetch_raw(url, timeout, accept="text/plain,application/xml,text/xml,*/*")
    return body


def _fetch_html(url: str, timeout: float) -> tuple[str, str]:
    return _fetch_raw(url, timeout, accept="text/html,application/xhtml+xml")


def _fetch_raw(url: str, timeout: float, *, accept: str) -> tuple[str, str]:
    request = Request(url, headers={"User-Agent": "alert-scanner/0.1", "Accept": accept})
    try:
        with urlopen(request, timeout=timeout) as response:
            content_type = (response.headers.get("Content-Type") or "").lower()
            if "html" in accept and content_type and "html" not in content_type and "xml" not in content_type:
                return "", response.geturl()
            raw = response.read(512_000)
            return raw.decode("utf-8", errors="ignore"), response.geturl()
    except Exception:
        return "", url


def _normalize_url(url: str) -> str:
    clean, _ = urldefrag(url.strip())
    parts = urlsplit(clean)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return ""
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{path}{query}"


def _origin_root(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def _same_site(url: str, target: str) -> bool:
    url_host = (urlsplit(url).hostname or "").lower().removeprefix("www.")
    target_host = (urlsplit(target).hostname or "").lower().removeprefix("www.")
    if not url_host or not target_host:
        return False
    return url_host == target_host or url_host.endswith("." + target_host)


def _yaml_quote(value: str) -> str:
    # Single-quoted YAML: backslashes stay literal, quotes are doubled.
    return "'" + value.replace("'", "''") + "'"


_REPORT_FILE = "zap-report.json"
_PLAN_FILE = "plan.yaml"
_HOOK_FILE = "seed_hook.py"
# `docker run` exits with 125 when Docker itself fails, before ZAP starts.
# The ZAP scripts use 0-3, so the codes cannot be confused.
_DOCKER_ERROR_EXIT_CODE = 125
_ZAP_SCRIPTS = {
    ScanMode.BASELINE: "zap-baseline.py",
    ScanMode.FULL: "zap-full-scan.py",
}
_SITEMAP_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
_SKIP_EXTENSIONS = re.compile(
    r"\.(?:jpg|jpeg|png|gif|webp|svg|ico|css|js|woff2?|ttf|eot|pdf|zip|rar|mp4|mp3)(?:\?|$)",
    re.IGNORECASE,
)
