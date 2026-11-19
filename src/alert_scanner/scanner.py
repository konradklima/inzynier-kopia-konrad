"""Run OWASP ZAP in Docker against a live target.

Modes:
  baseline  zap-baseline.py, passive. Crawls the site and only inspects the responses
            (headers, cookies, leaked information). A few minutes, safe for any site.
  full      zap-full-scan.py, active with every attack rule. Slow (about 25 minutes on
            Juice Shop) and runs many tests that do not apply to the target.
  focused   ZAP Automation Framework plan, active but limited to the rules listed in
            catalog.py, with the crawl kept inside the target and time limits per rule.

Active modes send attacks. Run them only against sites you own or have written
permission to test (here: the local Juice Shop container).
"""

from __future__ import annotations
import os
import re
import shutil
import subprocess
import tempfile
from enum import StrEnum
from pathlib import Path
from alert_scanner import catalog

# Defined before the functions because they are used as default argument values.
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
FOCUSED_SPIDER_MINUTES = 2
FOCUSED_AJAX_MINUTES = 3
FOCUSED_SCAN_MINUTES = 15


class ScanMode(StrEnum):
    BASELINE = "baseline"
    FULL = "full"
    FOCUSED = "focused"


def run_zap_scan(
    target: str,
    report_path: str | Path,
    mode: ScanMode = ScanMode.BASELINE,
    *,
    ajax: bool = False,
    spider_minutes: int | None = None,
    max_scan_minutes: int | None = None,
) -> Path:
    """Run ZAP, wait for it to finish and copy the JSON report to `report_path`.

    The ZAP scripts exit with a non-zero code when they find warnings, so the exit
    code is not an error signal. A missing report file is.
    """
    docker = find_docker()
    if docker is None:
        raise ScanError("Nie znaleziono polecenia 'docker'. Zainstaluj i uruchom Docker Desktop.")

    if subprocess.run([docker, "info"], capture_output=True, check=False).returncode != 0:
        raise ScanError(
            "Docker jest zainstalowany, ale nie odpowiada. Uruchom Docker Desktop, poczekaj aż "
            "się włączy, a jeśli program działa w ograniczonym środowisku, uruchom go z zwykłego terminala."
        )

    # A temp dir gives an ASCII-only path. Docker on Windows has trouble mounting
    # folders with non-ASCII names, and the project folder has one.
    with tempfile.TemporaryDirectory(prefix="alert-scanner-zap-") as workdir:
        os.chmod(workdir, 0o777)  # ZAP runs as a different user inside the container
        if mode is ScanMode.FOCUSED:
            # --spider-minutes caps both spiders in focused mode.
            plan = build_focused_plan(
                target,
                ajax=ajax,
                spider_minutes=spider_minutes or FOCUSED_SPIDER_MINUTES,
                ajax_minutes=spider_minutes or FOCUSED_AJAX_MINUTES,
                max_scan_minutes=max_scan_minutes or FOCUSED_SCAN_MINUTES,
            )
            (Path(workdir) / _PLAN_FILE).write_text(plan, encoding="utf-8")
        command = build_docker_command(
            target, mode, workdir,
            ajax=ajax, spider_minutes=spider_minutes, max_scan_minutes=max_scan_minutes,
        )
        command[0] = docker
        result = subprocess.run(command, check=False)  # ZAP output goes straight to the console
        if result.returncode == _DOCKER_ERROR_EXIT_CODE:
            raise ScanError(
                "Docker nie mógł uruchomić kontenera ZAP (zobacz błąd Dockera powyżej). "
                "Uruchom ponownie Docker Desktop i sprawdź, czy jest wolne miejsce na dysku."
            )

        produced_report = Path(workdir) / _REPORT_FILE
        if not produced_report.exists():
            raise ScanError(
                f"ZAP zakończył działanie z kodem {result.returncode} i nie zapisał raportu. "
                "Sprawdź, czy kontener może połączyć się ze stroną "
                "(np. http://host.docker.internal:3000)."
            )
        report_path = Path(report_path)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(produced_report, report_path)
    return report_path


def build_docker_command(
    target: str,
    mode: ScanMode,
    workdir: str | Path,
    *,
    ajax: bool = False,
    spider_minutes: int | None = None,
    max_scan_minutes: int | None = None,
    image: str = ZAP_IMAGE,
) -> list[str]:
    command = ["docker", "run", "--rm", "-v", f"{workdir}:/zap/wrk/:rw", image]
    if mode is ScanMode.FOCUSED:
        # The plan file is written to workdir by run_zap_scan().
        return command + ["zap.sh", "-cmd", "-autorun", f"/zap/wrk/{_PLAN_FILE}"]

    command += [_ZAP_SCRIPTS[mode], "-t", target, "-J", _REPORT_FILE]
    if ajax:
        command.append("-j")
    if spider_minutes is not None:
        command += ["-m", str(spider_minutes)]
    if mode is ScanMode.FULL and max_scan_minutes is not None:
        command += ["-z", f"-config scanner.maxScanDurationInMins={max_scan_minutes}"]
    return command


def build_focused_plan(
    target: str,
    *,
    rules: list[str] | None = None,
    ajax: bool = True,
    spider_minutes: int = FOCUSED_SPIDER_MINUTES,
    ajax_minutes: int = FOCUSED_AJAX_MINUTES,
    max_scan_minutes: int = FOCUSED_SCAN_MINUTES,
) -> str:
    """YAML plan for the ZAP Automation Framework.

    The context covers only the target, so third-party sites are neither crawled
    nor attacked. All active rules are switched off except `rules`. Each rule gets
    at most half of the total time, so one slow rule cannot use it all.
    """
    rules = rules if rules is not None else catalog.focused_scan_rules()
    scope_regex = re.escape(target.rstrip("/")) + ".*"
    rule_lines = "\n".join(
        f"        - id: {rule}\n          threshold: medium" for rule in rules
    )
    ajax_job = f"""
  - type: spiderAjax
    parameters:
      context: target
      maxDuration: {ajax_minutes}
      inScopeOnly: true
      browserId: firefox-headless""" if ajax else ""
    return f"""env:
  contexts:
    - name: target
      urls:
        - {_yaml_quote(target)}
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
  - type: spider
    parameters:
      context: target
      maxDuration: {spider_minutes}{ajax_job}
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


_DOCKER_LOCATIONS = (
    "/Applications/Docker.app/Contents/Resources/bin/docker",
    "/usr/local/bin/docker",
    "/opt/homebrew/bin/docker",
)


def find_docker() -> str | None:
    """Ścieżka do Dockera. Programy uruchamiane z edytora często nie mają /usr/local/bin w PATH."""
    found = shutil.which("docker")
    if found:
        return found
    return next((path for path in _DOCKER_LOCATIONS if os.access(path, os.X_OK)), None)


class ScanError(RuntimeError):
    """Docker is missing or ZAP did not produce a report."""


def _yaml_quote(value: str) -> str:
    # Single-quoted YAML: backslashes stay literal, quotes are doubled.
    return "'" + value.replace("'", "''") + "'"


_REPORT_FILE = "zap-report.json"
_PLAN_FILE = "plan.yaml"
# `docker run` exits with 125 when Docker itself fails, before ZAP starts.
# The ZAP scripts use 0-3, so the codes cannot be confused.
_DOCKER_ERROR_EXIT_CODE = 125
_ZAP_SCRIPTS = {
    ScanMode.BASELINE: "zap-baseline.py",
    ScanMode.FULL: "zap-full-scan.py",
}
