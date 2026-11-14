"""Runs pytest with coverage and reads the JUnit XML and coverage JSON reports (FR6)."""

import json
import re
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from devsecops.models import TestFailure, TestReport
from devsecops.tools.base import Runner, ToolError, run_command

_MAX_MESSAGE = 300
# pytest exit codes: 0 all passed, 1 tests failed, 2 interrupted (includes collection errors),
# 5 no tests collected. 3 (internal error) and 4 (usage error) mean pytest itself broke.
_USABLE_EXIT_CODES = {0, 1, 2, 5}


class PytestRunner:
    __test__ = False  # not a pytest class

    def __init__(
        self,
        runner: Runner = run_command,
        python: str = sys.executable,
        timeout_s: float = 600,
    ) -> None:
        self._runner = runner
        self._python = python
        self._timeout_s = timeout_s

    def run(
        self, workspace: str | Path, app_dir: str = "sample_app", cov_package: str = "app"
    ) -> TestReport:
        project = Path(workspace) / app_dir
        if not project.is_dir():
            raise ToolError(f"pytest: {app_dir} not found in the workspace")

        # Reports go outside the workspace so the change under test cannot pre-seed them.
        with tempfile.TemporaryDirectory(prefix="devsecops-pytest-") as tmp:
            junit = Path(tmp) / "junit.xml"
            coverage = Path(tmp) / "coverage.json"
            result = self._runner(
                [
                    self._python,
                    "-m",
                    "pytest",
                    f"--cov={cov_package}",
                    f"--cov-report=json:{coverage}",
                    f"--junitxml={junit}",
                    "-o",
                    "junit_family=xunit1",
                    "-p",
                    "no:cacheprovider",
                    "-q",
                ],
                cwd=project,
                timeout=self._timeout_s,
                env={"COVERAGE_FILE": str(Path(tmp) / ".coverage")},
            )
            if result.timed_out:
                raise ToolError(f"pytest timed out after {self._timeout_s:g} s")
            if result.returncode not in _USABLE_EXIT_CODES or not junit.exists():
                raise ToolError(
                    f"pytest exited with code {result.returncode} and no usable report: "
                    f"{result.tail(500)}"
                )
            report = parse_reports(
                junit.read_text(encoding="utf-8", errors="replace"),
                coverage.read_text(encoding="utf-8") if coverage.exists() else None,
                path_prefix=app_dir,
            )

        if result.returncode in (1, 2) and report.failed == 0:
            raise ToolError(
                f"pytest exited with code {result.returncode} but reported no failures: "
                f"{result.tail(500)}"
            )
        return report


def parse_reports(junit_xml: str, coverage_json: str | None, path_prefix: str = "") -> TestReport:
    """Build a TestReport from pytest's JUnit XML (xunit1) and coverage.py's JSON report."""
    try:
        root = ET.fromstring(junit_xml)  # noqa: S314 - written by our own pytest run
    except ET.ParseError as exc:
        raise ToolError(f"pytest: unreadable JUnit report: {exc}") from exc

    passed = failed = skipped = 0
    failures: list[TestFailure] = []
    for case in root.iter("testcase"):
        problem = case.find("failure")
        if problem is None:
            problem = case.find("error")
        if problem is not None:
            failed += 1
            failures.append(_failure(case, problem, path_prefix))
        elif case.find("skipped") is not None:
            skipped += 1
        else:
            passed += 1

    return TestReport(
        passed=passed,
        failed=failed,
        skipped=skipped,
        coverage_pct=_coverage_pct(coverage_json, failed),
        failures=failures,
    )


def _coverage_pct(coverage_json: str | None, failed: int) -> float:
    if coverage_json is None:
        if failed:
            return 0.0  # e.g. a collection error stops pytest before coverage is written
        raise ToolError("pytest: coverage report is missing")
    try:
        percent = float(json.loads(coverage_json)["totals"]["percent_covered"])
    except (ValueError, KeyError, TypeError) as exc:
        raise ToolError(f"pytest: unreadable coverage report: {exc}") from exc
    return round(min(max(percent, 0.0), 100.0), 2)


def _failure(case: ET.Element, problem: ET.Element, path_prefix: str) -> TestFailure:
    file = case.get("file")
    text = problem.text or ""
    line: int | None = None
    if file:
        # The traceback ends with "<file>:<line>: <Error>", the line that actually failed.
        hits = re.findall(rf"^{re.escape(file)}:(\d+): ", text, flags=re.MULTILINE)
        if hits:
            line = int(hits[-1])
        elif case.get("line") is not None:
            line = int(case.get("line")) + 1  # JUnit line is 0-based: the "def" line
    message = (problem.get("message") or text).strip().splitlines()
    return TestFailure(
        test_name=case.get("name") or "unknown",
        file=f"{path_prefix}/{file}" if (file and path_prefix) else file,
        line=line,
        message=(message[0] if message else "")[:_MAX_MESSAGE],
    )
