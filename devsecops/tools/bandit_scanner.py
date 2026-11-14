"""Runs Bandit over the source code and reads its JSON report (FR7)."""

import json
import sys
import tempfile
from pathlib import Path

from devsecops.models import Finding, Severity
from devsecops.tools.base import Runner, ScanOutput, ToolError, run_command


class BanditScanner:
    def __init__(
        self,
        runner: Runner = run_command,
        python: str = sys.executable,
        timeout_s: float = 300,
    ) -> None:
        self._runner = runner
        self._python = python
        self._timeout_s = timeout_s

    def scan(self, workspace: str | Path, target: str = "sample_app") -> ScanOutput:
        if not (Path(workspace) / target).exists():
            raise ToolError(f"bandit: {target} not found in the workspace")

        # The change under evaluation must not be able to switch off its own scan. An empty
        # --ini stops Bandit from reading a .bandit file in the repo, and --ignore-nosec
        # makes "# nosec" comments have no effect.
        with tempfile.NamedTemporaryFile("w", suffix=".ini", prefix="devsecops-bandit-") as ini:
            ini.write("[bandit]\n")
            ini.flush()
            result = self._runner(
                [
                    self._python,
                    "-m",
                    "bandit",
                    "-r",
                    target,
                    "-f",
                    "json",
                    "-q",
                    "--ignore-nosec",
                    "--ini",
                    ini.name,
                ],
                cwd=workspace,
                timeout=self._timeout_s,
            )
        if result.timed_out:
            raise ToolError(f"bandit timed out after {self._timeout_s:g} s")
        if result.returncode not in (0, 1):  # 1 means "issues found"
            raise ToolError(f"bandit exited with code {result.returncode}: {result.tail(500)}")
        return parse_bandit_json(result.stdout)


def parse_bandit_json(output: str) -> ScanOutput:
    try:
        report = json.loads(output)
        results = report["results"]
        errors = report.get("errors", [])
    except (ValueError, KeyError, TypeError) as exc:
        raise ToolError(f"bandit: unreadable JSON report: {exc}") from exc

    findings = [
        Finding(
            tool="bandit",
            rule_id=str(item.get("test_id", "UNKNOWN")),
            file=_relative(item.get("filename")),
            line=item.get("line_number"),
            severity=_severity(item.get("issue_severity")),
            message=str(item.get("issue_text", "")).strip(),
        )
        for item in results
    ]
    # A file Bandit could not parse was not scanned, so it must not count as clean.
    tool_errors = [
        f"bandit could not scan {_relative(error.get('filename'))}: {error.get('reason', '')}"
        for error in errors
    ]
    return ScanOutput(findings=findings, tool_errors=tool_errors)


def _severity(value: object) -> Severity:
    try:
        return Severity(str(value).upper())
    except ValueError:
        return Severity.MEDIUM  # unknown severity: send to a human rather than allow


def _relative(filename: object) -> str | None:
    if not filename:
        return None
    text = str(filename)
    return text[2:] if text.startswith("./") else text
