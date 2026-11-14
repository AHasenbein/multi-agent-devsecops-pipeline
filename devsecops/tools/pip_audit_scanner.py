"""Runs pip-audit over a requirements file and reads its JSON report (FR7, FR8)."""

import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from devsecops.models import Finding, Severity
from devsecops.tools.base import Runner, ScanOutput, ToolError, run_command

SeverityFor = Callable[[str, Sequence[str]], Severity]
_MAX_MESSAGE = 300


def always_high(vuln_id: str, aliases: Sequence[str]) -> Severity:
    """pip-audit gives no severity, so every finding is HIGH unless policy says otherwise."""
    return Severity.HIGH


class PipAuditScanner:
    """``severity_for`` applies the policy.yaml exceptions; the Security Agent passes
    ``functools.partial(pip_audit_severity, policy)``. The default treats everything as HIGH."""

    def __init__(
        self,
        severity_for: SeverityFor = always_high,
        runner: Runner = run_command,
        python: str = sys.executable,
        timeout_s: float = 300,
    ) -> None:
        self._severity_for = severity_for
        self._runner = runner
        self._python = python
        self._timeout_s = timeout_s

    def scan(
        self, workspace: str | Path, requirements: str = "sample_app/requirements.txt"
    ) -> ScanOutput:
        if not (Path(workspace) / requirements).is_file():
            raise ToolError(f"pip-audit: {requirements} not found in the workspace")
        result = self._runner(
            [
                self._python,
                "-m",
                "pip_audit",
                "-r",
                requirements,
                "-f",
                "json",
                "--progress-spinner",
                "off",
            ],
            cwd=workspace,
            timeout=self._timeout_s,
        )
        if result.timed_out:
            raise ToolError(f"pip-audit timed out after {self._timeout_s:g} s")
        if result.returncode not in (0, 1):  # 1 means "vulnerabilities found"
            raise ToolError(f"pip-audit exited with code {result.returncode}: {result.tail(500)}")
        return parse_pip_audit_json(result.stdout, self._severity_for, requirements)


def parse_pip_audit_json(
    output: str, severity_for: SeverityFor = always_high, requirements: str | None = None
) -> ScanOutput:
    try:
        dependencies = json.loads(output)["dependencies"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ToolError(f"pip-audit: unreadable JSON report: {exc}") from exc

    findings: list[Finding] = []
    tool_errors: list[str] = []
    seen: set[tuple[str, str]] = set()
    for dependency in dependencies:
        name = str(dependency.get("name", "unknown"))
        if "skip_reason" in dependency:
            # A dependency that was not audited must not count as clean.
            tool_errors.append(f"pip-audit skipped {name}: {dependency['skip_reason']}")
            continue
        version = dependency.get("version", "?")
        for vuln in dependency.get("vulns", []):
            vuln_id = str(vuln.get("id", "UNKNOWN"))
            if (name, vuln_id) in seen:  # pip-audit can list one advisory twice
                continue
            seen.add((name, vuln_id))
            aliases = [str(alias) for alias in vuln.get("aliases", [])]
            findings.append(
                Finding(
                    tool="pip-audit",
                    rule_id=vuln_id,
                    file=requirements,
                    package=name,
                    severity=severity_for(vuln_id, aliases),
                    message=_message(name, version, vuln),
                    aliases=aliases,
                )
            )
    return ScanOutput(findings=findings, tool_errors=tool_errors)


def _message(name: str, version: str, vuln: dict) -> str:
    text = f"{name} {version}"
    fixes = vuln.get("fix_versions") or []
    if fixes:
        text += f" (fixed in {', '.join(str(fix) for fix in fixes)})"
    description = " ".join(str(vuln.get("description", "")).split())
    if description:
        text += f": {description}"
    return text[:_MAX_MESSAGE]
