"""Security Agent: Bandit, pip-audit and the prompt-injection check (FR7, FR8, FR12)."""

from collections.abc import Callable, Mapping
from typing import Any

from devsecops.agents.base import Agent
from devsecops.models import SecurityReport
from devsecops.tools.bandit_scanner import BanditScanner
from devsecops.tools.base import ScanOutput, ToolError
from devsecops.tools.injection_detector import InjectionDetector
from devsecops.tools.pip_audit_scanner import PipAuditScanner


class SecurityAgent(Agent):
    name = "security"
    output_model = SecurityReport

    def __init__(
        self,
        bandit: BanditScanner,
        pip_audit: PipAuditScanner,
        injection: InjectionDetector,
        app_dir: str = "sample_app",
        schema_retries: int = 2,
    ) -> None:
        super().__init__(schema_retries)
        self._bandit = bandit
        self._pip_audit = pip_audit
        self._injection = injection
        self._app_dir = app_dir

    def run(self, state: Mapping[str, Any], **options: Any) -> Any:
        workspace = state["workspace"]
        scans: tuple[tuple[str, Callable[[], ScanOutput]], ...] = (
            ("bandit", lambda: self._bandit.scan(workspace, target=self._app_dir)),
            (
                "pip-audit",
                lambda: self._pip_audit.scan(
                    workspace, requirements=f"{self._app_dir}/requirements.txt"
                ),
            ),
        )
        findings, tool_errors = [], []
        for label, scan in scans:
            # One scanner crashing must not hide what the other one found. The crash is
            # kept as a tool error, which escalates (UC-04-01 exception 2).
            try:
                output = scan()
            except ToolError as exc:
                tool_errors.append(f"{label}: {exc}")
                continue
            findings += output.findings
            tool_errors += output.tool_errors

        injections = self._injection.scan_diff(state.get("diff") or "")
        return SecurityReport(
            findings=findings + injections,
            tool_errors=tool_errors,
            injection_suspected=bool(injections),
        )

    def summarize(self, output: SecurityReport) -> str:
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in output.findings:
            counts[finding.severity.value] += 1
        text = ", ".join(f"{n} {severity}" for severity, n in counts.items())
        if output.tool_errors:
            text += f", {len(output.tool_errors)} tool error(s)"
        if output.injection_suspected:
            text += ", possible prompt injection"
        return text
