"""Test Agent: runs the test suite through PytestRunner (FR6)."""

from collections.abc import Mapping
from typing import Any

from devsecops.agents.base import Agent
from devsecops.models import AgentStatus, TestReport
from devsecops.tools.pytest_runner import PytestRunner


class TestAgent(Agent):
    __test__ = False  # not a pytest class

    name = "test"
    output_model = TestReport

    def __init__(
        self, runner: PytestRunner, app_dir: str = "sample_app", schema_retries: int = 2
    ) -> None:
        super().__init__(schema_retries)
        self._runner = runner
        self._app_dir = app_dir

    def run(self, state: Mapping[str, Any], **options: Any) -> Any:
        return self._runner.run(state["workspace"], app_dir=self._app_dir)

    def status_of(self, output: TestReport) -> AgentStatus:
        return AgentStatus.FAILED if output.failed else AgentStatus.OK

    def summarize(self, output: TestReport) -> str:
        return (
            f"{output.passed} passed, {output.failed} failed, {output.skipped} skipped, "
            f"coverage {output.coverage_pct:.1f}%"
        )
