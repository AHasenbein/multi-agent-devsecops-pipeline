"""Monitoring Agent: watches the deployed app and rolls back on failed checks (FR17, FR18)."""

import time
from collections.abc import Callable, Mapping
from typing import Any

from pydantic import BaseModel, Field

from devsecops.agents.base import Agent
from devsecops.models import AgentStatus, DeploymentRecord, DeployStatus, HealthCheck, Timers
from devsecops.tools.health_checker import HealthChecker
from devsecops.tools.sandbox import Sandbox, watch_health


class MonitoringOutcome(BaseModel):
    healthy: bool
    checks: list[HealthCheck] = Field(default_factory=list)
    deployment: DeploymentRecord


class MonitoringAgent(Agent):
    name = "monitoring"
    output_model = MonitoringOutcome

    def __init__(
        self,
        sandbox: Sandbox,
        checker: HealthChecker,
        timers: Timers,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        schema_retries: int = 2,
    ) -> None:
        super().__init__(schema_retries)
        self._sandbox = sandbox
        self._checker = checker
        self._timers = timers
        self._sleep = sleep
        self._clock = clock

    def run(
        self,
        state: Mapping[str, Any],
        on_check: Callable[[HealthCheck], None] | None = None,
        **options: Any,
    ) -> Any:
        record = DeploymentRecord.model_validate(state["deployment"])
        result = watch_health(
            self._checker,
            self._sandbox.health_url,
            interval_s=self._timers.health_interval_s,
            window_s=self._timers.health_window_s,
            fail_threshold=self._timers.health_fail_threshold,
            on_check=on_check,
            sleep=self._sleep,
            clock=self._clock,
        )
        if result.healthy:
            record = record.model_copy(update={"status": DeployStatus.HEALTHY})
        else:
            record = self._sandbox.rollback(record)
        return MonitoringOutcome(healthy=result.healthy, checks=result.checks, deployment=record)

    def status_of(self, output: MonitoringOutcome) -> AgentStatus:
        return AgentStatus.OK if output.healthy else AgentStatus.FAILED

    def summarize(self, output: MonitoringOutcome) -> str:
        failed = sum(1 for check in output.checks if not check.ok)
        return (
            f"{len(output.checks)} health checks, {failed} failed: {output.deployment.status.value}"
        )
