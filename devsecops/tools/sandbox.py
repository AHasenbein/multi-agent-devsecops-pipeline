"""The Docker sandbox: deploy a new version, keep the old one, watch health, roll back
(FR16, FR17, FR18).

Container layout: the live app is ``<name>``. The version it replaced is kept, stopped, as
``<name>-previous`` so there is always something to roll back to.
"""

import math
import time
from collections.abc import Callable

from pydantic import BaseModel, Field

from devsecops.models import DeploymentRecord, DeployStatus, HealthCheck
from devsecops.tools.docker_client import DockerClient, DockerError
from devsecops.tools.health_checker import HealthChecker


class Sandbox:
    def __init__(
        self,
        docker: DockerClient,
        name: str = "sandbox-app",
        host_port: int = 8080,
        container_port: int = 8080,
        start_grace_s: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._docker = docker
        self.name = name
        self.previous_name = f"{name}-previous"
        self.host_port = host_port
        self._container_port = container_port
        self._start_grace_s = start_grace_s
        self._sleep = sleep

    @property
    def health_url(self) -> str:
        return f"http://127.0.0.1:{self.host_port}/health"

    # ------------------------------------------------------------------ deploy (FR16)

    def deploy(self, run_id: str, image_tag: str) -> DeploymentRecord:
        """Start ``image_tag`` as the live container. Never raises for a failed deploy:
        the returned record says STARTED, FAILED_TO_START (old version restored), or
        ROLLBACK_FAILED (old version could not be restored)."""
        record = DeploymentRecord(run_id=run_id, image_tag=image_tag, status=DeployStatus.STARTED)
        try:
            current = self._docker.inspect(self.name)
            if current is not None:
                # Keep the old version before the new one starts. The older kept copy is
                # dropped only now, while ``current`` still exists as a rollback target.
                if self._docker.inspect(self.previous_name) is not None:
                    self._docker.remove(self.previous_name)
                if current.status == "running":
                    self._docker.stop(self.name)
                self._docker.rename(self.name, self.previous_name)
            kept = self._docker.inspect(self.previous_name)
        except DockerError as exc:
            return record.model_copy(
                update={"status": DeployStatus.FAILED_TO_START, "error": f"prepare: {exc}"}
            )
        if kept is not None:
            record = record.model_copy(
                update={"previous_image_tag": kept.image_tag, "previous_container": kept.name}
            )

        try:
            self._docker.run(image_tag, self.name, self.host_port, self._container_port)
            self._sleep(self._start_grace_s)
            started = self._docker.inspect(self.name)
            if started is None or started.status != "running":
                status = started.status if started else "missing"
                raise DockerError(f"new container is not running (status: {status})")
        except DockerError as exc:
            return self._restore_after_failed_start(record, str(exc))
        return record

    def _restore_after_failed_start(self, record: DeploymentRecord, error: str) -> DeploymentRecord:
        if record.previous_container is None:
            # First ever deploy: nothing to restore. Clear the broken container.
            try:
                if self._docker.inspect(self.name) is not None:
                    self._docker.remove(self.name)
            except DockerError:
                pass
            return record.model_copy(
                update={"status": DeployStatus.FAILED_TO_START, "error": error}
            )
        try:
            self._docker.rollback(self.name, self.previous_name)
        except DockerError as exc:
            return record.model_copy(
                update={
                    "status": DeployStatus.ROLLBACK_FAILED,
                    "error": f"{error}; restoring the old version failed: {exc}",
                }
            )
        return record.model_copy(update={"status": DeployStatus.FAILED_TO_START, "error": error})

    # ------------------------------------------------------------------ rollback (FR17, FR18)

    def rollback(self, record: DeploymentRecord) -> DeploymentRecord:
        """Put the kept version back. ROLLBACK_FAILED means the developer must be told (FR18)."""
        try:
            self._docker.rollback(self.name, self.previous_name)
        except DockerError as exc:
            return record.model_copy(
                update={"status": DeployStatus.ROLLBACK_FAILED, "error": str(exc)}
            )
        return record.model_copy(update={"status": DeployStatus.ROLLED_BACK, "error": None})


# --------------------------------------------------------------------------- monitoring (FR17)


class MonitorResult(BaseModel):
    healthy: bool
    checks: list[HealthCheck] = Field(default_factory=list)
    consecutive_failures: int = 0


def watch_health(
    checker: HealthChecker,
    url: str,
    *,
    interval_s: float = 10,
    window_s: float = 300,
    fail_threshold: int = 3,
    on_check: Callable[[HealthCheck], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> MonitorResult:
    """Check ``url`` every ``interval_s`` for ``window_s``. Stops early, unhealthy, as soon as
    ``fail_threshold`` checks in a row fail. ``on_check`` sees each result (for evidence)."""
    total = max(1, math.ceil(window_s / interval_s))
    checks: list[HealthCheck] = []
    failures = 0
    for index in range(total):
        started = clock()
        check = checker.check(url)
        checks.append(check)
        if on_check is not None:
            on_check(check)
        failures = 0 if check.ok else failures + 1
        if failures >= fail_threshold:
            return MonitorResult(healthy=False, checks=checks, consecutive_failures=failures)
        if index < total - 1:
            sleep(max(0.0, interval_s - (clock() - started)))
    return MonitorResult(healthy=True, checks=checks, consecutive_failures=failures)
