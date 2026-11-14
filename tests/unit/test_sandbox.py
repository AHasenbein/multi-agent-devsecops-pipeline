"""Sandbox deploy, monitor and rollback against a fake docker (FR16, FR17, FR18)."""

import pytest

from devsecops.models import DeployStatus, HealthCheck
from devsecops.tools import DockerClient, Sandbox, watch_health

from ..fakes import FakeDocker

LIVE, KEPT = "sandbox-app", "sandbox-app-previous"


@pytest.fixture
def docker():
    return FakeDocker()


@pytest.fixture
def sandbox(docker):
    return Sandbox(DockerClient(runner=docker), sleep=lambda s: None)


# ------------------------------------------------------------------ deploy (FR16)


def test_fr16_first_deploy_starts_the_app_with_nothing_to_keep(sandbox, docker):
    record = sandbox.deploy("run-1", "sample_app:v1")
    assert record.status is DeployStatus.STARTED
    assert record.image_tag == "sample_app:v1"
    assert record.previous_container is None
    assert docker.containers[LIVE]["image"] == "sample_app:v1"
    assert sandbox.health_url == "http://127.0.0.1:8080/health"


def test_fr16_old_version_is_stopped_and_kept_before_the_new_one_starts(sandbox, docker):
    sandbox.deploy("run-1", "sample_app:v1")
    docker.commands.clear()
    record = sandbox.deploy("run-2", "sample_app:v2")

    assert record.status is DeployStatus.STARTED
    assert record.previous_image_tag == "sample_app:v1"
    assert record.previous_container == KEPT
    assert docker.containers[LIVE] == {**docker.containers[LIVE], "image": "sample_app:v2"}
    assert docker.containers[KEPT]["image"] == "sample_app:v1"
    assert docker.containers[KEPT]["status"] == "exited"

    order = [command[0] for command in docker.commands]
    assert order.index("rename") < order.index("run")  # invariant 9: keep first, then start


def test_fr16_third_deploy_keeps_only_the_most_recent_old_version(sandbox, docker):
    for n in (1, 2, 3):
        sandbox.deploy(f"run-{n}", f"sample_app:v{n}")
    assert docker.containers[LIVE]["image"] == "sample_app:v3"
    assert docker.containers[KEPT]["image"] == "sample_app:v2"
    assert set(docker.containers) == {LIVE, KEPT}


def test_fr16_failed_start_restores_the_old_version(sandbox, docker):
    """UC-07-01 exception: the deployment fails, the old version keeps running."""
    sandbox.deploy("run-1", "sample_app:v1")
    docker.fail["run"] = "port is already allocated"
    record = sandbox.deploy("run-2", "sample_app:v2")

    assert record.status is DeployStatus.FAILED_TO_START
    assert "port is already allocated" in record.error
    assert docker.containers[LIVE]["image"] == "sample_app:v1"
    assert docker.containers[LIVE]["status"] == "running"
    assert KEPT not in docker.containers


def test_fr16_container_that_exits_right_after_start_counts_as_failed_start(sandbox, docker):
    sandbox.deploy("run-1", "sample_app:v1")
    docker.run_status = "exited"
    record = sandbox.deploy("run-2", "sample_app:crashes")

    assert record.status is DeployStatus.FAILED_TO_START
    assert "not running" in record.error
    assert docker.containers[LIVE]["image"] == "sample_app:v1"
    assert docker.containers[LIVE]["status"] == "running"


def test_fr16_failed_first_deploy_leaves_no_broken_container(sandbox, docker):
    docker.run_status = "exited"
    record = sandbox.deploy("run-1", "sample_app:crashes")
    assert record.status is DeployStatus.FAILED_TO_START
    assert docker.containers == {}


def test_fr18_failed_start_and_failed_restore_is_rollback_failed(sandbox, docker):
    sandbox.deploy("run-1", "sample_app:v1")
    docker.fail["run"] = "boom"
    docker.fail["start"] = "cannot start old container"
    record = sandbox.deploy("run-2", "sample_app:v2")
    assert record.status is DeployStatus.ROLLBACK_FAILED
    assert "boom" in record.error
    assert "cannot start old container" in record.error


def test_deploy_reports_a_docker_failure_while_keeping_the_old_version(sandbox, docker):
    sandbox.deploy("run-1", "sample_app:v1")
    docker.fail["rename"] = "daemon error"
    record = sandbox.deploy("run-2", "sample_app:v2")
    assert record.status is DeployStatus.FAILED_TO_START
    assert "daemon error" in record.error
    assert docker.containers[LIVE]["image"] == "sample_app:v1"  # never replaced


# ------------------------------------------------------------------ rollback (FR17, FR18)


def test_fr17_rollback_restores_the_kept_version(sandbox, docker):
    sandbox.deploy("run-1", "sample_app:v1")
    record = sandbox.deploy("run-2", "sample_app:broken")
    rolled_back = sandbox.rollback(record)

    assert rolled_back.status is DeployStatus.ROLLED_BACK
    assert rolled_back.image_tag == "sample_app:broken"  # the record still says what was tried
    assert docker.containers[LIVE]["image"] == "sample_app:v1"
    assert docker.containers[LIVE]["status"] == "running"


def test_fr18_blocked_rollback_is_reported_not_raised(sandbox, docker):
    sandbox.deploy("run-1", "sample_app:v1")
    record = sandbox.deploy("run-2", "sample_app:broken")
    del docker.containers[KEPT]  # someone removed the rollback target
    failed = sandbox.rollback(record)
    assert failed.status is DeployStatus.ROLLBACK_FAILED
    assert "no previous container" in failed.error


# ------------------------------------------------------------------ monitoring (FR17)


class ScriptedChecker:
    """Returns the given results in order, then keeps returning the last one."""

    def __init__(self, *results: bool):
        self.results = list(results)
        self.calls = 0

    def check(self, url):
        ok = self.results[min(self.calls, len(self.results) - 1)]
        self.calls += 1
        return HealthCheck(ok=ok, status_code=200 if ok else 500)


class FakeTime:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def clock(self):
        return self.now


def watch(checker, **kwargs):
    fake = FakeTime()
    result = watch_health(checker, "http://x/health", sleep=fake.sleep, clock=fake.clock, **kwargs)
    return result, fake


def test_fr17_healthy_app_is_checked_every_10_s_for_5_min():
    checker = ScriptedChecker(True)
    result, fake = watch(checker)
    assert result.healthy
    assert len(result.checks) == 30
    assert fake.sleeps == [10] * 29
    assert fake.now == 290  # the 30th check is the last one inside the 5 minute window


def test_fr17_three_failures_in_a_row_stop_monitoring_within_30_s():
    checker = ScriptedChecker(False)
    result, fake = watch(checker)
    assert not result.healthy
    assert result.consecutive_failures == 3
    assert len(result.checks) == 3
    assert fake.now <= 30  # TS-08-01: 3 failed checks in 30 seconds


def test_fr17_failures_that_are_not_in_a_row_do_not_trigger_rollback():
    checker = ScriptedChecker(False, False, True, False, False, True, True)
    result, _ = watch(checker)
    assert result.healthy
    assert len(result.checks) == 30


def test_fr17_a_late_run_of_failures_still_triggers_rollback():
    checker = ScriptedChecker(*([True] * 10), False, False, False)
    result, fake = watch(checker)
    assert not result.healthy
    assert len(result.checks) == 13
    assert fake.now == 120


def test_fr17_timers_and_threshold_come_from_the_caller():
    result, fake = watch(ScriptedChecker(False), interval_s=1, window_s=5, fail_threshold=2)
    assert not result.healthy and len(result.checks) == 2
    result, fake = watch(ScriptedChecker(True), interval_s=1, window_s=5, fail_threshold=2)
    assert result.healthy and len(result.checks) == 5


def test_fr17_every_check_is_passed_to_on_check_for_the_run_record():
    seen = []
    watch(ScriptedChecker(True, False, False, False), on_check=seen.append)
    assert [check.ok for check in seen] == [True, False, False, False]
