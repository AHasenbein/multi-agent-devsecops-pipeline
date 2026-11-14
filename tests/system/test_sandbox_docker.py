"""TS-08-01 against a real Docker daemon: deploy, failed health checks, rollback
(FR4, FR16, FR17, FR18, QA-PE-01). Skipped when Docker is not running.

Uses its own container name and port, so it does not touch a real sandbox on :8080.
"""

import shutil
import time
from pathlib import Path

import pytest

from devsecops.models import DeployStatus
from devsecops.tools import DockerClient, HealthChecker, Sandbox, watch_health

pytestmark = pytest.mark.docker

REPO_ROOT = Path(__file__).resolve().parents[2]
NAME = "devsecops-test-sandbox"
PORT = 18080
GOOD, BROKEN, CRASHING = (f"devsecops-test-app:{tag}" for tag in ("good", "broken", "crashing"))


@pytest.fixture(scope="module")
def docker():
    client = DockerClient()
    if not client.is_available():
        pytest.skip("Docker daemon is not running")
    return client


@pytest.fixture(scope="module")
def images(docker, tmp_path_factory):
    """Build the real sample app, a copy with a broken /health, and one that exits at start."""
    good = docker.build(REPO_ROOT / "sample_app", GOOD)
    assert good.success, good.errors

    broken_dir = tmp_path_factory.mktemp("broken") / "sample_app"
    shutil.copytree(REPO_ROOT / "sample_app", broken_dir)
    main = broken_dir / "app" / "main.py"
    source = main.read_text()
    healthy = 'return {"status": "ok", "version": __version__}'
    assert healthy in source
    main.write_text(
        source.replace(healthy, 'raise HTTPException(status_code=500, detail="broken")')
    )
    assert docker.build(broken_dir, BROKEN).success

    crash_dir = tmp_path_factory.mktemp("crashing")
    (crash_dir / "Dockerfile").write_text(
        f'FROM {GOOD}\nCMD ["python", "-c", "raise SystemExit(1)"]\n'
    )
    assert docker.build(crash_dir, CRASHING).success


@pytest.fixture
def sandbox(docker, images):
    def clean():
        for name in (NAME, f"{NAME}-previous"):
            if docker.inspect(name) is not None:
                docker.remove(name)

    clean()
    yield Sandbox(docker, name=NAME, host_port=PORT)
    clean()


def wait_until_healthy(url: str, timeout_s: float = 20) -> None:
    checker = HealthChecker(timeout_s=2)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if checker.check(url).ok:
            return
        time.sleep(0.25)
    pytest.fail(f"{url} did not become healthy within {timeout_s} s")


def test_fr4_build_failure_is_reported_with_errors(docker, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nCOPY missing.txt .\n")
    result = docker.build(tmp_path, "devsecops-test-app:wontbuild")
    assert not result.success
    assert result.errors
    assert "missing.txt" in " ".join(result.errors) + result.log_tail


def test_fr16_deploy_serves_health_and_keeps_the_old_version(docker, sandbox):
    first = sandbox.deploy("run-1", GOOD)
    assert first.status is DeployStatus.STARTED
    wait_until_healthy(sandbox.health_url)

    second = sandbox.deploy("run-2", GOOD)
    assert second.status is DeployStatus.STARTED
    assert second.previous_container == sandbox.previous_name
    wait_until_healthy(sandbox.health_url)

    assert docker.inspect(sandbox.name).status == "running"
    assert docker.inspect(sandbox.previous_name).status == "exited"


def test_ts_08_01_broken_health_check_rolls_back_to_the_old_version(docker, sandbox):
    """Steps 1 and 2: deploy the broken change, 3 failed checks, old version back in time."""
    sandbox.deploy("run-1", GOOD)
    wait_until_healthy(sandbox.health_url)
    old_id = docker.inspect(sandbox.name).id

    record = sandbox.deploy("run-2", BROKEN)
    assert record.status is DeployStatus.STARTED
    assert record.previous_image_tag == GOOD

    detected_at = time.monotonic()
    result = watch_health(
        HealthChecker(timeout_s=2), sandbox.health_url, interval_s=1, window_s=30, fail_threshold=3
    )
    assert not result.healthy
    assert result.consecutive_failures == 3

    rolled_back = sandbox.rollback(record)
    assert rolled_back.status is DeployStatus.ROLLED_BACK
    wait_until_healthy(sandbox.health_url)
    recovery_s = time.monotonic() - detected_at

    assert recovery_s < 120  # rollback_sla_s (QA-PE-01)
    live = docker.inspect(sandbox.name)
    assert live.id == old_id  # the very container that was kept, not a rebuild
    assert live.image_tag == GOOD
    assert docker.inspect(sandbox.previous_name) is None


def test_ts_08_01_blocked_rollback_is_reported(docker, sandbox):
    """Step 3: block the rollback. The record says ROLLBACK_FAILED so the developer is told."""
    sandbox.deploy("run-1", GOOD)
    record = sandbox.deploy("run-2", BROKEN)
    docker.remove(sandbox.previous_name)  # the rollback target disappears

    failed = sandbox.rollback(record)
    assert failed.status is DeployStatus.ROLLBACK_FAILED
    assert "no previous container" in failed.error


def test_fr16_image_that_exits_at_start_is_failed_to_start_and_old_version_runs(docker, sandbox):
    sandbox.deploy("run-1", GOOD)
    wait_until_healthy(sandbox.health_url)

    record = sandbox.deploy("run-2", CRASHING)
    assert record.status is DeployStatus.FAILED_TO_START
    assert "not running" in record.error
    wait_until_healthy(sandbox.health_url)
    assert docker.inspect(sandbox.name).image_tag == GOOD


def test_fr16_container_is_published_on_localhost_only(docker, sandbox):
    from devsecops.tools import run_command

    sandbox.deploy("run-1", GOOD)
    ports = run_command(["docker", "port", NAME]).stdout
    assert f"127.0.0.1:{PORT}" in ports
    assert "0.0.0.0" not in ports
