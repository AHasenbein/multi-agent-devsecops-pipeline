"""Live demo of the Docker sandbox: deploy, broken deploy, failed health checks, rollback.

    uv run python scripts/demo_sandbox.py

Leaves the healthy sample app running at http://127.0.0.1:8080 (try /docs).
Remove it afterwards with:  docker rm -f sandbox-app
"""

import shutil
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from devsecops.models import DeployStatus, HealthCheck  # noqa: E402
from devsecops.policy import load_policy  # noqa: E402
from devsecops.tools import DockerClient, HealthChecker, Sandbox, watch_health  # noqa: E402

GOOD, BROKEN = "sample_app:demo-good", "sample_app:demo-broken"
HEALTHY_LINE = 'return {"status": "ok", "version": __version__}'


def step(text: str) -> None:
    print(f"\n=== {text}")


def show(docker: DockerClient, sandbox: Sandbox) -> None:
    for name in (sandbox.name, sandbox.previous_name):
        c = docker.inspect(name)
        print(f"    {name:<22} {f'{c.image_tag}  [{c.status}]' if c else '(none)'}")


def print_check(check: HealthCheck) -> None:
    result = "ok  " if check.ok else "FAIL"
    print(f"    {check.at:%H:%M:%S}  {result}  status={check.status_code}  {check.error or ''}")


def wait_healthy(checker: HealthChecker, url: str) -> None:
    for _ in range(40):
        check = checker.check(url)
        if check.ok:
            print_check(check)
            return
        time.sleep(0.25)
    sys.exit(f"{url} never became healthy")


def main() -> None:
    policy = load_policy(REPO_ROOT / "policy.yaml")
    docker = DockerClient()
    if not docker.is_available():
        sys.exit("Docker is not running. Start Docker Desktop and try again.")
    sandbox = Sandbox(docker)
    checker = HealthChecker(timeout_s=2)
    for name in (sandbox.name, sandbox.previous_name):
        if docker.inspect(name) is not None:
            docker.remove(name)

    step("1. Build the sample app (Build Agent's job, FR4)")
    build = docker.build(REPO_ROOT / "sample_app", GOOD)
    print(f"    {GOOD}: success={build.success}")

    step("2. Deploy it to the sandbox (FR16)")
    record = sandbox.deploy("demo-run-1", GOOD)
    print(f"    deploy status: {record.status.value}")
    wait_healthy(checker, sandbox.health_url)
    show(docker, sandbox)

    step("3. Build a broken change: /health now returns 500")
    with tempfile.TemporaryDirectory() as tmp:
        broken_dir = Path(tmp) / "sample_app"
        shutil.copytree(REPO_ROOT / "sample_app", broken_dir)
        main_py = broken_dir / "app" / "main.py"
        main_py.write_text(
            main_py.read_text().replace(
                HEALTHY_LINE, 'raise HTTPException(status_code=500, detail="broken")'
            )
        )
        print(f"    {BROKEN}: success={docker.build(broken_dir, BROKEN).success}")

    step("4. Deploy the broken change. The old version is stopped and kept first")
    record = sandbox.deploy("demo-run-2", BROKEN)
    print(
        f"    deploy status: {record.status.value}   rollback target: {record.previous_image_tag}"
    )
    show(docker, sandbox)

    timers = policy.timers
    step(
        f"5. Monitor: check every {timers.health_interval_s} s, roll back after "
        f"{timers.health_fail_threshold} failures in a row (FR17)"
    )
    started = time.monotonic()
    result = watch_health(
        checker,
        sandbox.health_url,
        interval_s=timers.health_interval_s,
        window_s=timers.health_window_s,
        fail_threshold=timers.health_fail_threshold,
        on_check=print_check,
    )
    print(f"    healthy={result.healthy} after {len(result.checks)} checks")

    step("6. Roll back to the kept version")
    record = sandbox.rollback(record)
    print(f"    deploy status: {record.status.value}")
    wait_healthy(checker, sandbox.health_url)
    took = time.monotonic() - started
    show(docker, sandbox)
    print(
        f"\n    First failed check to old version healthy again: {took:.1f} s "
        f"(limit {timers.rollback_sla_s} s after detection)"
    )
    if record.status is DeployStatus.ROLLED_BACK:
        print(
            f"\nThe sample app is still running: {sandbox.health_url.replace('/health', '/docs')}"
        )


if __name__ == "__main__":
    main()
