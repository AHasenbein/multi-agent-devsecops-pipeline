"""DeployLock: deploys are serialized (CLAUDE.md §1 invariant 7, QA-SC-01)."""

import threading
import time

import pytest

from devsecops.orchestrator.locks import DeployLock, DeployLockTimeout


def test_lock_records_the_holder_and_clears_it_on_release(tmp_path):
    lock = DeployLock(tmp_path / "deploy.lock")
    assert lock.holder() is None
    with lock.hold("run-1"):
        assert lock.holder() == "run-1"
    assert lock.holder() is None


def test_second_run_times_out_while_the_first_holds_the_lock(tmp_path):
    path = tmp_path / "deploy.lock"
    with DeployLock(path).hold("run-1"):
        with pytest.raises(DeployLockTimeout, match="held by run run-1"):
            with DeployLock(path, poll_s=0.01).hold("run-2", timeout_s=0.05):
                pytest.fail("run-2 must not get the lock")
    with DeployLock(path).hold("run-2", timeout_s=0.05):
        pass  # free again after run-1 leaves


def test_lock_is_released_when_the_deploy_raises(tmp_path):
    lock = DeployLock(tmp_path / "deploy.lock")
    with pytest.raises(RuntimeError):
        with lock.hold("run-1"):
            raise RuntimeError("deploy blew up")
    with lock.hold("run-2", timeout_s=0.05):
        assert lock.holder() == "run-2"


def test_qa_sc_01_five_runs_never_deploy_at_the_same_time(tmp_path):
    path = tmp_path / "deploy.lock"
    inside = 0
    most_at_once = 0
    finished = []
    guard = threading.Lock()

    def deploy(run_id):
        nonlocal inside, most_at_once
        with DeployLock(path, poll_s=0.005).hold(run_id, timeout_s=10):
            with guard:
                inside += 1
                most_at_once = max(most_at_once, inside)
            time.sleep(0.02)
            with guard:
                inside -= 1
                finished.append(run_id)

    threads = [threading.Thread(target=deploy, args=(f"run-{n}",)) for n in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert most_at_once == 1
    assert sorted(finished) == [f"run-{n}" for n in range(5)]
