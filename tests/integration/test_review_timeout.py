"""The review timeout sweeper (FR15, TS-06-01 "no answer"): an escalated run nobody
answers before its deadline is denied and the developer is told."""

import time
from datetime import timedelta

import pytest

from devsecops.models import Verdict, utc_now
from devsecops.orchestrator.approval_service import ApprovalService
from devsecops.tools import ScanOutput

from ..fakes import FakeDocker
from .test_control_api import Api
from .test_graph_paths import MEDIUM, Checker, Pipeline, RecordingNotifier, World, docker_ran

LATER = timedelta(days=2)  # past the 24 h review deadline of the test policy


def new_pipeline(tmp_path, like: Pipeline | None = None) -> Pipeline:
    """A fresh daemon. With ``like``, the same tools and files: a restarted daemon."""
    if like:
        return Pipeline(tmp_path, like.world, like.docker, like.checker, like.notifier)
    return Pipeline(tmp_path, World(), FakeDocker(), Checker(), RecordingNotifier())


@pytest.fixture
def pipeline(tmp_path):
    return new_pipeline(tmp_path)


def sweeper(pipeline: Pipeline) -> ApprovalService:
    return ApprovalService(pipeline.policy, pipeline.orchestrator, pipeline.evidence)


def escalate(pipeline: Pipeline, sha: str = "abc123"):
    pipeline.world.bandit = ScanOutput(findings=[MEDIUM])
    run, state = pipeline.start(sha=sha)
    assert state["status"] == "AWAITING_REVIEW"
    return run


def test_fr15_overdue_review_is_denied_and_the_developer_told(pipeline):
    docker, notifier = pipeline.docker, pipeline.notifier
    run = escalate(pipeline)

    expired = sweeper(pipeline).expire_overdue(now=utc_now() + LATER)

    assert expired == [run.run_id]
    assert pipeline.orchestrator.get_state(run.run_id)["status"] == "DENIED"
    verdict = pipeline.payloads(run, "REVIEW_VERDICT")[0]
    assert (verdict["reviewer"], verdict["verdict"]) == ("system", "TIMEOUT")
    assert pipeline.payloads(run, "RUN_FINISHED") == [{"status": "DENIED", "outcome": "ESCALATE"}]
    assert [call[1] for call in notifier.named("alert")] == ["Review timed out: change denied"]
    assert not docker_ran(docker)
    assert pipeline.evidence.verify_chain().ok


def test_fr15_review_before_its_deadline_is_left_alone(pipeline):
    notifier = pipeline.notifier
    run = escalate(pipeline)

    assert sweeper(pipeline).expire_overdue(now=utc_now() + timedelta(hours=23)) == []
    assert pipeline.orchestrator.is_awaiting_review(run.run_id)
    assert "REVIEW_VERDICT" not in pipeline.events(run)
    assert notifier.named("alert") == []


def test_fr15_deadline_that_passed_during_a_restart_is_still_found(tmp_path):
    """A second Pipeline on the same files stands in for the restarted Control API."""
    before = new_pipeline(tmp_path)
    run = escalate(before)

    after = new_pipeline(tmp_path, like=before)
    docker = after.docker
    del before
    assert sweeper(after).expire_overdue(now=utc_now() + LATER) == [run.run_id]
    assert after.orchestrator.get_state(run.run_id)["status"] == "DENIED"
    assert after.events(run)[-2:] == ["REVIEW_VERDICT", "RUN_FINISHED"]
    assert not docker_ran(docker)


def test_fr15_review_already_answered_is_skipped(pipeline):
    run = escalate(pipeline)
    pipeline.answer(run, Verdict.APPROVE)

    assert sweeper(pipeline).expire_overdue(now=utc_now() + LATER) == []
    verdicts = pipeline.payloads(run, "REVIEW_VERDICT")
    assert [v["verdict"] for v in verdicts] == ["APPROVE"]  # the reviewer's answer stands
    assert pipeline.orchestrator.get_state(run.run_id)["status"] == "DEPLOYED"


def test_fr15_answer_that_arrives_during_the_sweep_wins(pipeline):
    run = escalate(pipeline)
    service = sweeper(pipeline)
    _, continue_run = service.submit(run.run_id, run.commit_sha, "alice", Verdict.APPROVE)

    assert service.expire_overdue(now=utc_now() + LATER) == []  # claimed, not timed out
    assert continue_run()["status"] == "DEPLOYED"


def test_fr15_one_broken_run_does_not_stop_the_others(pipeline, monkeypatch):
    first = escalate(pipeline, sha="aaa111")
    second = escalate(pipeline, sha="bbb222")
    real = pipeline.orchestrator.begin_resume

    def flaky(approval):
        if approval.run_id == first.run_id:
            raise RuntimeError("checkpoint unreadable")
        return real(approval)

    monkeypatch.setattr(pipeline.orchestrator, "begin_resume", flaky)

    assert sweeper(pipeline).expire_overdue(now=utc_now() + LATER) == [second.run_id]
    assert pipeline.orchestrator.get_state(second.run_id)["status"] == "DENIED"
    assert pipeline.orchestrator.is_awaiting_review(first.run_id)


# ------------------------------------------------------------------ through the Control API


def wait_for_status(api: Api, run_id: str, status: str, timeout_s: float = 5) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        view = api.view(run_id)
        if view["status"] == status or time.monotonic() > deadline:
            return view
        time.sleep(0.02)


class Clock:
    """The daemon's clock. Real time until a test moves it forward."""

    def __init__(self):
        self.ahead = timedelta(0)

    def __call__(self):
        return utc_now() + self.ahead


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def late_api(tmp_path, clock):
    return Api(tmp_path, sweep_interval_s=0.05, clock=clock)


def test_fr15_daemon_denies_an_overdue_review_while_it_runs(late_api, clock):
    with late_api.client:
        run_id = late_api.escalated_run()
        assert late_api.view(run_id)["status"] == "AWAITING_REVIEW"
        clock.ahead = LATER  # only once the run has paused, so no sweep can race the pause
        view = wait_for_status(late_api, run_id, "DENIED")

    assert view["status"] == "DENIED"
    assert late_api.answer(run_id).status_code == 403  # too late to approve
    assert not docker_ran(late_api.docker)


def test_fr15_daemon_start_denies_a_review_that_ran_out_while_it_was_down(late_api, clock):
    run_id = late_api.escalated_run()  # escalated before the daemon (re)starts
    assert late_api.view(run_id)["status"] == "AWAITING_REVIEW"
    clock.ahead = LATER  # the deadline passed while the daemon was down

    with late_api.client:  # entering the client starts the app, as uvicorn does
        view = wait_for_status(late_api, run_id, "DENIED")

    assert view["status"] == "DENIED"
    assert [call[1] for call in late_api.notifier.named("alert")] == [
        "Review timed out: change denied"
    ]
