"""The Control API over the real graph with fake tools (FR1, FR2, FR3, FR14, FR19, FR20;
invariant 8). Background work runs inline, so a request returns when the run has finished
or paused."""

import pytest
from fastapi.testclient import TestClient

from devsecops.api.main import ApiServices, create_app, create_app_from_env
from devsecops.config import ConfigError
from devsecops.models import EventType, HealthCheck, PipelineRun, TestFailure, TestReport
from devsecops.tools import Checkout, ScanOutput
from devsecops.tools import WorkspaceError as FakeWorkspaceError

from ..fakes import FakeDocker
from .test_graph_paths import HIGH, LIVE, MEDIUM, Checker, Pipeline, RecordingNotifier, World

TOKEN = "control-test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
SHA = "a" * 40
BASE = "b" * 40
IMAGE = f"sample_app:{SHA[:12]}"  # the build agent tags images with the short commit id


class Workspaces:
    """Stands in for GitWorkspaces: no git, just what the checkout would have found."""

    def __init__(self):
        self.changed_files = ["sample_app/app/main.py"]
        self.error = None
        self.prepared = []
        self.removed = []

    def prepare(self, run_id, commit_sha, base_sha=None):
        self.prepared.append((run_id, commit_sha, base_sha))
        if self.error:
            raise self.error
        return Checkout(path="/ws", diff="", changed_files=list(self.changed_files))

    def remove(self, run_id):
        self.removed.append(run_id)


class Api:
    def __init__(self, tmp_path, submit=None):
        self.world = World()
        self.docker = FakeDocker()
        self.notifier = RecordingNotifier()
        self.pipeline = Pipeline(tmp_path, self.world, self.docker, Checker(), self.notifier)
        self.workspaces = Workspaces()
        self.probe = HealthCheck(ok=True, status_code=200, latency_ms=3.0)
        self.client = TestClient(
            create_app(
                ApiServices(
                    policy=self.pipeline.policy,
                    evidence=self.pipeline.evidence,
                    orchestrator=self.pipeline.orchestrator,
                    workspaces=self.workspaces,
                    token=TOKEN,
                    sandbox_probe=lambda: self.probe,
                    submit=submit or (lambda work: work()),
                )
            ),
            headers=AUTH,
        )

    def start(self, event="push", **extra):
        body = {"commit_sha": SHA, "branch": "main", "author": "dev", "event": event, **extra}
        response = self.client.post("/runs", json=body)
        assert response.status_code == 202, response.text
        return response.json()["run_id"]

    def view(self, run_id):
        response = self.client.get(f"/runs/{run_id}")
        assert response.status_code == 200, response.text
        return response.json()

    def answer(self, run_id, verdict="APPROVE", reviewer="alice", commit_sha=SHA):
        body = {
            "run_id": run_id,
            "commit_sha": commit_sha,
            "reviewer": reviewer,
            "verdict": verdict,
        }
        return self.client.post("/runs/approval", json=body)

    def escalated_run(self, event="push"):
        self.world.bandit = ScanOutput(findings=[MEDIUM])
        return self.start(event)


@pytest.fixture
def api(tmp_path):
    return Api(tmp_path)


# ------------------------------------------------------------------ access


def test_health_needs_no_token(api):
    response = api.client.get("/health", headers={"Authorization": ""})
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/runs"),
        ("GET", "/runs/some-run"),
        ("POST", "/runs"),
        ("POST", "/runs/approval"),
        ("GET", "/policies"),
    ],
)
@pytest.mark.parametrize("header", ["", "Bearer wrong-token", f"Basic {TOKEN}", TOKEN])
def test_every_other_route_needs_the_bearer_token(api, method, path, header):
    response = api.client.request(method, path, headers={"Authorization": header}, json={})
    assert response.status_code == 401
    assert api.workspaces.prepared == []  # nothing was started


def test_no_docs_pages_are_served_without_the_token(api):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert api.client.get(path, headers={"Authorization": ""}).status_code == 404


def test_app_refuses_to_start_without_a_token(api, tmp_path):
    services = ApiServices(
        policy=api.pipeline.policy,
        evidence=api.pipeline.evidence,
        orchestrator=api.pipeline.orchestrator,
        workspaces=api.workspaces,
        token="  ",
        sandbox_probe=lambda: api.probe,
        submit=lambda work: work(),
    )
    with pytest.raises(ValueError, match="CONTROL_API_TOKEN is not set"):
        create_app(services)


# ------------------------------------------------------------------ POST /runs (FR1, FR2)


def test_fr1_post_runs_starts_a_run_and_the_view_shows_its_record(api):
    run_id = api.start()
    view = api.view(run_id)

    assert view["status"] == "DEPLOYED"
    assert view["outcome"] == "ALLOW"
    assert view["decided"] is True
    assert view["decision"]["matched_rules"] == []
    assert (view["commit_sha"], view["branch"], view["author"]) == (SHA, "main", "dev")
    assert api.docker.containers[LIVE]["image"] == IMAGE

    # FR2 and FR19: the whole record, in order, with a chain that verifies.
    events = [entry["event_type"] for entry in view["evidence"]]
    assert events[0] == "RUN_STARTED" and events[-1] == "RUN_FINISHED"
    assert view["evidence"][0]["payload"]["run_id"] == run_id
    assert view["chain"] == {
        "ok": True,
        "records_checked": len(events),
        "first_bad_seq": None,
        "error": None,
    }


def test_checkout_gets_the_commit_and_base_and_is_removed_afterwards(api):
    run_id = api.start(base_sha=BASE.upper())
    assert api.workspaces.prepared == [(run_id, SHA, BASE)]
    assert api.workspaces.removed == [run_id]


def test_all_zero_base_of_a_new_branch_is_passed_on_as_no_base(api):
    run_id = api.start(base_sha="0" * 40)
    assert api.workspaces.prepared == [(run_id, SHA, None)]


def test_fr12_changed_files_from_the_checkout_reach_the_rules(api):
    api.workspaces.changed_files = ["sample_app/Dockerfile"]
    view = api.view(api.start())
    assert view["status"] == "AWAITING_REVIEW"
    assert view["decision"]["matched_rules"] == ["important_file_changed"]


def test_pull_request_run_is_deployed_like_a_push(api):
    """CLAUDE.md §11 item 2."""
    view = api.view(api.start("pull_request", pr_number=7))
    assert (view["status"], view["event"], view["pr_number"]) == ("DEPLOYED", "pull_request", 7)
    assert api.docker.containers[LIVE]["image"] == IMAGE


def test_daemon_start_closes_a_run_the_previous_process_left_unfinished(api):
    """CLAUDE.md §11 item 12: without this the workflow would poll a stuck run forever."""
    run = PipelineRun(commit_sha=SHA, branch="main", author="dev", event="push")
    api.pipeline.evidence.append(run.run_id, EventType.RUN_STARTED, run)  # then the process died
    stuck = api.view(run.run_id)
    assert (stuck["status"], stuck["decided"]) == ("RUNNING", False)

    with api.client:  # entering the client starts the app, as uvicorn does
        view = api.view(run.run_id)

    assert (view["status"], view["decided"]) == ("ERROR", True)
    assert [entry["event_type"] for entry in view["evidence"]] == [
        "RUN_STARTED",
        "AGENT_ERROR",
        "RUN_FINISHED",
    ]
    assert [call[:2] for call in api.notifier.calls] == [
        ("alert", "Pipeline run interrupted"),
        ("set_status", "error"),
    ]


@pytest.mark.parametrize(
    "change",
    [
        {"commit_sha": "abc123"},
        {"commit_sha": "main"},
        {"base_sha": "HEAD~1"},
        {"event": "schedule"},
        {"branch": ""},
        {"pr_number": 0},
        {"workspace": "/etc"},  # the checkout path is never taken from the request
    ],
)
def test_bad_run_request_is_rejected_and_starts_nothing(api, change):
    body = {"commit_sha": SHA, "branch": "main", "author": "dev", "event": "push", **change}
    assert api.client.post("/runs", json=body).status_code == 422
    assert api.workspaces.prepared == []


def test_post_runs_returns_before_the_pipeline_runs(tmp_path):
    waiting = []
    api = Api(tmp_path, submit=waiting.append)

    run_id = api.start()
    view = api.view(run_id)
    assert (view["status"], view["decided"], view["evidence"]) == ("PENDING", False, [])
    assert [run["run_id"] for run in api.client.get("/runs").json()] == [run_id]

    waiting.pop()()  # the background thread gets to it
    assert api.view(run_id)["status"] == "DEPLOYED"
    assert [run["run_id"] for run in api.client.get("/runs").json()] == [run_id]


def test_fr3_failed_checkout_still_leaves_a_record_and_tells_the_developer(api):
    api.workspaces.error = FakeWorkspaceError("commit was not found in the app repo")
    run_id = api.start()
    view = api.view(run_id)

    assert (view["status"], view["decided"], view["decision"]) == ("ERROR", True, None)
    assert [entry["event_type"] for entry in view["evidence"]] == [
        "RUN_STARTED",
        "AGENT_ERROR",
        "RUN_FINISHED",
    ]
    assert view["evidence"][1]["payload"]["errors"] == [
        "checkout failed: commit was not found in the app repo"
    ]
    assert api.notifier.named("alert")[0][1] == "Pipeline run could not start"
    assert api.notifier.calls[-1][:2] == ("set_status", "error")
    assert api.workspaces.removed == [run_id]


def test_fr3_setup_problem_is_visible_in_the_view(api):
    api.world.setup_problems = ["Docker is not installed or the daemon is not running"]
    view = api.view(api.start())
    assert (view["status"], view["decided"]) == ("ERROR", True)
    assert view["evidence"][1]["event_type"] == "SETUP_FAILED"


# ------------------------------------------------------------------ GET /runs (FR20)


def test_ts_04_01_denied_run_shows_the_failed_test_and_the_finding(api):
    failure = TestFailure(test_name="test_create_note", file="tests/test_main.py", line=31)
    api.world.test_report = TestReport(passed=11, failed=1, coverage_pct=96, failures=[failure])
    api.world.bandit = ScanOutput(findings=[HIGH])
    view = api.view(api.start())

    assert (view["status"], view["outcome"], view["decided"]) == ("DENIED", "DENY", True)
    assert view["decision"]["matched_rules"] == ["test_failed", "high_finding"]
    assert view["failed_tests"][0]["test_name"] == "test_create_note"
    assert (view["findings"][0]["rule_id"], view["findings"][0]["line"]) == ("B602", 9)
    assert LIVE not in api.docker.containers  # nothing was deployed


def test_fr20_list_runs_is_newest_first_and_honours_the_limit(api):
    api.world.bandit = ScanOutput(findings=[HIGH])
    denied = api.start()
    api.world.bandit = ScanOutput()
    allowed = api.start()

    runs = api.client.get("/runs").json()
    assert [(run["run_id"], run["status"], run["outcome"]) for run in runs] == [
        (allowed, "DEPLOYED", "ALLOW"),
        (denied, "DENIED", "DENY"),
    ]
    assert [run["run_id"] for run in api.client.get("/runs?limit=1").json()] == [allowed]
    assert api.client.get("/runs?limit=0").status_code == 422


def test_unknown_run_is_a_404(api):
    assert api.client.get("/runs/no-such-run").status_code == 404


def test_uc_09_sandbox_status_is_live_when_the_sandbox_answers(api):
    sandbox = api.view(api.start())["sandbox"]
    assert sandbox["live"] is True
    assert sandbox["last_health"]["latency_ms"] == 3.0
    assert sandbox["last_deployment"]["status"] == "HEALTHY"
    assert sandbox["last_deployment"]["image_tag"] == IMAGE


def test_uc_09_sandbox_down_shows_the_last_recorded_check(api):
    run_id = api.start()
    api.probe = HealthCheck(ok=False, error="ConnectError: connection refused")
    sandbox = api.view(run_id)["sandbox"]
    assert sandbox["live"] is False
    assert sandbox["last_health"]["ok"] is True  # the last check the run recorded
    assert sandbox["last_health"]["status_code"] == 200


def test_get_policies_returns_the_trusted_policy(api):
    policy = api.client.get("/policies").json()
    assert policy["reviewers"] == ["alice", "bob"]
    assert policy["thresholds"] == {"min_coverage_pct": 80.0}
    assert {rule["id"] for rule in policy["rules"]} >= {"test_failed", "high_finding"}


# ------------------------------------------------------------------ POST /runs/approval (FR14)


def test_escalated_run_waits_and_counts_as_decided(api):
    view = api.view(api.escalated_run())
    assert (view["status"], view["outcome"], view["decided"]) == (
        "AWAITING_REVIEW",
        "ESCALATE",
        True,
    )
    assert view["review_deadline"] and view["approval"] is None
    assert LIVE not in api.docker.containers


def test_fr14_listed_reviewer_approves_and_the_change_deploys(api):
    run_id = api.escalated_run()
    response = api.answer(run_id, reviewer="ALICE")  # GitHub logins ignore case

    assert response.status_code == 200
    assert response.json() == {"run_id": run_id, "reviewer": "ALICE", "verdict": "APPROVE"}
    view = api.view(run_id)
    assert view["status"] == "DEPLOYED"
    assert (view["approval"]["reviewer"], view["approval"]["verdict"]) == ("ALICE", "APPROVE")
    assert "REVIEW_VERDICT" in [entry["event_type"] for entry in view["evidence"]]
    assert api.docker.containers[LIVE]["image"] == IMAGE


def test_fr14_reviewer_rejects_and_the_run_is_denied(api):
    run_id = api.escalated_run()
    assert api.answer(run_id, "REJECT", reviewer="bob").status_code == 200
    view = api.view(run_id)
    assert (view["status"], view["approval"]["verdict"]) == ("DENIED", "REJECT")
    assert LIVE not in api.docker.containers


def test_invariant_8_unlisted_reviewer_is_refused(api):
    run_id = api.escalated_run()
    response = api.answer(run_id, reviewer="mallory")
    assert response.status_code == 403
    assert response.json() == {"detail": "reviewer is not listed in policy.yaml"}
    assert api.view(run_id)["status"] == "AWAITING_REVIEW"


def test_invariant_8_approval_for_another_commit_is_refused(api):
    run_id = api.escalated_run()
    assert api.answer(run_id, commit_sha="c" * 40).status_code == 403
    assert api.view(run_id)["status"] == "AWAITING_REVIEW"


def test_invariant_8_run_that_is_not_waiting_is_refused(api):
    finished = api.start()
    assert api.answer(finished).status_code == 403
    assert api.answer("no-such-run").status_code == 403


def test_second_answer_for_the_same_run_is_refused(api):
    run_id = api.escalated_run()
    assert api.answer(run_id, "REJECT").status_code == 200
    assert api.answer(run_id, "APPROVE").status_code == 403
    assert api.view(run_id)["status"] == "DENIED"


def test_fr15_nobody_can_send_a_timeout_verdict(api):
    """Only the pipeline's own timer may time a review out."""
    run_id = api.escalated_run()
    assert api.answer(run_id, "TIMEOUT").status_code == 422
    assert api.view(run_id)["status"] == "AWAITING_REVIEW"


def test_answer_is_accepted_before_the_run_continues(tmp_path):
    waiting = []
    api = Api(tmp_path, submit=lambda work: waiting.append(work))
    run_id = api.escalated_run()
    waiting.pop()()  # the run itself: pauses for review

    assert api.answer(run_id).status_code == 200
    assert api.view(run_id)["status"] == "AWAITING_REVIEW"  # deploy has not begun yet
    assert api.answer(run_id).status_code == 403  # but the run is already claimed
    waiting.pop()()
    assert api.view(run_id)["status"] == "DEPLOYED"


# ------------------------------------------------------------------ the real wiring


def test_daemon_wiring_builds_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("DEVSECOPS_APP_REPO", "someone/notes-app")
    monkeypatch.setenv("DEVSECOPS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("CONTROL_API_TOKEN", TOKEN)
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test_value")

    client = TestClient(create_app_from_env())

    assert client.get("/health").status_code == 200
    assert client.get("/policies").status_code == 401
    assert client.get("/policies", headers=AUTH).json()["reviewers"]
    assert client.get("/runs", headers=AUTH).json() == []
    assert (tmp_path / "state" / "evidence.db").exists()


def test_daemon_needs_the_app_repo_and_the_token(tmp_path, monkeypatch):
    monkeypatch.setenv("DEVSECOPS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("DEVSECOPS_APP_REPO", raising=False)
    monkeypatch.setenv("CONTROL_API_TOKEN", TOKEN)
    with pytest.raises(ConfigError, match="DEVSECOPS_APP_REPO is not set"):
        create_app_from_env()

    monkeypatch.setenv("DEVSECOPS_APP_REPO", "someone/notes-app")
    monkeypatch.delenv("CONTROL_API_TOKEN")
    with pytest.raises(ValueError, match="CONTROL_API_TOKEN is not set"):
        create_app_from_env()
