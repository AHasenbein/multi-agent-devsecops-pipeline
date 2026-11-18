"""scripts/run_ts_06_01.py with GitHub and the host faked: the four legs of TS-06-01
(FR14, FR15) and what each one checks."""

import importlib.util
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from devsecops.models import Outcome, PipelineRun, ReleaseDecision
from devsecops.notifications.github_notifier import GitHubNotifier

from .conftest import clean_input

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("run_ts_06_01", REPO / "scripts" / "run_ts_06_01.py")
script = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = script
spec.loader.exec_module(script)

T0 = datetime(2026, 11, 20, 15, 0, 0, tzinfo=UTC)
TIMEOUT = 120


def stamp(seconds: float) -> str:
    return (T0 + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds

    def wall(self):
        return T0 + timedelta(seconds=self.now)


class FakePipeline:
    """Escalates every change 60 s after the PR, asks for review 5 s later, and ends the
    run the way the real pipeline would for the answer it gets (or does not get)."""

    def __init__(self, policy, clock, deadline_s=TIMEOUT, notify_s=5, answer_s=20):
        self.policy, self.clock = policy, clock
        self.deadline_s, self.notify_s, self.answer_s = deadline_s, notify_s, answer_s
        self.notifier = GitHubNotifier("owner/app", "token", policy)
        self.prs = {}
        self.answers = []
        self.closed = []
        self.down_from = self.up_at = None

    # the seeded Runner's half
    def push_change(self, branch, patch, message, base):
        return branch.rsplit("/", 1)[1].lower().ljust(40, "0")

    def open_pr(self, branch, title, body):
        number = len(self.prs) + 1
        sha = self.push_change(branch, None, None, None)
        run = PipelineRun(
            commit_sha=sha, branch=branch, author="dev", event="pull_request", pr_number=number
        )
        self.prs[number] = {"sha": sha, "run": run, "opened": self.clock.now, "answer": None}
        return {"number": number, "created_at": stamp(self.clock.now)}

    def close_pr(self, number, branch):
        self.closed.append(number)

    def answer(self, run_id, commit_sha, verdict):
        pr = next(p for p in self.prs.values() if p["run"].run_id == run_id)
        assert pr["sha"] == commit_sha
        pr["answer"] = (verdict, self.clock.now)
        self.answers.append(verdict)

    def stop(self):
        self.down_from = self.clock.now

    def start(self):
        self.up_at = self.clock.now

    # what the pipeline has posted by now
    def _timeline(self, pr):
        decided = pr["opened"] + 60
        requested = decided + self.notify_s
        comments, final = [], None
        now = self.clock.now
        if now >= decided:
            decision = ReleaseDecision(
                run_id=pr["run"].run_id,
                outcome=Outcome.ESCALATE,
                matched_rules=("medium_finding",),
                reason="because",
                reason_source="template",
            )
            body = self.notifier.decision_comment(pr["run"], decision, clean_input())
            comments.append({"body": body, "created_at": stamp(decided)})
        if now >= requested:
            # The notifier rounds the deadline down to the minute; so does the fake.
            deadline = (T0 + timedelta(seconds=requested + self.deadline_s)).replace(second=0)
            lines = []
            self.notifier._comment = lambda run, text: lines.append(text)
            self.notifier.request_review(pr["run"], decision, ("rev",), deadline)
            comments.append({"body": lines[0], "created_at": stamp(requested)})
            if pr["answer"]:
                verdict, at = pr["answer"]
                if verdict == "APPROVE":
                    final = ("success", "DEPLOYED", at + 330)
                else:
                    final = ("failure", "DENIED", at + 15)
            else:
                expires = requested + self.deadline_s
                if self.down_from is not None and self.down_from <= expires:
                    expires = self.up_at if self.up_at is not None else None
                if expires is not None:
                    swept = expires + 25
                    final = ("failure", "DENIED", swept)
                    if now >= swept:
                        alert = []
                        self.notifier._comment = lambda run, text: alert.append(text)
                        self.notifier.alert(pr["run"], script.TIMED_OUT_ALERT, "x")
                        comments.append({"body": alert[0], "created_at": stamp(swept)})
        if final and now < final[2]:
            final = None
        return comments, final

    def comments(self, number):
        return self._timeline(self.prs[number])[0]

    def combined_status(self, sha):
        pr = next(p for p in self.prs.values() if p["sha"] == sha)
        _, final = self._timeline(pr)
        if final is None:
            return {"statuses": [{"context": "devsecops/pipeline", "state": "pending"}]}
        state, status, at = final
        return {
            "statuses": [
                {
                    "context": "devsecops/pipeline",
                    "state": state,
                    "description": f"{status} (run {pr['run'].run_id})",
                    "created_at": stamp(at),
                }
            ]
        }


def drive(policy, leg_name, **fake):
    clock = Clock()
    gh = FakePipeline(policy, clock, **fake)
    calls = {gh_cmd: getattr(gh, gh_cmd) for gh_cmd in ("stop", "start")}
    driver = script.Driver(
        gh,
        "base",
        "tag",
        TIMEOUT,
        stop_cmd="stop",
        start_cmd="start",
        shell=lambda cmd: calls[cmd](),
        clock=clock,
        sleep=clock.sleep,
        now=clock.wall,
        say=lambda s: None,
    )
    leg = next(leg for leg in script.LEGS if leg.name == leg_name)
    change = next(
        c
        for c in script.seeded.offline.load_manifest(script.seeded.MANIFEST).changes
        if c.id == leg.change_id
    )
    return gh, driver.run(leg, change)


def test_ts_06_01_approve_deploys(policy):
    gh, result = drive(policy, "approve")
    assert result.passed, result.failures
    assert gh.answers == ["APPROVE"] and result.run_status == "DEPLOYED"
    assert gh.closed == [1]


def test_ts_06_01_reject_stops_the_run(policy):
    gh, result = drive(policy, "reject")
    assert result.passed, result.failures
    assert gh.answers == ["REJECT"] and result.run_status == "DENIED"


def test_fr15_no_answer_is_denied_after_the_timeout_with_an_alert(policy):
    gh, result = drive(policy, "timeout")
    assert result.passed, result.failures
    assert gh.answers == []
    assert script.TIMED_OUT_ALERT in result.alerts
    assert TIMEOUT <= result.finished_s <= TIMEOUT + script.SWEEP_SLACK_S


def test_fr15_deadline_passed_while_the_daemon_was_down_is_denied_at_start(policy):
    gh, result = drive(policy, "restart")
    assert result.passed, result.failures
    assert gh.down_from is not None and gh.up_at - gh.down_from >= TIMEOUT
    assert result.daemon_down_s >= TIMEOUT


def test_fr14_slow_review_request_fails(policy):
    _, result = drive(policy, "reject", notify_s=90)
    assert any("FR14" in f for f in result.failures)


def test_long_review_timeout_on_the_host_stops_the_leg(policy):
    gh, result = drive(policy, "timeout", deadline_s=86400)
    assert any("short review timeout" in f for f in result.failures)
    assert gh.closed == [1]  # the PR is closed even when the leg stops early


def test_review_deadline_is_read_from_the_request(policy):
    run = PipelineRun(commit_sha="a" * 40, branch="b", author="d", event="push")
    decision = ReleaseDecision(
        run_id=run.run_id,
        outcome=Outcome.ESCALATE,
        matched_rules=("x",),
        reason="r",
        reason_source="template",
    )
    notifier = GitHubNotifier("owner/app", "token", policy)
    lines = []
    notifier._comment = lambda run, text: lines.append(text)
    notifier.request_review(run, decision, ("rev",), T0)
    assert script.review_deadline(lines[0]) == T0
    assert script.review_deadline("no deadline here") is None
