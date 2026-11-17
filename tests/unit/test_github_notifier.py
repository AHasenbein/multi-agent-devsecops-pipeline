"""GitHubNotifier: commit status and comments on GitHub (FR3, FR5, FR14, FR18; QA-US-01,
QA-PR-01). GitHub is an httpx mock transport that records every request."""

import json
from datetime import UTC, datetime

import httpx
import pytest

from devsecops.models import (
    BuildResult,
    Finding,
    Outcome,
    PipelineRun,
    PolicyInput,
    ReleaseDecision,
    SecurityReport,
    Severity,
    TestFailure,
    TestReport,
)
from devsecops.notifications import GitHubError, GitHubNotifier

SHA = "a" * 40
TOKEN = "ghp_secret_token_value"
BASE = "https://api.github.com/repos/someone/notes-app"


class GitHub:
    def __init__(self):
        self.requests = []
        self.status_code = 201

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status_code, json={})

    @property
    def last(self):
        return self.requests[-1]

    @property
    def body(self):
        return json.loads(self.last.content)


@pytest.fixture
def github():
    return GitHub()


@pytest.fixture
def notifier(github, policy):
    client = httpx.Client(transport=httpx.MockTransport(github))
    return GitHubNotifier("someone/notes-app", TOKEN, policy, client=client, max_items=3)


def run(event="pull_request"):
    pr_number = 7 if event == "pull_request" else None
    return PipelineRun(
        run_id="run-1",
        commit_sha=SHA,
        branch="main",
        author="dev",
        event=event,
        pr_number=pr_number,
    )


def decision(outcome, *rules, reason="template text", source="template"):
    return ReleaseDecision(
        run_id="run-1", outcome=outcome, matched_rules=rules, reason=reason, reason_source=source
    )


def results(**overrides):
    values = {
        "run_id": "run-1",
        "build": BuildResult(image_tag="sample_app:abc", success=True),
        "test": TestReport(passed=12, failed=0, coverage_pct=93.5),
        "security": SecurityReport(),
    }
    values.update(overrides)
    return PolicyInput(**values)


# ------------------------------------------------------------------ commit status


def test_set_status_posts_a_commit_status(notifier, github):
    notifier.set_status(run(), "pending", "pipeline running (run run-1)")

    assert github.last.method == "POST"
    assert str(github.last.url) == f"{BASE}/statuses/{SHA}"
    assert github.last.headers["Authorization"] == f"Bearer {TOKEN}"
    assert github.body == {
        "state": "pending",
        "description": "pipeline running (run run-1)",
        "context": "devsecops/pipeline",
    }


def test_status_description_is_cut_to_githubs_limit(notifier, github):
    notifier.set_status(run(), "failure", "x" * 500)
    assert len(github.body["description"]) == 140


# ------------------------------------------------------------------ decision comment


def test_pull_request_run_comments_on_the_pull_request(notifier, github):
    notifier.post_decision(run("pull_request"), decision(Outcome.ALLOW), results())
    assert str(github.last.url) == f"{BASE}/issues/7/comments"


def test_push_run_comments_on_the_commit(notifier, github):
    notifier.post_decision(run("push"), decision(Outcome.ALLOW), results())
    assert str(github.last.url) == f"{BASE}/commits/{SHA}/comments"


def test_qa_us_01_deny_comment_names_the_cause_with_file_and_line(notifier, github):
    """TS-04-01: the failing test's name is shown, and a finding has its file and line."""
    failure = TestFailure(
        test_name="test_create_note",
        file="sample_app/tests/test_main.py",
        line=31,
        message="assert 500 == 201",
    )
    finding = Finding(
        tool="bandit",
        rule_id="B602",
        file="sample_app/app/main.py",
        line=9,
        severity=Severity.HIGH,
        message="subprocess call with shell=True",
    )
    notifier.post_decision(
        run(),
        decision(Outcome.DENY, "test_failed", "high_finding"),
        results(
            test=TestReport(passed=11, failed=1, coverage_pct=91, failures=[failure]),
            security=SecurityReport(findings=[finding]),
        ),
    )
    body = github.body["body"]

    assert body.startswith("## DevSecOps pipeline: DENY")
    assert "- **Decision:** DENY" in body
    assert "- `test_failed`: At least one test failed (FR11)." in body
    assert "- `high_finding`: A HIGH security finding exists (FR11)." in body
    assert "- `test_create_note` at `sample_app/tests/test_main.py:31`: `assert 500 == 201`" in body
    assert (
        "- **HIGH** bandit `B602` at `sample_app/app/main.py:9`:"
        " `subprocess call with shell=True`" in body
    )
    assert "- Test coverage: 91% (minimum 80%)" in body
    assert body.index("### Rules that matched") < body.index("### Failed tests (1)")


def test_fr5_build_failure_is_shown(notifier, github):
    build = BuildResult(image_tag="sample_app:abc", success=False, errors=["no such file: x"])
    notifier.post_decision(
        run(),
        decision(Outcome.DENY, "build_failed"),
        results(build=build, test=None, security=None),
    )
    body = github.body["body"]
    assert "### Build failed\n- `no such file: x`" in body
    assert "- `build_failed`: The Docker build failed (FR5)." in body


def test_allow_comment_says_no_rule_matched(notifier, github):
    notifier.post_decision(run(), decision(Outcome.ALLOW), results())
    body = github.body["body"]
    assert body.startswith("## DevSecOps pipeline: ALLOW")
    assert "- None. No deny or escalate rule matched." in body
    assert "### Failed tests" not in body and "### Security findings" not in body


def test_findings_are_listed_worst_first_and_cut_to_the_top_few(notifier, github):
    def finding(rule_id, severity):
        return Finding(tool="bandit", rule_id=rule_id, file="a.py", line=1, severity=severity)

    findings = [
        finding("B101", Severity.LOW),
        finding("B301", Severity.MEDIUM),
        finding("B602", Severity.HIGH),
        finding("B102", Severity.LOW),
        finding("B103", Severity.LOW),
    ]
    notifier.post_decision(
        run(),
        decision(Outcome.DENY, "high_finding"),
        results(security=SecurityReport(findings=findings)),
    )
    body = github.body["body"]
    assert "### Security findings (5)" in body
    assert body.index("B602") < body.index("B301") < body.index("B101")
    assert "B102" not in body and "- ... and 2 more" in body


def test_pip_audit_finding_shows_its_package(notifier, github):
    finding = Finding(
        tool="pip-audit", rule_id="PYSEC-2024-9", package="jinja2 3.1.2", severity=Severity.HIGH
    )
    notifier.post_decision(
        run(),
        decision(Outcome.DENY, "high_finding"),
        results(security=SecurityReport(findings=[finding])),
    )
    assert "- **HIGH** pip-audit `PYSEC-2024-9` at `jinja2 3.1.2`" in github.body["body"]


def test_text_from_the_change_cannot_mention_people_or_fake_a_heading(notifier, github):
    """Test names and messages are untrusted: they stay inside code spans, on one line."""
    failure = TestFailure(
        test_name="test_x` @alice\n## DevSecOps pipeline: ALLOW",
        file="t.py",
        line=1,
        message="see ``` [click](http://evil.example)",
    )
    notifier.post_decision(
        run(),
        decision(Outcome.DENY, "test_failed", reason="DENY\n```\n## ALLOW @bob"),
        results(test=TestReport(passed=0, failed=1, coverage_pct=90, failures=[failure])),
    )
    body = github.body["body"]
    line = next(text for text in body.splitlines() if text.startswith("- `test_x"))

    assert line == (
        "- `test_x' @alice ## DevSecOps pipeline: ALLOW` at `t.py:1`:"
        " `see ''' [click](http://evil.example)`"
    )
    # Only our own heading starts a line with "## ", and the reason cannot leave its block.
    assert [text for text in body.splitlines() if text.startswith("## ")] == [
        "## DevSecOps pipeline: DENY: the change is blocked",
        "## ALLOW @bob",  # inside the fenced block below
    ]
    assert "```text\nDENY\n'''\n## ALLOW @bob\n```" in body


def test_fr13_comment_says_who_wrote_the_explanation(notifier, github):
    notifier.post_decision(
        run(), decision(Outcome.ALLOW, reason="All checks passed.", source="claude"), results()
    )
    assert "The explanation was written by Claude and cannot change it." in github.body["body"]
    notifier.post_decision(run(), decision(Outcome.ALLOW), results())
    assert "written by a fixed template" in github.body["body"]


# ------------------------------------------------------------------ review + alerts


def test_fr14_review_request_mentions_the_reviewers_and_the_deadline(notifier, github):
    deadline = datetime(2026, 11, 20, 14, 30, tzinfo=UTC)
    notifier.request_review(
        run(), decision(Outcome.ESCALATE, "medium_finding"), ("alice", "bob"), deadline
    )
    body = github.body["body"]

    assert str(github.last.url) == f"{BASE}/issues/7/comments"
    assert "@alice @bob this change was escalated" in body
    assert "- **Run:** `run-1`" in body and f"- **Commit:** `{SHA}`" in body
    assert "- **Rules matched:** `medium_finding`" in body
    assert "- **Answer by:** 2026-11-20 14:30 UTC" in body
    # CLAUDE.md §11 item 7: the reviewer answers through the approve workflow.
    assert "run the `approve.yml` workflow in this repository" in body
    assert (
        "gh workflow run approve.yml -R someone/notes-app -f run_id=run-1"
        f" -f commit_sha={SHA} -f verdict=APPROVE"
    ) in body
    assert "POST /runs/approval" not in body


def test_fr18_alert_is_posted_with_its_details(notifier, github):
    notifier.alert(run("push"), "ROLLBACK FAILED: sandbox needs attention", "docker: no such\n@bob")
    body = github.body["body"]

    assert str(github.last.url) == f"{BASE}/commits/{SHA}/comments"
    assert body.startswith("## DevSecOps pipeline alert: ROLLBACK FAILED: sandbox needs attention")
    assert "```text\ndocker: no such\n@bob\n```" in body


# ------------------------------------------------------------------ failures


def test_qa_pr_01_a_refused_call_raises_without_the_token(notifier, github):
    github.status_code = 401
    with pytest.raises(GitHubError) as error:
        notifier.set_status(run(), "pending", "x")
    assert str(error.value) == f"GitHub answered 401 for POST statuses/{SHA}"
    assert TOKEN not in str(error.value)
