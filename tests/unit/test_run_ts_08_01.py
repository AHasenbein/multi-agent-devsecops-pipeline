"""scripts/run_ts_08_01.py with GitHub and the host faked: the three legs of TS-08-01
(FR16, FR17, FR18) and the rollback timing read from the evidence."""

import importlib.util
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from devsecops.models import Outcome, PipelineRun, ReleaseDecision
from devsecops.notifications.github_notifier import GitHubNotifier

from .conftest import clean_input

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("run_ts_08_01", REPO / "scripts" / "run_ts_08_01.py")
script = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = script
spec.loader.exec_module(script)

T0 = datetime(2026, 11, 20, 15, 0, 0, tzinfo=UTC)


def at(seconds: float) -> str:
    return (T0 + timedelta(seconds=seconds)).isoformat()


def entry(kind, seconds, **payload):
    return {"event_type": kind, "created_at": at(seconds), "payload": payload}


def checks(*oks, start=100):
    return [entry("HEALTH_CHECK", start + 10 * i, ok=ok) for i, ok in enumerate(oks)]


def rolled_back_evidence(rollback_after_s=5, kind="ROLLBACK"):
    found = checks(True, True, False, False, False)  # 3rd failure at 140 s
    return [
        entry("DEPLOY_RESULT", 95, status="STARTED"),
        *found,
        entry(kind, 140 + rollback_after_s, status="ROLLED_BACK"),
    ]


class FakeGitHub:
    def __init__(self, policy, final_status, alert=None, alert_at=150):
        self.notifier = GitHubNotifier("owner/app", "token", policy)
        self.final_status, self.alert, self.alert_at = final_status, alert, alert_at
        self.prs, self.closed = {}, []

    def push_change(self, branch, patch, message, base):
        return branch.rsplit("/", 1)[1].lower().ljust(40, "0")

    def open_pr(self, branch, title, body):
        number = len(self.prs) + 1
        sha = self.push_change(branch, None, None, None)
        run = PipelineRun(
            commit_sha=sha, branch=branch, author="dev", event="pull_request", pr_number=number
        )
        self.prs[number] = {"sha": sha, "run": run}
        return {"number": number, "created_at": at(0)}

    def close_pr(self, number, branch):
        self.closed.append(number)

    def comments(self, number):
        run = self.prs[number]["run"]
        decision = ReleaseDecision(
            run_id=run.run_id,
            outcome=Outcome.ALLOW,
            matched_rules=(),
            reason="ok",
            reason_source="template",
        )
        out = [
            {
                "body": self.notifier.decision_comment(run, decision, clean_input()),
                "created_at": at(60),
            }
        ]
        if self.alert:
            texts = []
            self.notifier._comment = lambda r, text: texts.append(text)
            self.notifier.alert(run, self.alert, "no previous container")
            out.append({"body": texts[0], "created_at": at(self.alert_at)})
        return out

    def combined_status(self, sha):
        return {
            "statuses": [
                {
                    "context": "devsecops/pipeline",
                    "state": "success" if self.final_status == "DEPLOYED" else "failure",
                    "description": f"{self.final_status} (run x)",
                }
            ]
        }


def drive(policy, leg_name, final_status, evidence, alert=None, live=True, **fake):
    gh = FakeGitHub(policy, final_status, alert, **fake)
    blocked = []
    view = {
        "evidence": evidence,
        "chain": {"ok": True, "records_checked": len(evidence)},
        "sandbox": {"live": live, "last_deployment": {"image_tag": "sample_app:abc"}},
    }
    driver = script.Driver(
        gh,
        "base",
        "tag",
        view=lambda run_id: view,
        start_block=blocked.append,
        sleep=lambda s: None,
        say=lambda s: None,
    )
    leg = next(leg for leg in script.LEGS if leg.name == leg_name)
    change = SimpleChange(leg.change_id)
    return gh, blocked, driver.run(leg, change)


class SimpleChange:
    def __init__(self, change_id):
        from types import SimpleNamespace

        self.id = change_id
        self.category = SimpleNamespace(value="system")
        self.expected = SimpleNamespace(value="ALLOW")
        self.rules = ()
        self.patch = script.BROKEN_PATCH
        self.description = "test"


def test_ts_08_01_failed_checks_roll_back_within_the_sla(policy):
    gh, blocked, result = drive(policy, "rollback", "ROLLED_BACK", rolled_back_evidence())
    assert result.passed, result.failures
    assert (result.failed_checks, result.health_checks) == (3, 5)
    assert result.detect_to_rollback_s == 5
    assert blocked == [] and gh.closed == [1]


def test_ts_08_01_slow_rollback_fails(policy):
    _, _, result = drive(
        policy, "rollback", "ROLLED_BACK", rolled_back_evidence(rollback_after_s=200)
    )
    assert any("limit 120 s" in f for f in result.failures)


def test_fr16_a_version_that_never_started_is_not_a_monitored_rollback(policy):
    evidence = [entry("DEPLOY_RESULT", 95, status="FAILED_TO_START")]
    _, _, result = drive(policy, "rollback", "ROLLED_BACK", evidence)
    assert any("did the new version start" in f for f in result.failures)


def test_fr18_blocked_rollback_is_reported_at_once(policy):
    evidence = rolled_back_evidence(kind="ROLLBACK_FAILED")
    gh, blocked, result = drive(
        policy, "blocked", "ROLLBACK_FAILED", evidence, alert=script.ROLLBACK_FAILED_ALERT
    )
    assert result.passed, result.failures
    assert blocked == [gh.prs[1]["sha"]]  # the host was told which version to wait for
    assert result.alert_after_s == 5


def test_fr18_blocked_rollback_without_an_alert_fails(policy):
    evidence = rolled_back_evidence(kind="ROLLBACK_FAILED")
    _, _, result = drive(policy, "blocked", "ROLLBACK_FAILED", evidence)
    assert any("alert" in f for f in result.failures)


def test_restore_leg_needs_a_live_sandbox(policy):
    evidence = [entry("DEPLOY_RESULT", 95, status="HEALTHY"), *checks(True, True)]
    _, _, result = drive(policy, "restore", "DEPLOYED", evidence)
    assert result.passed, result.failures
    _, _, down = drive(policy, "restore", "DEPLOYED", evidence, live=False)
    assert any("not live" in f for f in down.failures)


@pytest.mark.parametrize(
    ("oks", "expected"),
    [
        ((False, True, False, False, False), 5),  # the streak restarts after an ok check
        ((False, False, True, False), None),  # never 3 in a row
    ],
)
def test_detect_to_rollback_counts_consecutive_failures(oks, expected):
    found = checks(*oks)
    last = 100 + 10 * (len(oks) - 1)
    evidence = [*found, entry("ROLLBACK", last + 5)]
    assert script.detect_to_rollback(evidence) == expected


def test_t08_patch_breaks_health_only_after_start():
    text = (REPO / "test_changes" / script.BROKEN_PATCH).read_text()
    assert "HEALTHY_FOR_S = 20" in text and "HTTP_503_SERVICE_UNAVAILABLE" in text
