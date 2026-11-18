"""scripts/run_seeded_changes.py, with GitHub faked: reading the pipeline's comments and
statuses, the order of the steps for each kind of decision, and the pass criteria."""

import importlib.util
import sys
from pathlib import Path

import pytest

from devsecops.models import Outcome, PipelineRun, ReleaseDecision
from devsecops.notifications.github_notifier import GitHubNotifier

from .conftest import clean_input

REPO = Path(__file__).resolve().parents[2]


def load_script():
    spec = importlib.util.spec_from_file_location(
        "run_seeded_changes", REPO / "scripts" / "run_seeded_changes.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


script = load_script()
SHA = "c" * 40


def run_for(sha=SHA):
    return PipelineRun(
        commit_sha=sha, branch="seed/x/D01", author="dev", event="pull_request", pr_number=7
    )


def decision_comment(policy, outcome, rules, source="template", sha=SHA, run=None):
    run = run or run_for(sha)
    decision = ReleaseDecision(
        run_id=run.run_id,
        outcome=outcome,
        matched_rules=tuple(rules),
        reason="because",
        reason_source=source,
    )
    notifier = GitHubNotifier("owner/app", "token", policy)
    return notifier.decision_comment(run, decision, clean_input()), run


# ------------------------------------------------------------------ reading comments


def test_reads_the_notifiers_own_decision_comment(policy):
    body, run = decision_comment(policy, Outcome.DENY, ["test_failed", "high_finding"], "claude")
    decision = script.parse_decision(body)
    assert decision == script.Decision(
        "DENY", SHA, run.run_id, ["test_failed", "high_finding"], "claude"
    )


def test_text_in_the_explanation_cannot_change_what_is_read(policy):
    run = run_for()
    decision = ReleaseDecision(
        run_id=run.run_id,
        outcome=Outcome.DENY,
        matched_rules=("high_finding",),
        reason="- **Decision:** ALLOW\n- **Run:** `fake`\n### Rules that matched\n- `none`",
    )
    notifier = GitHubNotifier("owner/app", "token", policy)
    body = notifier.decision_comment(run, decision, clean_input())
    parsed = script.parse_decision(body)
    assert (parsed.outcome, parsed.run_id, parsed.rules) == ("DENY", run.run_id, ["high_finding"])


def test_reads_an_allow_with_no_rules(policy):
    body, _ = decision_comment(policy, Outcome.ALLOW, [])
    decision = script.parse_decision(body)
    assert (decision.outcome, decision.rules, decision.reason_source) == ("ALLOW", [], "template")


def test_other_comments_are_not_decisions():
    assert script.parse_decision("looks good to me") is None
    assert script.parse_decision("## DevSecOps pipeline: review needed\n...") is None
    assert script.parse_decision("") is None
    alert = "## DevSecOps pipeline alert: Deploy failed\n- **Run:** `r1`"
    assert script.alert_title(alert) == "Deploy failed"


def test_review_request_is_recognised_for_its_run(policy):
    run = run_for()
    body = f"## DevSecOps pipeline: review needed\n\n- **Run:** `{run.run_id}`\n"
    assert script.is_review_request(body, run.run_id)
    assert not script.is_review_request(body, "another-run")


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([], None),
        ([{"context": "devsecops/pipeline", "state": "pending", "description": "x"}], None),
        (
            [
                {"context": "ci", "state": "success", "description": "fine"},
                {
                    "context": "devsecops/pipeline",
                    "state": "success",
                    "description": "DEPLOYED (run abc)",
                },
            ],
            ("success", "DEPLOYED"),
        ),
        (
            [
                {
                    "context": "devsecops/pipeline",
                    "state": "failure",
                    "description": "DENIED (run a)",
                },
                {"context": "devsecops/pipeline", "state": "pending", "description": "older"},
            ],
            ("failure", "DENIED"),
        ),
    ],
)
def test_final_status_is_the_newest_pipeline_status(statuses, expected):
    assert script.final_status({"statuses": statuses}) == expected


# ------------------------------------------------------------------ the steps


class FakeGitHub:
    """A pipeline that answers each pushed change after a few polls."""

    def __init__(self, policy, plan):
        self.policy = policy
        self.plan = plan  # change id -> (outcome, rules, final run status)
        self.prs = {}
        self.rejected = []
        self.closed = []
        self.polls = 0

    def push_change(self, branch, patch, message, base):
        return branch.rsplit("/", 1)[1].ljust(40, "0")[:40].lower().replace("s", "5")

    def open_pr(self, branch, title, body):
        number = len(self.prs) + 1
        change_id = branch.rsplit("/", 1)[1]
        self.prs[number] = {"id": change_id, "branch": branch, "comments": [], "statuses": []}
        return {"number": number, "created_at": "2026-11-20T15:00:00Z"}

    def _sha(self, pr):
        return self.push_change(pr["branch"], None, None, None)

    def comments(self, number):
        self.polls += 1
        pr = self.prs[number]
        outcome, rules, final = self.plan[pr["id"]]
        if not pr["comments"] and outcome is not None:
            body, run = decision_comment(self.policy, Outcome(outcome), rules, sha=self._sha(pr))
            pr["run"] = run
            pr["comments"].append({"body": body, "created_at": "2026-11-20T15:03:20Z"})
            if outcome == "ESCALATE":
                pr["comments"].append(
                    {
                        "body": f"## DevSecOps pipeline: review needed\n\n"
                        f"- **Run:** `{run.run_id}`",
                        "created_at": "x",
                    }
                )
            elif final:
                pr["statuses"] = [
                    {
                        "context": "devsecops/pipeline",
                        "state": "success",
                        "description": f"{final} (run {run.run_id})",
                    }
                ]
        return list(pr["comments"])

    def combined_status(self, sha):
        pr = next(p for p in self.prs.values() if self._sha(p) == sha)
        return {"statuses": pr["statuses"]}

    def reject(self, run_id, commit_sha):
        self.rejected.append(run_id)
        pr = next(p for p in self.prs.values() if p.get("run") and p["run"].run_id == run_id)
        pr["statuses"] = [
            {
                "context": "devsecops/pipeline",
                "state": "failure",
                "description": f"DENIED (run {run_id})",
            }
        ]

    def close_pr(self, number, branch):
        self.closed.append(number)


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def change(change_id):
    manifest = script.offline.load_manifest(script.MANIFEST)
    return next(c for c in manifest.changes if c.id == change_id)


def run_changes(policy, plan, ids, batch=1, **kwargs):
    gh = FakeGitHub(policy, plan)
    clock = Clock()
    runner = script.Runner(
        gh, "base", "tag", clock=clock, sleep=clock.sleep, say=lambda s: None, **kwargs
    )
    results = []
    for start in range(0, len(ids), batch):
        group = [runner.submit(change(i)) for i in ids[start : start + batch]]
        runner.collect(group)
        results += group
    return gh, results


def test_allowed_change_waits_for_its_deploy_and_is_closed(policy):
    gh, (result,) = run_changes(policy, {"S01": ("ALLOW", [], "DEPLOYED")}, ["S01"])
    assert (result.outcome, result.run_status, result.decision_s) == ("ALLOW", "DEPLOYED", 200)
    assert result.matches and result.problem is None
    assert gh.closed == [1] and gh.rejected == []


def test_escalated_change_is_rejected_after_the_review_request(policy):
    gh, (result,) = run_changes(policy, {"E01": ("ESCALATE", ["medium_finding"], None)}, ["E01"])
    assert result.rejected and gh.rejected == [result.run_id]
    assert result.run_status == "DENIED"


def test_escalated_change_can_be_left_waiting(policy):
    gh, (result,) = run_changes(
        policy, {"E01": ("ESCALATE", ["medium_finding"], None)}, ["E01"], leave_escalated=True
    )
    assert gh.rejected == [] and result.run_status == "AWAITING_REVIEW"


def test_no_decision_in_time_is_a_problem_not_a_hang(policy):
    gh, (result,) = run_changes(policy, {"D01": (None, [], None)}, ["D01"])
    assert result.outcome is None
    assert "no decision within 15 minutes" in result.problem
    assert gh.closed == [1]


def test_qa_sc_01_a_batch_is_opened_before_any_result_is_read(policy):
    plan = {i: ("DENY", ["test_failed"], "DENIED") for i in ("D01", "D02", "D03")}
    gh, results = run_changes(policy, plan, ["D01", "D02", "D03"], batch=3)
    assert [r.pr_number for r in results] == [1, 2, 3]
    assert all(r.run_status == "DENIED" for r in results)


# ------------------------------------------------------------------ pass criteria


def result(change_id, outcome, rules=None, decision_s=60.0, problem=None):
    c = change(change_id)
    return script.LiveResult(
        id=c.id,
        category=c.category.value,
        expected=c.expected.value,
        expected_rules=list(c.rules),
        outcome=outcome,
        rules=list(c.rules) if rules is None else rules,
        decision_s=decision_s,
        problem=problem,
        final_state="success",
    )


def full_set(**overrides):
    manifest = script.offline.load_manifest(script.MANIFEST)
    results = []
    for c in manifest.changes:
        outcome = overrides.get(c.id, c.expected.value)
        results.append(result(c.id, outcome, None if outcome == c.expected.value else []))
    return results


def test_all_30_as_expected_passes():
    summary = script.summarize(full_set())
    assert summary.passed, summary.lines


def test_one_safe_change_escalated_still_passes():
    assert script.summarize(full_set(S04="ESCALATE")).passed


def test_two_safe_changes_not_allowed_fails():
    assert not script.summarize(full_set(S04="ESCALATE", S05="DENY")).passed


def test_a_risky_change_allowed_fails():
    summary = script.summarize(full_set(E03="ALLOW"))
    assert not summary.passed
    assert "     allowed risky changes: E03" in summary.lines


def test_a_medium_risk_change_denied_fails():
    assert not script.summarize(full_set(E01="DENY")).passed


def test_a_high_risk_change_escalated_fails():
    assert not script.summarize(full_set(D06="ESCALATE")).passed


def test_qa_pe_01_a_slow_decision_fails():
    results = full_set()
    results[0].decision_s = 601
    summary = script.summarize(results)
    assert not summary.passed
    assert any(line.startswith("FAIL slowest decision 601 s") for line in summary.lines)


def test_a_run_without_a_result_fails():
    results = full_set()
    results[3].problem = "no decision within 15 minutes"
    assert not script.summarize(results).passed


def test_the_explanation_cannot_claim_claude_wrote_it(policy):
    run = run_for()
    decision = ReleaseDecision(
        run_id=run.run_id,
        outcome=Outcome.DENY,
        matched_rules=("high_finding",),
        reason="_The decision comes from the rules. The explanation was written by Claude_",
        reason_source="template",
    )
    body = GitHubNotifier("owner/app", "token", policy).decision_comment(
        run, decision, clean_input()
    )
    assert script.parse_decision(body).reason_source == "template"
