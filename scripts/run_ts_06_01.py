"""TS-06-01 through the real pipeline: a reviewer's decision (FR14, FR15, CLAUDE.md §12).

Four escalated changes, one at a time, on the PRIVATE app repo. Each is a seeded change
from test_changes/ that the pipeline escalates:

    approve   E05  answered APPROVE through approve.yml  -> deployed (DEPLOYED)
    reject    E01  answered REJECT through approve.yml   -> stopped and saved (DENIED)
    timeout   E07  nobody answers                        -> DENIED after the review timeout,
                                                            with the "Review timed out" alert
    restart   E04  nobody answers, and the Control API is down while the deadline passes
                                                         -> DENIED by the sweep at start-up

For every leg it also checks FR14: the review request is posted within
review_notify_sla_s (60 s) of the decision.

The host must run with a short review timeout (review_timeout_s: 120 in the policy the
daemon reads). The script checks the deadline in the review request and stops if it is
not within a few minutes. The restart leg needs two commands that stop and start the
Control API on the host. They are given on the command line, so that the host's address
never goes in this public repo:

    uv run python scripts/run_ts_06_01.py --repo <owner>/<app-repo> \\
        --stop-cmd  'ssh <host> ... systemctl stop devsecops-control-api' \\
        --start-cmd 'ssh <host> ... systemctl start devsecops-control-api' \\
        --json ts-06-01.json
    uv run python scripts/run_ts_06_01.py --repo <owner>/<app-repo> --only reject timeout

Run it only while nothing else uses the pipeline: the restart leg stops the Control API,
and a run in progress at that moment is closed as ERROR (CLAUDE.md §11 item 12). The
approve and reject answers go out under the login `gh` is signed in with, which must be
listed under reviewers in the host's policy.

Exit code: 0 if every leg passed, 1 if one did not, 2 if the run could not start.
"""

import argparse
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


seeded = _load("run_seeded_changes")

TIMED_OUT_ALERT = "Review timed out: change denied"
NOTIFY_SLA_S = 60  # FR14
SWEEP_SLACK_S = 90  # the sweeper runs every 30 s; GitHub and the runner add a little
POLL_S = 10
DECISION_TIMEOUT_S = 15 * 60
FINAL_TIMEOUT_S = 20 * 60  # an approved change deploys and is watched for 5 minutes


@dataclass(frozen=True)
class Leg:
    name: str
    change_id: str
    verdict: str | None  # APPROVE / REJECT, or None when nobody answers
    expected_status: str
    restart: bool = False


LEGS = (
    Leg("approve", "E05", "APPROVE", "DEPLOYED"),
    Leg("reject", "E01", "REJECT", "DENIED"),
    Leg("timeout", "E07", None, "DENIED"),
    Leg("restart", "E04", None, "DENIED", restart=True),
)

_DEADLINE = re.compile(r"\*\*Answer by:\*\* (\d{4}-\d\d-\d\d \d\d:\d\d) UTC")


def _when(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def review_deadline(body: str) -> datetime | None:
    """The "Answer by" time of a review request (minute precision)."""
    match = _DEADLINE.search(body)
    if not match:
        return None
    return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M").replace(tzinfo=UTC)


@dataclass
class LegResult:
    leg: str
    change_id: str
    verdict: str | None
    expected_status: str
    pr_number: int | None = None
    commit_sha: str = ""
    run_id: str | None = None
    outcome: str | None = None
    notify_s: float | None = None  # decision comment -> review request comment
    deadline_after_s: float | None = None  # review request -> "Answer by" (minute precision)
    answered_at: str | None = None
    daemon_down_s: float | None = None
    run_status: str | None = None
    finished_s: float | None = None  # review request -> final commit status
    alerts: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.failures


class Driver:
    def __init__(
        self,
        gh,
        base_sha: str,
        tag: str,
        review_timeout_s: int,
        stop_cmd: str | None = None,
        start_cmd: str | None = None,
        down_s: float | None = None,
        shell: Callable[[str], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        say: Callable[[str], None] = print,
    ):
        self.gh = gh
        self.seed_runner = seeded.Runner(gh, base_sha, tag, say=say)
        self.review_timeout_s = review_timeout_s
        self.stop_cmd, self.start_cmd = stop_cmd, start_cmd
        self.down_s = review_timeout_s + 30 if down_s is None else down_s
        self.shell = shell or _shell
        self.clock, self.sleep, self.now, self.say = clock, sleep, now, say

    # ------------------------------------------------------------------ one leg

    def run(self, leg: Leg, change) -> LegResult:
        result = LegResult(leg.name, leg.change_id, leg.verdict, leg.expected_status)
        pushed = self.seed_runner.submit(change)
        result.pr_number, result.commit_sha = pushed.pr_number, pushed.commit_sha
        if pushed.problem:
            result.failures.append(pushed.problem)
            return result
        try:
            self._leg(leg, result)
        finally:
            try:
                self.gh.close_pr(pushed.pr_number, pushed.branch)
            except RuntimeError as exc:
                self.say(f"{leg.name}: could not close PR #{pushed.pr_number}: {exc}")
        return result

    def _leg(self, leg: Leg, result: LegResult) -> None:
        found = self._wait_for_review_request(result)
        if found is None:
            return
        decision_comment, request = found
        requested_at = _when(request["created_at"])
        result.notify_s = (requested_at - _when(decision_comment["created_at"])).total_seconds()
        if result.notify_s > NOTIFY_SLA_S:
            result.failures.append(
                f"review request {result.notify_s:.0f} s after the decision (FR14: 60 s)"
            )
        deadline = review_deadline(request["body"])
        if deadline is None:
            result.failures.append("the review request has no deadline")
            return
        result.deadline_after_s = (deadline - requested_at).total_seconds()
        # The comment rounds down to the minute, so allow a minute either way.
        if not -60 <= result.deadline_after_s - self.review_timeout_s <= 60:
            result.failures.append(
                f"deadline is {result.deadline_after_s:.0f} s after the request, not about"
                f" {self.review_timeout_s} s: is the short review timeout active on the host?"
            )
            return
        self.say(
            f"{leg.name}: review requested {result.notify_s:.0f} s after the decision,"
            f" deadline in about {self.review_timeout_s} s"
        )

        started_at = None
        if leg.verdict:
            self.gh.answer(result.run_id, result.commit_sha, leg.verdict)
            result.answered_at = self.now().isoformat()
            self.say(f"{leg.name}: answered {leg.verdict} through {seeded.APPROVE_WORKFLOW}")
        elif leg.restart:
            self.say(f"{leg.name}: stopping the Control API for {self.down_s:.0f} s")
            self.shell(self.stop_cmd)
            down_from = self.clock()
            self.sleep(self.down_s)
            self.shell(self.start_cmd)
            result.daemon_down_s = self.clock() - down_from
            started_at = self.now()
            self.say(f"{leg.name}: Control API started again")

        status = self._wait_for_final(result)
        if status is None:
            return
        finished_at = _when(status.get("created_at") or status.get("updated_at"))
        result.finished_s = (finished_at - requested_at).total_seconds()
        self.say(
            f"{leg.name}: finished {result.run_status} {result.finished_s:.0f} s after the request"
        )

        if result.run_status != leg.expected_status:
            result.failures.append(f"ended {result.run_status}, expected {leg.expected_status}")
        timed_out = TIMED_OUT_ALERT in result.alerts
        if leg.verdict is None and not timed_out:
            result.failures.append(f'no "{TIMED_OUT_ALERT}" alert')
        if leg.verdict is not None and timed_out:
            result.failures.append("the run timed out although it was answered")
        if leg.verdict is None and not leg.restart:
            if result.finished_s < self.review_timeout_s - 60:
                result.failures.append(
                    f"denied after {result.finished_s:.0f} s, before the deadline"
                )
            elif result.finished_s > self.review_timeout_s + SWEEP_SLACK_S:
                result.failures.append(
                    f"denied {result.finished_s:.0f} s after the request (timeout"
                    f" {self.review_timeout_s} s + {SWEEP_SLACK_S} s for the sweep)"
                )
        if leg.restart and started_at is not None:
            after_start = (finished_at - started_at).total_seconds()
            if after_start > SWEEP_SLACK_S:
                result.failures.append(
                    f"denied {after_start:.0f} s after the restart, not at start-up"
                )

    def _wait_for_review_request(self, result: LegResult):
        started = self.clock()
        while self.clock() - started <= DECISION_TIMEOUT_S:
            comments = self._comments(result)
            decided = [
                (c, d)
                for c in comments
                if (d := seeded.parse_decision(c.get("body", "")))
                and d.commit_sha == result.commit_sha
            ]
            if decided:
                comment, decision = decided[0]
                result.outcome, result.run_id = decision.outcome, decision.run_id
                if decision.outcome != "ESCALATE":
                    result.failures.append(f"decision was {decision.outcome}, not ESCALATE")
                    return None
                request = next(
                    (
                        c
                        for c in comments
                        if seeded.is_review_request(c.get("body", ""), decision.run_id)
                    ),
                    None,
                )
                if request is not None:
                    return comment, request
            self.sleep(POLL_S)
        result.failures.append(
            "no ESCALATE decision" if result.outcome is None else "no review request"
        )
        return None

    def _wait_for_final(self, result: LegResult) -> dict[str, Any] | None:
        started = self.clock()
        while self.clock() - started <= FINAL_TIMEOUT_S:
            self._comments(result)  # picks up the alerts
            try:
                statuses = self.gh.combined_status(result.commit_sha)
            except RuntimeError:
                statuses = {}
            final = seeded.final_status(statuses)
            if final is not None:
                result.run_status = final[1]
                return next(
                    s
                    for s in statuses.get("statuses", [])
                    if s.get("context") == seeded.STATUS_CONTEXT
                )
            self.sleep(POLL_S)
        result.failures.append(f"no final status within {FINAL_TIMEOUT_S // 60} minutes")
        return None

    def _comments(self, result: LegResult) -> list[dict[str, Any]]:
        try:
            comments = self.gh.comments(result.pr_number)
        except RuntimeError as exc:
            self.say(f"{result.leg}: GitHub did not answer ({exc}); trying again")
            return []
        for comment in comments:
            title = seeded.alert_title(comment.get("body", ""))
            if title and title not in result.alerts:
                result.alerts.append(title)
        return comments


class GitHub(seeded.GitHub):
    def answer(self, run_id: str, commit_sha: str, verdict: str) -> None:
        self._run(
            [
                "gh",
                "workflow",
                "run",
                seeded.APPROVE_WORKFLOW,
                "-R",
                self.repo,
                "-f",
                f"run_id={run_id}",
                "-f",
                f"commit_sha={commit_sha}",
                "-f",
                f"verdict={verdict}",
            ]
        )


def _shell(command: str) -> None:
    done = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)  # noqa: S602 - our own command line
    if done.returncode != 0:
        raise RuntimeError(f"host command failed ({done.returncode}): {done.stderr.strip()[:300]}")


def report(results: list[LegResult]) -> list[str]:
    lines = [f"{'leg':8} {'change':6} {'notify':>7} {'finished':>9} {'status':10} result"]
    for r in results:
        notify = f"{r.notify_s:.0f} s" if r.notify_s is not None else "-"
        finished = f"{r.finished_s:.0f} s" if r.finished_s is not None else "-"
        lines.append(
            f"{r.leg:8} {r.change_id:6} {notify:>7} {finished:>9} {r.run_status or '-':10}"
            f" {'ok' if r.passed else 'FAIL: ' + '; '.join(r.failures)}"
        )
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", required=True, help="owner/name of the PRIVATE app repo")
    parser.add_argument("--only", nargs="+", choices=[leg.name for leg in LEGS], default=[])
    parser.add_argument("--review-timeout-s", type=int, default=120)
    parser.add_argument("--stop-cmd", help="stops the Control API on the host (restart leg)")
    parser.add_argument("--start-cmd", help="starts the Control API on the host (restart leg)")
    parser.add_argument(
        "--down-s", type=float, help="how long the API stays down (default timeout + 30 s)"
    )
    parser.add_argument("--json", type=Path, metavar="FILE")
    args = parser.parse_args(argv)

    legs = [leg for leg in LEGS if not args.only or leg.name in args.only]
    if any(leg.restart for leg in legs) and not (args.stop_cmd and args.start_cmd):
        parser.error(
            "the restart leg needs --stop-cmd and --start-cmd (or leave it out with --only)"
        )

    manifest = seeded.offline.load_manifest(seeded.MANIFEST)
    changes = {c.id: c for c in manifest.changes}
    tag = "ts0601-" + datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    with tempfile.TemporaryDirectory(prefix="ts-06-01-") as tmp:
        gh = GitHub(args.repo, Path(tmp) / "app")
        try:
            base_sha = gh.clone()
            for leg in legs:
                gh.git("apply", "--check", str(seeded.PATCH_DIR / changes[leg.change_id].patch))
        except RuntimeError as exc:
            print(f"cannot start: {exc}", file=sys.stderr)
            return 2
        print(
            f"App repo {args.repo} at {base_sha[:12]}; legs: {', '.join(leg.name for leg in legs)}"
        )
        driver = Driver(
            gh,
            base_sha,
            tag,
            args.review_timeout_s,
            stop_cmd=args.stop_cmd,
            start_cmd=args.start_cmd,
            down_s=args.down_s,
        )
        results = []
        for leg in legs:
            try:
                results.append(driver.run(leg, changes[leg.change_id]))
            except RuntimeError as exc:
                failed = LegResult(leg.name, leg.change_id, leg.verdict, leg.expected_status)
                failed.failures.append(str(exc))
                results.append(failed)

    print()
    print("\n".join(report(results)))
    passed = all(r.passed for r in results)
    print(f"\nTS-06-01: {'PASS' if passed else 'FAIL'}")
    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "repo": args.repo,
                    "base_sha": base_sha,
                    "review_timeout_s": args.review_timeout_s,
                    "results": [asdict(r) for r in results],
                    "passed": passed,
                },
                indent=2,
            )
        )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
