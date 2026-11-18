"""TS-08-01 through the real pipeline: a failed deploy rolls back (FR16, FR17, FR18).

Three pull requests, one at a time, on the PRIVATE app repo:

    rollback  T08  /health turns 503 20 s after the app starts. Its tests pass, so it is
                   ALLOWED and deployed; 3 failed checks in a row -> the old version is
                   back (ROLLED_BACK) within rollback_sla_s (120 s) of the 3rd failure.
    blocked   T08  again, but the kept old version is removed while the new one runs
                   (scripts/host_block_rollback.sh). The rollback fails (ROLLBACK_FAILED)
                   and the developer gets the "ROLLBACK FAILED" alert at once.
    restore   S03  a safe seeded change, so the sandbox ends healthy (DEPLOYED).

The timings come from the run's evidence (HEALTH_CHECK, ROLLBACK, ROLLBACK_FAILED records),
which only the host can read. Two commands reach it; they are given on the command line,
so the host's address never goes in this public repo. "{run_id}" and "{sha}" are filled in:

    uv run python scripts/run_ts_08_01.py --repo <owner>/<app-repo> \\
        --view-cmd  'ssh <host> ... bash <checkout>/scripts/host_run_view.sh {run_id}' \\
        --block-cmd 'ssh <host> ... bash <checkout>/scripts/host_block_rollback.sh {sha}' \\
        --json ts-08-01.json

Run it only while nothing else deploys: it relies on the one sandbox and its deploy lock.
Exit code: 0 if every leg passed, 1 if one did not, 2 if the run could not start.
"""

import argparse
import importlib.util
import json
import shlex
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


seeded = _load("run_seeded_changes")

BROKEN_PATCH = "system/T08-health-degrades-after-start.patch"
ROLLBACK_FAILED_ALERT = "ROLLBACK FAILED: sandbox needs attention"
ROLLBACK_SLA_S = 120  # policy.yaml timers.rollback_sla_s
FAIL_THRESHOLD = 3  # policy.yaml timers.health_fail_threshold
ALERT_SLA_S = 60  # "notified immediately": the alert follows the record within a minute
POLL_S = 10
FINAL_TIMEOUT_S = 25 * 60


@dataclass(frozen=True)
class Leg:
    name: str
    change_id: str
    expected_status: str
    block: bool = False


LEGS = (
    Leg("rollback", "T08", "ROLLED_BACK"),
    Leg("blocked", "T08", "ROLLBACK_FAILED", block=True),
    Leg("restore", "S03", "DEPLOYED"),
)


def _when(stamp: str) -> datetime:
    when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    return when if when.tzinfo else when.replace(tzinfo=UTC)


@dataclass
class LegResult:
    leg: str
    change_id: str
    expected_status: str
    pr_number: int | None = None
    commit_sha: str = ""
    run_id: str | None = None
    outcome: str | None = None
    run_status: str | None = None
    health_checks: int = 0
    failed_checks: int = 0
    detect_to_rollback_s: float | None = None  # 3rd failed check -> ROLLBACK record
    alert_after_s: float | None = None  # ROLLBACK_FAILED record -> alert comment
    sandbox_live: bool | None = None
    sandbox_image: str | None = None
    chain_ok: bool | None = None
    alerts: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.failures


def detect_to_rollback(evidence: list[dict[str, Any]], threshold: int = FAIL_THRESHOLD):
    """Seconds from the check that completed ``threshold`` failures in a row to the
    ROLLBACK or ROLLBACK_FAILED record, or None if that never happened."""
    streak, detected = 0, None
    for entry in evidence:
        if entry["event_type"] == "HEALTH_CHECK":
            streak = 0 if entry["payload"].get("ok") else streak + 1
            if streak == threshold and detected is None:
                detected = _when(entry["created_at"])
        elif entry["event_type"] in ("ROLLBACK", "ROLLBACK_FAILED") and detected is not None:
            return (_when(entry["created_at"]) - detected).total_seconds()
    return None


class Driver:
    def __init__(
        self,
        gh,
        base_sha: str,
        tag: str,
        view: Callable[[str], dict[str, Any]],
        start_block: Callable[[str], Any],
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        say: Callable[[str], None] = print,
    ):
        self.gh = gh
        self.seed_runner = seeded.Runner(gh, base_sha, tag, say=say)
        self.view, self.start_block = view, start_block
        self.clock, self.sleep, self.say = clock, sleep, say

    def run(self, leg: Leg, change) -> LegResult:
        result = LegResult(leg.name, leg.change_id, leg.expected_status)
        pushed = self.seed_runner.submit(change)
        result.pr_number, result.commit_sha = pushed.pr_number, pushed.commit_sha
        if pushed.problem:
            result.failures.append(pushed.problem)
            return result
        blocker = None
        try:
            if leg.block:
                blocker = self.start_block(result.commit_sha)
                self.say(f"{leg.name}: waiting on the host to remove the old version")
            self._leg(leg, result)
        finally:
            if blocker is not None and hasattr(blocker, "poll") and blocker.poll() is None:
                blocker.terminate()
            try:
                self.gh.close_pr(pushed.pr_number, pushed.branch)
            except RuntimeError as exc:
                self.say(f"{leg.name}: could not close PR #{pushed.pr_number}: {exc}")
        return result

    def _leg(self, leg: Leg, result: LegResult) -> None:
        comments = self._wait_for_final(result)
        if result.run_status is None:
            return
        self.say(f"{leg.name}: {result.outcome} -> {result.run_status}")
        if result.outcome != "ALLOW":
            result.failures.append(f"decision was {result.outcome}, not ALLOW")
        if result.run_status != leg.expected_status:
            result.failures.append(f"ended {result.run_status}, expected {leg.expected_status}")
        if result.run_id is None:
            return

        try:
            view = self.view(result.run_id)
        except (RuntimeError, ValueError) as exc:
            result.failures.append(f"could not read the run from the host: {exc}")
            return
        evidence = view.get("evidence", [])
        checks = [e for e in evidence if e["event_type"] == "HEALTH_CHECK"]
        result.health_checks = len(checks)
        result.failed_checks = sum(1 for e in checks if not e["payload"].get("ok"))
        result.chain_ok = bool(view.get("chain", {}).get("ok"))
        sandbox = view.get("sandbox") or {}
        result.sandbox_live = sandbox.get("live")
        last = sandbox.get("last_deployment") or {}
        result.sandbox_image = last.get("image_tag")
        if not result.chain_ok:
            result.failures.append("the evidence chain does not verify")

        if leg.expected_status in ("ROLLED_BACK", "ROLLBACK_FAILED"):
            result.detect_to_rollback_s = detect_to_rollback(evidence)
            if result.detect_to_rollback_s is None:
                result.failures.append(
                    f"no {FAIL_THRESHOLD} failed health checks in a row before the rollback"
                    " (did the new version start at all?)"
                )
            elif result.detect_to_rollback_s > ROLLBACK_SLA_S:
                result.failures.append(
                    f"rollback {result.detect_to_rollback_s:.0f} s after detection"
                    f" (limit {ROLLBACK_SLA_S} s)"
                )
        if leg.expected_status == "ROLLED_BACK" and not any(
            e["event_type"] == "ROLLBACK" for e in evidence
        ):
            result.failures.append("no ROLLBACK record")
        if leg.block:
            record = next((e for e in evidence if e["event_type"] == "ROLLBACK_FAILED"), None)
            alert = next(
                (
                    c
                    for c in comments
                    if seeded.alert_title(c.get("body", "")) == ROLLBACK_FAILED_ALERT
                ),
                None,
            )
            if record is None:
                result.failures.append("no ROLLBACK_FAILED record")
            if alert is None:
                result.failures.append(f'no "{ROLLBACK_FAILED_ALERT}" alert on the PR')
            if record is not None and alert is not None:
                result.alert_after_s = (
                    _when(alert["created_at"]) - _when(record["created_at"])
                ).total_seconds()
                if result.alert_after_s > ALERT_SLA_S:
                    result.failures.append(
                        f"alert {result.alert_after_s:.0f} s after the failed rollback"
                    )
        if leg.expected_status == "DEPLOYED" and not result.sandbox_live:
            result.failures.append("the sandbox is not live after the deploy")

    def _wait_for_final(self, result: LegResult) -> list[dict[str, Any]]:
        started, comments = self.clock(), []
        while self.clock() - started <= FINAL_TIMEOUT_S:
            try:
                comments = self.gh.comments(result.pr_number)
            except RuntimeError as exc:
                self.say(f"{result.leg}: GitHub did not answer ({exc}); trying again")
                comments = []
            for comment in comments:
                title = seeded.alert_title(comment.get("body", ""))
                if title and title not in result.alerts:
                    result.alerts.append(title)
                decision = seeded.parse_decision(comment.get("body", ""))
                if decision and decision.commit_sha == result.commit_sha:
                    result.outcome, result.run_id = decision.outcome, decision.run_id
            try:
                final = seeded.final_status(self.gh.combined_status(result.commit_sha))
            except RuntimeError:
                final = None
            if final is not None:
                result.run_status = final[1]
                return comments
            self.sleep(POLL_S)
        result.failures.append(f"no final status within {FINAL_TIMEOUT_S // 60} minutes")
        return comments


def _fill(template: str, **values: str) -> str:
    return template.format(**{k: shlex.quote(v) for k, v in values.items()})


def view_from(template: str) -> Callable[[str], dict[str, Any]]:
    def view(run_id: str) -> dict[str, Any]:
        done = subprocess.run(  # noqa: S602 - our own command line
            _fill(template, run_id=run_id), shell=True, capture_output=True, text=True
        )
        if done.returncode != 0:
            raise RuntimeError(f"view command failed ({done.returncode}): {done.stderr[:300]}")
        return json.loads(done.stdout)

    return view


def blocker_from(template: str) -> Callable[[str], subprocess.Popen]:
    def start(sha: str) -> subprocess.Popen:
        return subprocess.Popen(  # noqa: S602 - our own command line
            _fill(template, sha=sha), shell=True, stdout=subprocess.DEVNULL
        )

    return start


def report(results: list[LegResult]) -> list[str]:
    lines = [f"{'leg':9} {'status':16} {'checks':>9} {'detect->rb':>10} {'alert':>6} result"]
    for r in results:
        rb = f"{r.detect_to_rollback_s:.0f} s" if r.detect_to_rollback_s is not None else "-"
        alert = f"{r.alert_after_s:.0f} s" if r.alert_after_s is not None else "-"
        lines.append(
            f"{r.leg:9} {r.run_status or '-':16} {r.failed_checks:>3}/{r.health_checks:<5}"
            f" {rb:>10} {alert:>6} {'ok' if r.passed else 'FAIL: ' + '; '.join(r.failures)}"
        )
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", required=True, help="owner/name of the PRIVATE app repo")
    parser.add_argument("--only", nargs="+", choices=[leg.name for leg in LEGS], default=[])
    parser.add_argument("--view-cmd", required=True, help="prints the RunView of {run_id}")
    parser.add_argument("--block-cmd", help="removes the kept old version once {sha} is live")
    parser.add_argument("--json", type=Path, metavar="FILE")
    args = parser.parse_args(argv)

    legs = [leg for leg in LEGS if not args.only or leg.name in args.only]
    if any(leg.block for leg in legs) and not args.block_cmd:
        parser.error("the blocked leg needs --block-cmd (or leave it out with --only)")

    manifest = seeded.offline.load_manifest(seeded.MANIFEST)
    changes = {c.id: c for c in manifest.changes}
    changes["T08"] = SimpleNamespace(
        id="T08",
        category=SimpleNamespace(value="system"),
        expected=SimpleNamespace(value="ALLOW"),
        rules=(),
        patch=BROKEN_PATCH,
        description="TS-08-01: /health turns 503 20 s after the app starts",
    )
    tag = "ts0801-" + datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    with tempfile.TemporaryDirectory(prefix="ts-08-01-") as tmp:
        gh = seeded.GitHub(args.repo, Path(tmp) / "app")
        try:
            base_sha = gh.clone()
            for leg in legs:
                gh.git("apply", "--check", str(seeded.PATCH_DIR / changes[leg.change_id].patch))
        except RuntimeError as exc:
            print(f"cannot start: {exc}", file=sys.stderr)
            return 2
        print(f"App repo {args.repo} at {base_sha[:12]}; legs: {', '.join(x.name for x in legs)}")
        driver = Driver(
            gh,
            base_sha,
            tag,
            view_from(args.view_cmd),
            blocker_from(args.block_cmd) if args.block_cmd else lambda sha: None,
        )
        results = []
        for leg in legs:
            try:
                results.append(driver.run(leg, changes[leg.change_id]))
            except RuntimeError as exc:
                failed = LegResult(leg.name, leg.change_id, leg.expected_status)
                failed.failures.append(str(exc))
                results.append(failed)

    print()
    print("\n".join(report(results)))
    passed = all(r.passed for r in results)
    print(f"\nTS-08-01: {'PASS' if passed else 'FAIL'}")
    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "repo": args.repo,
                    "base_sha": base_sha,
                    "results": [asdict(r) for r in results],
                    "passed": passed,
                },
                indent=2,
            )
        )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
