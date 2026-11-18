"""Phase 8: the 30 seeded changes through the real pipeline (CLAUDE.md §9, §11 item 1, §12).

For each change in test_changes/manifest.yaml this script, on the PRIVATE app repo:

1. pushes a branch with the patch applied and opens a pull request to main, which starts
   the pipeline on the team host (pipeline.yml),
2. waits for the pipeline's decision comment and reads the decision, the matched rules,
   the run id and who wrote the explanation,
3. for an ESCALATE, waits for the review request and answers REJECT through approve.yml,
   so that nothing waits for 24 hours (pass --leave-escalated to keep them waiting),
4. waits for the final commit status (an allowed change deploys and is watched for
   5 minutes first), then closes the pull request and deletes the branch.

Then it compares every result with the manifest and checks the pass criteria: every
high-risk change DENIED, no risky change ever ALLOWED, at least 9 of 10 safe changes
ALLOWED, and every decision within 10 minutes of the pull request (QA-PE-01).

    uv run python scripts/run_seeded_changes.py --repo <owner>/<app-repo> --check-only
    uv run python scripts/run_seeded_changes.py --repo <owner>/<app-repo>
    uv run python scripts/run_seeded_changes.py --only D07 E03 --json results.json
    uv run python scripts/run_seeded_changes.py --only S01 D06 E01 E07 D01 --batch 5  # QA-SC-01

It runs on a laptop: only git and an authenticated `gh` (with write access to the app
repo) are needed. Nothing here runs the evaluated code. Before pushing anything it runs
the offline check (scripts/check_seeded_changes.py) against a fresh clone of the app repo,
so that a difference between that repo and this one shows up before the live runs
(--skip-precheck turns this off).

The whole run of 30 takes about 1.5 hours, because every allowed change is deployed and
monitored for 5 minutes behind the deploy lock. Changes are sent one at a time by default;
--batch N opens N pull requests at once.

Exit code: 0 if every pass criterion holds, 1 if one does not, 2 if the run could not start.
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
MANIFEST = REPO_ROOT / "test_changes" / "manifest.yaml"
PATCH_DIR = REPO_ROOT / "test_changes"
STATUS_CONTEXT = "devsecops/pipeline"
APPROVE_WORKFLOW = "approve.yml"
DECISION_LIMIT_S = 10 * 60  # QA-PE-01
DECISION_TIMEOUT_S = 15 * 60  # QA-SC-01: each record within 15 minutes
FINAL_TIMEOUT_S = 30 * 60  # build + tests + deploy + 5 minutes of health checks
POLL_S = 10


def _load_offline_checker():
    spec = importlib.util.spec_from_file_location(
        "check_seeded_changes", REPO_ROOT / "scripts" / "check_seeded_changes.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


offline = _load_offline_checker()


class SetupError(Exception):
    """The run cannot start. Exit code 2."""


# --------------------------------------------------------------------------- comments


@dataclass
class Decision:
    outcome: str
    commit_sha: str
    run_id: str
    rules: list[str]
    reason_source: str  # "claude" or "template"


_HEAD = re.compile(r"^## DevSecOps pipeline: (ALLOW|DENY|ESCALATE)\b")
_FIELD = re.compile(r"^- \*\*(Decision|Commit|Run):\*\* `?([^`\s]+)`?\s*$")
_RULE = re.compile(r"^- `([^`]+)`")
_FENCE = re.compile(r"^(`{3,}|~{3,})")
_REVIEW_HEAD = "## DevSecOps pipeline: review needed"
_ALERT = re.compile(r"^## DevSecOps pipeline alert: (.+)$")


def parse_decision(body: str) -> Decision | None:
    """Read a decision comment written by GitHubNotifier.decision_comment."""
    lines = body.splitlines()
    if not lines or not _HEAD.match(lines[0]):
        return None
    fields: dict[str, str] = {}
    rules: list[str] = []
    section = None  # None = the header, before the first "###" heading
    fence = None  # the opening fence of the code block we are in, if any
    for line in lines[1:]:
        if fence is not None:
            if line.strip() == fence:
                fence = None
            continue  # code blocks hold untrusted text: never read from them
        if match := _FENCE.match(line):
            fence = match.group(1)
            continue
        if line.startswith("### "):
            section = line
            continue
        if section is None:
            # Only the header holds these fields. Text further down (the explanation)
            # may come from the change or from Claude and must not be able to set them.
            if (match := _FIELD.match(line)) and match.group(1) not in fields:
                fields[match.group(1)] = match.group(2)
        elif section == "### Rules that matched" and (match := _RULE.match(line)):
            rules.append(match.group(1))
    if not {"Decision", "Commit", "Run"} <= fields.keys():
        return None
    # Only our own footer line counts. The explanation is shown as an escaped quote
    # ("> ..."), so text in it can never start a line with "_The decision".
    footer = next((line for line in lines if line.startswith("_The decision comes from")), "")
    source = "claude" if "written by Claude" in footer else "template"
    return Decision(fields["Decision"], fields["Commit"], fields["Run"], rules, source)


def is_review_request(body: str, run_id: str) -> bool:
    return body.startswith(_REVIEW_HEAD) and f"`{run_id}`" in body


def alert_title(body: str) -> str | None:
    first = body.splitlines()[0] if body else ""
    match = _ALERT.match(first)
    return match.group(1) if match else None


def final_status(combined_status: dict[str, Any]) -> tuple[str, str] | None:
    """(commit state, run status) once the pipeline's commit status is final, else None.
    The description starts with the final RunStatus, e.g. "DEPLOYED (run ...)"."""
    for status in combined_status.get("statuses", []):  # newest first
        if status.get("context") != STATUS_CONTEXT:
            continue
        if status.get("state") == "pending":
            return None
        description = status.get("description") or ""
        return status["state"], (description.split() or ["?"])[0]
    return None


# --------------------------------------------------------------------------- GitHub + git


class GitHub:
    """The few GitHub and git operations the script needs, through `gh` and `git`."""

    def __init__(self, repo: str, workdir: Path, run: Callable[..., str] | None = None):
        self.repo = repo
        self.workdir = workdir
        self._run = run or _run

    def clone(self) -> str:
        self._run(["gh", "repo", "clone", self.repo, str(self.workdir), "--", "-q"])
        return self.git("rev-parse", "HEAD").strip()

    def git(self, *args: str) -> str:
        return self._run(["git", "-C", str(self.workdir), *args])

    def api(self, path: str, *args: str) -> Any:
        out = self._run(["gh", "api", f"repos/{self.repo}/{path}", *args])
        return json.loads(out) if out.strip() else None

    def push_change(self, branch: str, patch: Path, message: str, base: str) -> str:
        self.git("reset", "-q", "--hard")  # a failed earlier patch leaves nothing behind
        self.git("checkout", "-q", "-B", branch, base)
        self.git("apply", "--index", str(patch))
        self.git("commit", "-q", "-m", message)
        self.git("push", "-q", "-f", "origin", f"HEAD:refs/heads/{branch}")
        return self.git("rev-parse", "HEAD").strip()

    def open_pr(self, branch: str, title: str, body: str) -> dict[str, Any]:
        return self.api(
            "pulls",
            "-X",
            "POST",
            "-f",
            f"title={title}",
            "-f",
            f"head={branch}",
            "-f",
            "base=main",
            "-f",
            f"body={body}",
        )

    def comments(self, pr_number: int) -> list[dict[str, Any]]:
        return self.api(f"issues/{pr_number}/comments?per_page=100") or []

    def combined_status(self, sha: str) -> dict[str, Any]:
        return self.api(f"commits/{sha}/status") or {}

    def reject(self, run_id: str, commit_sha: str) -> None:
        self._run(
            [
                "gh",
                "workflow",
                "run",
                APPROVE_WORKFLOW,
                "-R",
                self.repo,
                "-f",
                f"run_id={run_id}",
                "-f",
                f"commit_sha={commit_sha}",
                "-f",
                "verdict=REJECT",
            ]
        )

    def close_pr(self, pr_number: int, branch: str) -> None:
        self.api(f"pulls/{pr_number}", "-X", "PATCH", "-f", "state=closed")
        self.api(f"git/refs/heads/{branch}", "-X", "DELETE")


def _run(command: Sequence[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{command[0]} {command[1]} failed: {result.stderr.strip()[:500]}")
    return result.stdout


# --------------------------------------------------------------------------- one change


@dataclass
class LiveResult:
    id: str
    category: str
    expected: str
    expected_rules: list[str]
    branch: str = ""
    commit_sha: str = ""
    pr_number: int | None = None
    opened_at: str = ""
    outcome: str | None = None
    rules: list[str] = field(default_factory=list)
    run_id: str | None = None
    reason_source: str | None = None
    decision_s: float | None = None
    rejected: bool = False
    final_state: str | None = None
    run_status: str | None = None
    final_s: float | None = None
    alerts: list[str] = field(default_factory=list)
    problem: str | None = None

    @property
    def matches(self) -> bool:
        return self.outcome == self.expected and sorted(self.rules) == sorted(self.expected_rules)

    @property
    def done(self) -> bool:
        return self.problem is not None or self.final_state is not None


def _when(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


class Runner:
    def __init__(
        self,
        gh: GitHub,
        base_sha: str,
        tag: str,
        leave_escalated: bool = False,
        keep_prs: bool = False,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        say: Callable[[str], None] = print,
    ):
        self.gh = gh
        self.base_sha = base_sha
        self.tag = tag
        self.leave_escalated = leave_escalated
        self.keep_prs = keep_prs
        self.clock = clock
        self.sleep = sleep
        self.say = say

    def submit(self, change) -> LiveResult:
        result = LiveResult(
            id=change.id,
            category=change.category.value,
            expected=change.expected.value,
            expected_rules=list(change.rules),
            branch=f"seed/{self.tag}/{change.id}",
        )
        title = f"[seed {change.id}] {change.description}"[:200]
        try:
            result.commit_sha = self.gh.push_change(
                result.branch, PATCH_DIR / change.patch, title, self.base_sha
            )
            pr = self.gh.open_pr(
                result.branch,
                title,
                f"Seeded test change {change.id} ({change.category.value}, expected"
                f" {change.expected.value}) from the pipeline repo's test_changes/.\n\n"
                "Opened by scripts/run_seeded_changes.py to measure the pipeline. Do not merge.",
            )
        except RuntimeError as exc:
            result.problem = f"could not open the pull request: {exc}"
            return result
        result.pr_number = pr["number"]
        result.opened_at = pr["created_at"]
        self.say(f"{change.id}: PR #{result.pr_number} opened ({result.commit_sha[:12]})")
        return result

    def collect(self, results: list[LiveResult]) -> None:
        """Poll every open result until it is final or out of time."""
        started = self.clock()
        while True:
            for result in results:
                if not result.done:
                    self._step(result, self.clock() - started)
            if all(r.done for r in results):
                break
            self.sleep(POLL_S)
        for result in results:
            if result.pr_number and not self.keep_prs:
                try:
                    self.gh.close_pr(result.pr_number, result.branch)
                except RuntimeError as exc:
                    self.say(f"{result.id}: could not close PR #{result.pr_number}: {exc}")

    def _step(self, result: LiveResult, waited_s: float) -> None:
        try:
            comments = self.gh.comments(result.pr_number)
        except RuntimeError as exc:
            self.say(f"{result.id}: GitHub did not answer ({exc}); trying again")
            return
        for comment in comments:
            title = alert_title(comment.get("body", ""))
            if title and title not in result.alerts:
                result.alerts.append(title)

        if result.outcome is None:
            decision = next(
                (
                    d
                    for c in comments
                    if (d := parse_decision(c.get("body", "")))
                    and d.commit_sha == result.commit_sha
                ),
                None,
            )
            if decision is None:
                if self._final(result, waited_s):  # ended without a decision
                    result.problem = result.problem or "the run ended without a decision"
                elif waited_s > DECISION_TIMEOUT_S:
                    result.problem = f"no decision within {DECISION_TIMEOUT_S // 60} minutes"
                return
            result.outcome, result.rules = decision.outcome, decision.rules
            result.run_id, result.reason_source = decision.run_id, decision.reason_source
            posted = next(c for c in comments if parse_decision(c.get("body", "")) == decision)
            result.decision_s = (
                _when(posted["created_at"]) - _when(result.opened_at)
            ).total_seconds()
            mark = "ok" if result.matches else "MISMATCH"
            self.say(
                f"{result.id}: {result.outcome} {result.rules} after {result.decision_s:.0f} s"
                f" [{mark}]"
            )

        if result.outcome == "ESCALATE" and not result.rejected and not self.leave_escalated:
            if any(is_review_request(c.get("body", ""), result.run_id) for c in comments):
                try:
                    self.gh.reject(result.run_id, result.commit_sha)
                    result.rejected = True
                    self.say(f"{result.id}: answered REJECT through {APPROVE_WORKFLOW}")
                except RuntimeError as exc:
                    result.problem = f"could not start {APPROVE_WORKFLOW}: {exc}"
                    return

        if result.outcome == "ESCALATE" and self.leave_escalated:
            result.final_state, result.run_status = "pending", "AWAITING_REVIEW"
            return
        if not self._final(result, waited_s) and waited_s > FINAL_TIMEOUT_S:
            result.problem = f"no final status within {FINAL_TIMEOUT_S // 60} minutes"

    def _final(self, result: LiveResult, waited_s: float) -> bool:
        try:
            final = final_status(self.gh.combined_status(result.commit_sha))
        except RuntimeError:
            return False
        if final is None:
            return False
        result.final_state, result.run_status = final
        result.final_s = waited_s
        self.say(f"{result.id}: finished {result.run_status}")
        return True


# --------------------------------------------------------------------------- summary


@dataclass
class Summary:
    lines: list[str]
    passed: bool


def summarize(results: list[LiveResult]) -> Summary:
    by = {c: [r for r in results if r.category == c] for c in ("safe", "high_risk", "medium_risk")}
    risky = by["high_risk"] + by["medium_risk"]
    allowed_risky = [r.id for r in risky if r.outcome == "ALLOW"]
    denied_high = [r for r in by["high_risk"] if r.outcome == "DENY"]
    allowed_safe = [r for r in by["safe"] if r.outcome == "ALLOW"]
    escalated_medium = [r for r in by["medium_risk"] if r.outcome == "ESCALATE"]
    decided = [r for r in results if r.decision_s is not None]
    slow = [r.id for r in decided if r.decision_s > DECISION_LIMIT_S]
    problems = [f"{r.id}: {r.problem}" for r in results if r.problem]
    mismatches = [r.id for r in results if r.outcome is not None and not r.matches]

    checks: list[tuple[str, bool]] = []
    if by["high_risk"]:
        checks.append(
            (
                f"high_risk   {len(denied_high)}/{len(by['high_risk'])} DENY (all must be)",
                len(denied_high) == len(by["high_risk"]),
            )
        )
    if by["medium_risk"]:
        checks.append(
            (
                f"medium_risk {len(escalated_medium)}/{len(by['medium_risk'])} ESCALATE"
                " (all must be)",
                len(escalated_medium) == len(by["medium_risk"]),
            )
        )
    if by["safe"]:
        need = len(by["safe"]) - 1 if len(by["safe"]) == 10 else len(by["safe"])
        checks.append(
            (
                f"safe        {len(allowed_safe)}/{len(by['safe'])} ALLOW (at least {need})",
                len(allowed_safe) >= need,
            )
        )
    checks.append((f"risky changes allowed: {len(allowed_risky)} (must be 0)", not allowed_risky))
    if decided:
        worst = max(r.decision_s for r in decided)
        checks.append(
            (
                f"slowest decision {worst:.0f} s (limit {DECISION_LIMIT_S} s, QA-PE-01)",
                not slow,
            )
        )
    checks.append((f"runs without a result: {len(problems)}", not problems))

    lines = [("ok   " if ok else "FAIL ") + text for text, ok in checks]
    if allowed_risky:
        lines.append(f"     allowed risky changes: {', '.join(allowed_risky)}")
    if mismatches:
        lines.append(f"     outcome or rules differ from the manifest: {', '.join(mismatches)}")
    lines += [f"     {p}" for p in problems]
    sources = sorted({r.reason_source for r in decided if r.reason_source})
    if sources:
        lines.append(f"     explanations written by: {', '.join(sources)}")
    return Summary(lines, all(ok for _, ok in checks))


def table(results: list[LiveResult]) -> list[str]:
    rows = [f"{'id':4} {'expected':9} {'got':9} {'decision':>8} {'final':16} rules"]
    for r in results:
        decided = f"{r.decision_s:.0f} s" if r.decision_s is not None else "-"
        mark = "" if r.outcome is None or r.matches else "  <-- expected " + str(r.expected_rules)
        rows.append(
            f"{r.id:4} {r.expected:9} {r.outcome or '-':9} {decided:>8} "
            f"{r.run_status or '-':16} {r.rules}{mark}"
        )
    return rows


# --------------------------------------------------------------------------- entry point


def precheck(clone: Path, only: Sequence[str], say: Callable[[str], None]) -> None:
    """The offline check against the app repo's own tree, before anything is pushed."""
    say("Offline check against the app repo's main (about a minute) ...")
    try:
        cases = offline.run(only=only, repo=clone)
    except offline.SetupError as exc:
        raise SetupError(f"offline check could not run on the app repo: {exc}") from exc
    misses = []
    for case in cases:
        change, got = case.change, case.evaluation
        want = change.offline_expected or change.expected
        want_rules = change.offline_rules if change.offline_rules is not None else change.rules
        if got.outcome != want or sorted(got.rules) != sorted(want_rules):
            misses.append(
                f"{change.id}: expected {want.value} {list(want_rules)}, got"
                f" {got.outcome.value} {list(got.rules)} ({got.tests})"
            )
    if misses:
        raise SetupError(
            "the app repo's tree does not give the expected offline results, so the live"
            " run would not measure what the manifest says:\n  " + "\n  ".join(misses)
        )
    say(f"Offline check: {len(cases)}/{len(cases)} as expected.")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", required=True, help="owner/name of the PRIVATE app repo")
    parser.add_argument("--only", nargs="+", default=[], metavar="ID")
    parser.add_argument("--batch", type=int, default=1, help="pull requests open at once")
    parser.add_argument("--json", type=Path, metavar="FILE", help="write the results as JSON")
    parser.add_argument("--skip-precheck", action="store_true")
    parser.add_argument(
        "--leave-escalated",
        action="store_true",
        help="do not REJECT escalated runs; they wait for a reviewer or the timeout",
    )
    parser.add_argument("--keep-prs", action="store_true", help="leave the PRs and branches")
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="clone, check that the patches apply and run the offline check; push nothing",
    )
    args = parser.parse_args(argv)
    if args.batch < 1:
        parser.error("--batch must be at least 1")

    manifest = offline.load_manifest(MANIFEST)
    changes = [c for c in manifest.changes if not args.only or c.id in args.only]
    unknown = sorted(set(args.only) - {c.id for c in manifest.changes})
    if unknown:
        print(f"no such change id(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    tag = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    with tempfile.TemporaryDirectory(prefix="seeded-run-") as tmp:
        gh = GitHub(args.repo, Path(tmp) / "app")
        try:
            base_sha = gh.clone()
            for change in changes:
                try:
                    gh.git("apply", "--check", str(PATCH_DIR / change.patch))
                except RuntimeError as exc:
                    raise SetupError(f"{change.id} does not apply to the app repo: {exc}") from exc
            if not args.skip_precheck:
                precheck(gh.workdir, [c.id for c in changes], print)
        except (SetupError, RuntimeError) as exc:
            print(f"cannot start: {exc}", file=sys.stderr)
            return 2

        print(f"App repo {args.repo} at {base_sha[:12]}; {len(changes)} change(s), tag {tag}.")
        if args.check_only:
            print("Check only: nothing was pushed.")
            return 0
        runner = Runner(gh, base_sha, tag, args.leave_escalated, args.keep_prs)
        results: list[LiveResult] = []
        for start in range(0, len(changes), args.batch):
            batch = [runner.submit(c) for c in changes[start : start + args.batch]]
            runner.collect(batch)
            results += batch

    print()
    print("\n".join(table(results)))
    summary = summarize(results)
    print()
    print("\n".join(summary.lines))
    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "repo": args.repo,
                    "base_sha": base_sha,
                    "tag": tag,
                    "batch": args.batch,
                    "results": [asdict(r) for r in results],
                    "summary": summary.lines,
                    "passed": summary.passed,
                },
                indent=2,
            )
        )
    return 0 if summary.passed else 1


if __name__ == "__main__":
    sys.exit(main())
