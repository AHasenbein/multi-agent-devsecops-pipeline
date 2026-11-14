"""Offline check of the seeded test changes in test_changes/ (CLAUDE.md §11 item 1).

For every patch listed in test_changes/manifest.yaml this script:

1. copies the working tree to a temporary directory and applies the patch there,
2. runs PytestRunner, BanditScanner, PipAuditScanner and InjectionDetector on the result,
3. gives those results to the RuleEngine, using the repo's own policy.yaml,
4. compares the outcome and the matched rules with the manifest.

It needs no Docker, no GitHub, no Claude and no LangGraph graph. Two things are therefore not
checked here, and the manifest marks the affected changes with ``verify_e2e``:

* The Docker build is never run. Every change is evaluated as if its image built.
* The list of changed files is worked out here, by comparing the tree before and after the
  patch. The pipeline has no code yet that works out the changed files of a commit.

Usage:
    uv run python scripts/check_seeded_changes.py                # all 30 changes
    uv run python scripts/check_seeded_changes.py --only D07 E03 -v
    uv run python scripts/check_seeded_changes.py --json results.json

Exit code: 0 if every change got its expected offline result, 1 if any did not, 2 if the check
could not run (invalid manifest, a patch that does not apply, or a baseline that is not ALLOW).
"""

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from devsecops.models import (
    BUILTIN_RULES,
    AgentResult,
    AgentStatus,
    BuildResult,
    Finding,
    Outcome,
    PolicyInput,
    PolicySet,
    SecurityReport,
    Severity,
    TestReport,
)
from devsecops.policy import PolicyError, RuleEngine, load_policy, pip_audit_severity
from devsecops.tools import (
    BanditScanner,
    InjectionDetector,
    PipAuditScanner,
    PytestRunner,
    ScanOutput,
    ToolError,
    run_command,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "test_changes" / "manifest.yaml"
REQUIREMENTS = "sample_app/requirements.txt"
PER_CATEGORY = 10
MIN_SAFE_ALLOWED = 9  # CLAUDE.md §11 item 1: safe -> ALLOW for at least 9 of 10

_RULE_KINDS = {rule.id: rule.kind for rule in BUILTIN_RULES}


class SetupError(Exception):
    """The check itself cannot run. This says nothing about the seeded changes."""


# --------------------------------------------------------------------------- manifest


class Category(StrEnum):
    SAFE = "safe"
    HIGH_RISK = "high_risk"
    MEDIUM_RISK = "medium_risk"


EXPECTED_OUTCOME = {
    Category.SAFE: Outcome.ALLOW,
    Category.HIGH_RISK: Outcome.DENY,
    Category.MEDIUM_RISK: Outcome.ESCALATE,
}


def _check_rules(outcome: Outcome, rules: Sequence[str], what: str) -> None:
    unknown = sorted(set(rules) - set(_RULE_KINDS))
    if unknown:
        raise ValueError(f"{what}: unknown rule id(s) {unknown}")
    if outcome is Outcome.ALLOW:
        if rules:
            raise ValueError(f"{what}: an ALLOW matches no rule")
        return
    if not rules:
        raise ValueError(f"{what}: {outcome.value} needs at least one matched rule")
    # The RuleEngine reports deny matches or escalate matches, never a mix.
    kind = "deny" if outcome is Outcome.DENY else "escalate"
    wrong = sorted(rule for rule in rules if _RULE_KINDS[rule] != kind)
    if wrong:
        raise ValueError(f"{what}: {wrong} are not {kind} rules, so they cannot give {outcome}")


class SeededChange(BaseModel):
    """One entry of manifest.yaml.

    ``expected`` and ``rules`` describe the finished pipeline. ``offline_expected`` and
    ``offline_rules`` are set only where this offline check must see something else, and
    ``verify_e2e`` says why the offline result is not the final word.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[SDE]\d{2}$")
    patch: str = Field(pattern=r"^[A-Za-z0-9._-]+\.patch$")
    category: Category
    expected: Outcome
    rules: tuple[str, ...]
    description: str = Field(min_length=1)
    covers: tuple[str, ...] = ()
    verify_e2e: str | None = None
    offline_expected: Outcome | None = None
    offline_rules: tuple[str, ...] | None = None

    @model_validator(mode="after")
    def _consistent(self) -> "SeededChange":
        if self.expected is not EXPECTED_OUTCOME[self.category]:
            raise ValueError(
                f"{self.id}: a {self.category.value} change must expect "
                f"{EXPECTED_OUTCOME[self.category].value}, not {self.expected.value}"
            )
        _check_rules(self.expected, self.rules, f"{self.id} rules")
        if (self.offline_expected is None) != (self.offline_rules is None):
            raise ValueError(f"{self.id}: set offline_expected and offline_rules together")
        if self.offline_expected is not None:
            if not self.verify_e2e:
                raise ValueError(f"{self.id}: offline_expected needs a verify_e2e explanation")
            if self.offline_expected is Outcome.ALLOW and self.category is not Category.SAFE:
                raise ValueError(f"{self.id}: a risky change is never allowed, offline or not")
            _check_rules(self.offline_expected, self.offline_rules, f"{self.id} offline_rules")
        return self

    @property
    def offline_outcome(self) -> Outcome:
        return self.offline_expected or self.expected

    @property
    def offline_rule_set(self) -> frozenset[str]:
        return frozenset(self.rules if self.offline_rules is None else self.offline_rules)


class Manifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1]
    changes: tuple[SeededChange, ...]

    @model_validator(mode="after")
    def _complete(self) -> "Manifest":
        for what, values in (
            ("id", [change.id for change in self.changes]),
            ("patch", [change.patch for change in self.changes]),
        ):
            repeated = sorted({value for value in values if values.count(value) > 1})
            if repeated:
                raise ValueError(f"duplicate {what}(s): {repeated}")
        for category in Category:
            count = sum(change.category is category for change in self.changes)
            if count != PER_CATEGORY:
                raise ValueError(f"expected {PER_CATEGORY} {category.value} changes, found {count}")
        return self


def load_manifest(path: Path = DEFAULT_MANIFEST) -> Manifest:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SetupError(f"{path}: cannot read manifest: {exc}") from exc
    try:
        return Manifest.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(error["msg"] for error in exc.errors())
        raise SetupError(f"{path}: invalid manifest: {problems}") from exc


# --------------------------------------------------------------------------- workspaces


def _git(args: Sequence[str], cwd: Path) -> str:
    # The ceiling stops git from finding a repository above cwd. Inside a repository,
    # "git apply" would silently skip every path that lies outside the current directory.
    ceiling = {"GIT_CEILING_DIRECTORIES": str(cwd.resolve().parent)}
    try:
        result = run_command(["git", *args], cwd=cwd, timeout=60, env=ceiling)
    except ToolError as exc:
        raise SetupError(str(exc)) from exc
    if result.timed_out or result.returncode != 0:
        raise SetupError(f"git {' '.join(args)} failed: {result.tail(500)}")
    return result.stdout


def snapshot(repo: Path, dest: Path) -> None:
    """Copy the working tree to ``dest``: tracked files plus new files that are not ignored."""
    try:
        result = run_command(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=repo,
            timeout=60,
        )
    except ToolError as exc:
        raise SetupError(str(exc)) from exc
    if result.returncode != 0:
        raise SetupError(f"git ls-files failed in {repo}: {result.tail(500)}")
    for relative in filter(None, result.stdout.split("\0")):
        source = repo / relative
        if source.is_file():  # a tracked file may be deleted in the working tree
            target = dest / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def apply_patch(workspace: Path, patch: Path) -> None:
    """Apply the patch to the files in ``workspace``. All of it applies, or nothing does."""
    try:
        _git(["apply", "--whitespace=nowarn", str(patch.resolve())], cwd=workspace)
    except SetupError as exc:
        raise SetupError(f"{patch.name} does not apply to the current tree: {exc}") from exc


TreeState = dict[str, tuple[int, bytes]]


def tree_state(root: Path) -> TreeState:
    """Permission bits and content hash of every file under ``root``, by relative path."""
    return {
        path.relative_to(root).as_posix(): (
            path.stat().st_mode & 0o777,
            hashlib.sha256(path.read_bytes()).digest(),
        )
        for path in root.rglob("*")
        if path.is_file()
    }


def changed_files(before: TreeState, after: TreeState) -> list[str]:
    """Every path that was added, deleted or modified. A rename gives both names.

    This is the checker's stand-in for a pipeline step that does not exist yet. Cases that
    depend on it are marked ``verify_e2e`` in the manifest.
    """
    return sorted(
        path for path in before.keys() | after.keys() if before.get(path) != after.get(path)
    )


# --------------------------------------------------------------------------- running the tools


@dataclass(frozen=True)
class Tools:
    """The four checks, as plain callables so that tests can pass fakes."""

    run_tests: Callable[[Path], TestReport]
    scan_code: Callable[[Path], ScanOutput]
    scan_dependencies: Callable[[Path], ScanOutput]
    scan_diff: Callable[[str], list[Finding]]


class CachedPipAudit:
    """pip-audit takes several seconds and its result depends only on requirements.txt,
    so each distinct file content is scanned once per run."""

    def __init__(self, scan: Callable[[Path], ScanOutput]) -> None:
        self._scan = scan
        self._cache: dict[str, ScanOutput | str] = {}

    def scan(self, workspace: Path) -> ScanOutput:
        path = Path(workspace) / REQUIREMENTS
        key = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "missing"
        if key not in self._cache:
            try:
                self._cache[key] = self._scan(workspace)
            except ToolError as exc:
                self._cache[key] = str(exc)
        cached = self._cache[key]
        if isinstance(cached, str):
            raise ToolError(cached)
        return cached


def real_tools(policy: PolicySet) -> Tools:
    pip_audit = PipAuditScanner(severity_for=partial(pip_audit_severity, policy))
    return Tools(
        run_tests=PytestRunner().run,
        scan_code=BanditScanner().scan,
        scan_dependencies=CachedPipAudit(pip_audit.scan).scan,
        scan_diff=InjectionDetector().scan_diff,
    )


def collect_results(
    workspace: Path, run_id: str, diff: str, changed: Sequence[str], tools: Tools
) -> PolicyInput:
    """Run the tools on a workspace and gather what the RuleEngine reads.

    This stands in for the Build, Test and Security agents until they exist:
    * build: not run. It is reported as a success.
    * test: a ToolError means there is no report, and the test agent result is ERROR.
    * security: a scanner that crashes becomes a tool error. The findings of the other
      scanners are kept, so a HIGH finding still denies when another scanner failed.
    """
    agents = [
        AgentResult(agent="build", status=AgentStatus.OK, summary="not run by the offline check")
    ]
    build = BuildResult(image_tag=f"seeded-{run_id.lower()}:offline", success=True)

    test: TestReport | None
    try:
        test = tools.run_tests(workspace)
        agents.append(AgentResult(agent="test", status=AgentStatus.OK))
    except ToolError as exc:
        test = None
        agents.append(AgentResult(agent="test", status=AgentStatus.ERROR, errors=[str(exc)]))

    findings: list[Finding] = []
    tool_errors: list[str] = []
    for scan in (tools.scan_code, tools.scan_dependencies):
        try:
            output = scan(workspace)
        except ToolError as exc:
            tool_errors.append(str(exc))
        else:
            findings += output.findings
            tool_errors += output.tool_errors
    injections = tools.scan_diff(diff)
    security = SecurityReport(
        findings=findings + injections,
        tool_errors=tool_errors,
        injection_suspected=bool(injections),
    )
    agents.append(AgentResult(agent="security", status=AgentStatus.OK))

    return PolicyInput(
        run_id=run_id,
        build=build,
        test=test,
        security=security,
        agent_results=agents,
        changed_files=list(changed),
    )


# --------------------------------------------------------------------------- checking


@dataclass(frozen=True)
class Evaluation:
    """What the RuleEngine decided for one workspace, with a short summary of its inputs."""

    outcome: Outcome
    rules: tuple[str, ...]
    reason: str
    tests: str
    findings: str


@dataclass(frozen=True)
class CaseResult:
    change: SeededChange
    evaluation: Evaluation
    changed: tuple[str, ...]
    seconds: float

    @property
    def outcome(self) -> Outcome:
        return self.evaluation.outcome

    @property
    def rules(self) -> tuple[str, ...]:
        return self.evaluation.rules

    @property
    def ok(self) -> bool:
        return (
            self.outcome is self.change.offline_outcome
            and frozenset(self.rules) == self.change.offline_rule_set
        )

    @property
    def waits_for_e2e(self) -> bool:
        """True if the offline expectation differs from the final one."""
        return self.change.offline_expected is not None

    def as_dict(self) -> dict:
        change = self.change
        return {
            "id": change.id,
            "patch": change.patch,
            "category": change.category.value,
            "expected": change.expected.value,
            "offline_expected": change.offline_outcome.value,
            "outcome": self.outcome.value,
            "rules": list(self.rules),
            "ok": self.ok,
            "verify_e2e": change.verify_e2e,
            "changed_files": list(self.changed),
            "tests": self.evaluation.tests,
            "findings": self.evaluation.findings,
            "seconds": round(self.seconds, 1),
            "reason": self.evaluation.reason,
        }


def _describe_tests(results: PolicyInput) -> str:
    if results.test is None:
        return "no report"
    test = results.test
    return f"{test.passed} passed, {test.failed} failed, cov {test.coverage_pct:.0f}%"


def _describe_findings(results: PolicyInput, engine: RuleEngine) -> str:
    security = results.security or SecurityReport()
    severities = [engine.effective_severity(finding) for finding in security.findings]
    parts = [
        f"{severities.count(severity)} {severity.value}"
        for severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        if severity in severities
    ]
    if security.tool_errors:
        parts.append(f"{len(security.tool_errors)} tool error(s)")
    return ", ".join(parts) or "none"


def evaluate(
    workspace: Path, run_id: str, diff: str, changed: Sequence[str], tools: Tools, policy: PolicySet
) -> Evaluation:
    engine = RuleEngine(policy)
    results = collect_results(workspace, run_id, diff, changed, tools)
    decision = engine.evaluate(results)
    return Evaluation(
        outcome=decision.outcome,
        rules=decision.matched_rules,
        reason=decision.reason,
        tests=_describe_tests(results),
        findings=_describe_findings(results, engine),
    )


def check_change(
    change: SeededChange,
    patch_dir: Path,
    base: Path,
    base_state: TreeState,
    workspace: Path,
    tools: Tools,
    policy: PolicySet,
) -> CaseResult:
    started = time.monotonic()
    patch = patch_dir / change.patch
    if not patch.is_file():
        raise SetupError(f"{change.id}: patch file {patch} is missing")
    shutil.copytree(base, workspace)
    apply_patch(workspace, patch)
    changed = changed_files(base_state, tree_state(workspace))  # before the tools add files
    evaluation = evaluate(
        workspace, change.id, patch.read_text(encoding="utf-8"), changed, tools, policy
    )
    return CaseResult(
        change=change,
        evaluation=evaluation,
        changed=tuple(changed),
        seconds=time.monotonic() - started,
    )


# --------------------------------------------------------------------------- report


def _row(result: CaseResult) -> str:
    change = result.change
    status = "ok" if result.ok else "MISMATCH"
    if result.ok and change.verify_e2e:
        status = "ok*"
    return (
        f"{change.id:<4} {change.offline_outcome.value:<9} {result.outcome.value:<9} "
        f"{status:<9} {', '.join(result.rules) or '-':<38} {result.evaluation.tests:<32} "
        f"{result.evaluation.findings}"
    )


def _indent(text: str) -> str:
    return "\n".join(f"       {line}" for line in text.splitlines())


def acceptance(results: Sequence[CaseResult]) -> tuple[list[str], bool]:
    """The pass criteria of CLAUDE.md §11 item 1, for the changes that were run."""

    def of(category: Category) -> list[CaseResult]:
        return [result for result in results if result.change.category is category]

    lines: list[str] = []
    passed = True

    safe = of(Category.SAFE)
    if safe:
        allowed = sum(result.outcome is Outcome.ALLOW for result in safe)
        needed = min(MIN_SAFE_ALLOWED, len(safe))
        passed &= allowed >= needed
        lines.append(f"safe         {allowed}/{len(safe)} ALLOW (need at least {needed})")

    high = of(Category.HIGH_RISK)
    if high:
        denied = sum(result.outcome is Outcome.DENY for result in high)
        waiting = [r.change.id for r in high if r.waits_for_e2e and r.ok]
        passed &= denied + len(waiting) == len(high)
        note = f"; {', '.join(waiting)} can only DENY in the real pipeline" if waiting else ""
        lines.append(f"high_risk    {denied}/{len(high)} DENY offline{note}")

    medium = of(Category.MEDIUM_RISK)
    if medium:
        escalated = sum(result.outcome is Outcome.ESCALATE for result in medium)
        lines.append(f"medium_risk  {escalated}/{len(medium)} ESCALATE")

    risky_allowed = [
        result.change.id
        for result in results
        if result.change.category is not Category.SAFE and result.outcome is Outcome.ALLOW
    ]
    passed &= not risky_allowed
    lines.append(
        f"risky changes allowed: {len(risky_allowed)} (must be 0)"
        + (f" -> {', '.join(risky_allowed)}" if risky_allowed else "")
    )
    return lines, passed


def print_report(results: Sequence[CaseResult], verbose: bool) -> None:
    print()
    print(
        f"{'ID':<4} {'EXPECTED':<9} {'GOT':<9} {'RESULT':<9} {'MATCHED RULES':<38} "
        f"{'TESTS':<32} FINDINGS"
    )
    for result in results:
        print(_row(result))
        if verbose or not result.ok:
            print(_indent(result.change.description))
            if not result.ok:
                wanted = ", ".join(sorted(result.change.offline_rule_set)) or "-"
                print(_indent(f"expected rules: {wanted}"))
            print(_indent(result.evaluation.reason))

    pending = [result for result in results if result.ok and result.change.verify_e2e]
    if pending:
        print("\n* Offline result only. Verify once the pipeline runs end to end:")
        for result in pending:
            change = result.change
            final = f" Final outcome: {change.expected.value}." if result.waits_for_e2e else ""
            print(f"  {change.id}: {change.verify_e2e}{final}")

    lines, passed = acceptance(results)
    print("\nAcceptance (CLAUDE.md §11 item 1):" + ("" if passed else " NOT MET"))
    for line in lines:
        print(f"  {line}")

    mismatches = [result.change.id for result in results if not result.ok]
    total = sum(result.seconds for result in results)
    print(
        f"\n{len(results) - len(mismatches)}/{len(results)} changes got their expected offline "
        f"result in {total:.0f} s."
        + (f" Mismatches: {', '.join(mismatches)}" if mismatches else "")
    )


# --------------------------------------------------------------------------- entry point


def run(
    manifest_path: Path = DEFAULT_MANIFEST,
    only: Sequence[str] = (),
    repo: Path = REPO_ROOT,
    tools: Tools | None = None,
    progress: Callable[[str], None] = lambda text: None,
) -> list[CaseResult]:
    manifest = load_manifest(manifest_path)
    selected = [change for change in manifest.changes if not only or change.id in only]
    unknown = sorted(set(only) - {change.id for change in manifest.changes})
    if unknown:
        raise SetupError(f"no such change id(s): {', '.join(unknown)}")

    # The policy is the repo's own file, never the copy in a patched workspace: a change must
    # not be able to weaken the rules it is judged by (CLAUDE.md §11 item 3).
    try:
        policy = load_policy(repo / "policy.yaml")
    except PolicyError as exc:
        raise SetupError(str(exc)) from exc
    tools = tools or real_tools(policy)

    with tempfile.TemporaryDirectory(prefix="seeded-changes-") as tmp:
        root = Path(tmp).resolve()
        base = root / "base"
        base.mkdir()
        snapshot(repo, base)
        base_state = tree_state(base)

        # The tools run only in copies, so ``base`` stays exactly the snapshot.
        progress("baseline (no patch) ...")
        shutil.copytree(base, root / "baseline")
        baseline = evaluate(root / "baseline", "baseline", "", [], tools, policy)
        if baseline.outcome is not Outcome.ALLOW:
            raise SetupError(
                "the unpatched tree is not ALLOWed, so no result below could be trusted.\n"
                f"{baseline.reason}"
            )

        results: list[CaseResult] = []
        for change in selected:
            progress(f"{change.id} {change.patch} ...")
            workspace = root / change.id
            results.append(
                check_change(
                    change, manifest_path.parent, base, base_state, workspace, tools, policy
                )
            )
            shutil.rmtree(workspace, ignore_errors=True)
        return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--only", nargs="+", default=[], metavar="ID", help="e.g. --only D07 E03")
    parser.add_argument("-v", "--verbose", action="store_true", help="show every decision reason")
    parser.add_argument("--json", type=Path, metavar="FILE", help="also write the results as JSON")
    args = parser.parse_args(argv)

    def progress(text: str) -> None:
        print(text, file=sys.stderr, flush=True)

    try:
        results = run(args.manifest, args.only, progress=progress)
    except SetupError as exc:
        print(f"cannot run the check: {exc}", file=sys.stderr)
        return 2

    print_report(results, args.verbose)
    if args.json:
        args.json.write_text(
            json.dumps([result.as_dict() for result in results], indent=2) + "\n",
            encoding="utf-8",
        )
    return 0 if all(result.ok for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
