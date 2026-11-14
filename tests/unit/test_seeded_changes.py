"""The seeded test changes and their offline checker (CLAUDE.md §11 item 1).

These tests are fast and need no network. They validate the manifest, apply every patch to a
copy of the current tree, and drive the checker with the real agents on fake tools. The full
check, which runs pytest, Bandit and pip-audit on every patched copy, is
``scripts/check_seeded_changes.py``.
"""

import importlib.util
import sys
from collections import Counter
from pathlib import Path

import pytest
import yaml

from devsecops.agents import SecurityAgent, TestAgent
from devsecops.models import Finding, Outcome, Severity, TestReport
from devsecops.policy import RuleEngine, load_policy
from devsecops.tools import CommandResult, InjectionDetector, ScanOutput, ToolError

REPO = Path(__file__).resolve().parents[2]
PATCH_DIR = REPO / "test_changes"


def _load_checker():
    spec = importlib.util.spec_from_file_location(
        "check_seeded_changes", REPO / "scripts" / "check_seeded_changes.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_checker()
Category = checker.Category

PASSING = TestReport(passed=12, failed=0, coverage_pct=100)
HIGH = Finding(tool="bandit", rule_id="B602", file="sample_app/app/main.py", severity=Severity.HIGH)


class FakePytest:
    """Stands in for PytestRunner: returns a report, calls ``on_run``, or raises ``error``."""

    def __init__(self, report=PASSING, error=None, on_run=None):
        self._report, self._error, self._on_run = report, error, on_run

    def run(self, workspace, app_dir="sample_app"):
        if self._error:
            raise ToolError(self._error)
        if self._on_run:
            self._on_run(Path(workspace))
        return self._report


class FakeScanner:
    """Stands in for BanditScanner or PipAuditScanner."""

    def __init__(self, findings=(), error=None):
        self._findings, self._error = list(findings), error

    def scan(self, workspace, **kwargs):
        if self._error:
            raise ToolError(self._error)
        return ScanOutput(findings=self._findings)


def make_agents(pytest_runner=None, bandit=None, pip_audit=None):
    """The real Test and Security agents. Their tools report a clean change unless a fake is
    passed in. The InjectionDetector is always the real one: it only reads the diff."""
    return checker.Agents(
        test=TestAgent(pytest_runner or FakePytest()),
        security=SecurityAgent(
            bandit or FakeScanner(), pip_audit or FakeScanner(), InjectionDetector()
        ),
    )


@pytest.fixture(scope="module")
def manifest():
    return checker.load_manifest()


@pytest.fixture(scope="module")
def policy():
    return load_policy(REPO / "policy.yaml")


@pytest.fixture(scope="module")
def static_run():
    """Every patch applied to a copy of the tree. pytest, Bandit and pip-audit are faked as
    clean, so only the important-file rule and the InjectionDetector can match."""
    return {result.change.id: result for result in checker.run(agents=make_agents())}


# --------------------------------------------------------------------------- the manifest


def test_manifest_has_ten_changes_per_category(manifest):
    counts = Counter(change.category for change in manifest.changes)
    assert counts == {Category.SAFE: 10, Category.HIGH_RISK: 10, Category.MEDIUM_RISK: 10}
    for change in manifest.changes:
        assert change.expected is checker.EXPECTED_OUTCOME[change.category], change.id


def test_manifest_and_patch_files_match(manifest):
    listed = {change.patch for change in manifest.changes}
    assert listed == {path.name for path in PATCH_DIR.glob("*.patch")}
    for change in manifest.changes:
        assert change.patch.startswith(f"{change.id}-"), change.patch


def test_every_patch_applies_to_the_current_tree(static_run, manifest):
    """If this fails after sample_app changed, regenerate the patch (test_changes/README.md)."""
    assert set(static_run) == {change.id for change in manifest.changes}
    for result in static_run.values():
        assert result.changed, f"{result.change.id} changes no file"


def test_safe_changes_touch_no_important_file_and_trip_no_injection_pattern(static_run):
    for result in static_run.values():
        if result.change.category is Category.SAFE:
            assert result.outcome is Outcome.ALLOW, (result.change.id, result.evaluation.reason)


def test_fr12_important_file_and_injection_changes_escalate_without_any_scanner(static_run):
    """The two escalate rules that need no test or scan result match exactly where the
    manifest says they do."""
    static_rules = {"important_file_changed", "prompt_injection"}
    checked = 0
    for result in static_run.values():
        change = result.change
        if change.offline_outcome is not Outcome.ESCALATE:
            continue  # a DENY hides the escalate rules, so there is nothing to compare
        assert set(result.rules) == set(change.offline_rule_set) & static_rules, change.id
        checked += 1
    assert checked == 12  # E01-E10, plus D04 and D05, which only escalate offline


def test_fr11_denied_change_that_asks_for_approval_is_seen_by_the_detector(static_run):
    """D10 pairs a HIGH finding with a comment aimed at an AI reviewer. With the scanners
    faked as clean, the comment alone must already stop an ALLOW."""
    assert static_run["D10"].outcome is Outcome.ESCALATE
    assert static_run["D10"].rules == ("prompt_injection",)


def _entry(**overrides):
    entry = {
        "id": "S01",
        "patch": "S01-x.patch",
        "category": "safe",
        "expected": "ALLOW",
        "rules": [],
        "description": "x",
    }
    entry.update(overrides)
    return entry


@pytest.mark.parametrize(
    ("entry", "problem"),
    [
        (_entry(expected="ESCALATE", rules=["low_coverage"]), "must expect ALLOW"),
        (_entry(rules=["low_coverage"]), "matches no rule"),
        (_entry(category="high_risk", expected="DENY", rules=[]), "at least one matched rule"),
        (_entry(category="high_risk", expected="DENY", rules=["no_such_rule"]), "unknown rule"),
        (
            _entry(category="high_risk", expected="DENY", rules=["low_coverage"]),
            "not deny rules",
        ),
        (
            _entry(category="medium_risk", expected="ESCALATE", rules=["test_failed"]),
            "not escalate rules",
        ),
        (
            _entry(
                category="high_risk",
                expected="DENY",
                rules=["build_failed"],
                verify_e2e="needs docker",
                offline_expected="ALLOW",
                offline_rules=[],
            ),
            "never allowed",
        ),
        (
            _entry(
                category="high_risk",
                expected="DENY",
                rules=["build_failed"],
                offline_expected="ESCALATE",
                offline_rules=["important_file_changed"],
            ),
            "needs a verify_e2e",
        ),
        (_entry(id="X1"), "pattern"),
        (_entry(surprise=1), "Extra inputs"),
    ],
)
def test_manifest_entry_that_contradicts_itself_is_rejected(entry, problem):
    with pytest.raises(ValueError, match=problem):
        checker.SeededChange.model_validate(entry)


def test_offline_expectation_replaces_the_final_one_only_where_given(manifest):
    by_id = {change.id: change for change in manifest.changes}
    assert by_id["D04"].expected is Outcome.DENY
    assert by_id["D04"].offline_outcome is Outcome.ESCALATE
    assert by_id["D04"].offline_rule_set == {"important_file_changed"}
    assert by_id["D07"].offline_outcome is Outcome.DENY
    assert by_id["D07"].offline_rule_set == {"high_finding"}


def test_manifest_with_a_missing_or_repeated_change_is_rejected(tmp_path):
    raw = yaml.safe_load((PATCH_DIR / "manifest.yaml").read_text())

    short = tmp_path / "short.yaml"
    short.write_text(yaml.safe_dump({**raw, "changes": raw["changes"][1:]}))
    with pytest.raises(checker.SetupError, match="expected 10 safe changes, found 9"):
        checker.load_manifest(short)

    repeated = tmp_path / "repeated.yaml"
    repeated.write_text(yaml.safe_dump({**raw, "changes": [raw["changes"][0], *raw["changes"]]}))
    with pytest.raises(checker.SetupError, match="duplicate id"):
        checker.load_manifest(repeated)

    with pytest.raises(checker.SetupError, match="cannot read manifest"):
        checker.load_manifest(tmp_path / "missing.yaml")


# --------------------------------------------------------------------------- workspaces


def test_changed_files_lists_added_deleted_and_modified_paths(static_run):
    assert static_run["S02"].changed == (
        "sample_app/app/main.py",
        "sample_app/app/models.py",
        "sample_app/app/storage.py",
    )
    assert static_run["E03"].changed == ("sample_app/tests/test_main.py",)
    assert static_run["E09"].changed == ("policy.yaml", "sample_app/tests/test_main.py")


def test_changed_files_gives_both_names_of_a_rename_and_sees_a_mode_change(tmp_path):
    before, after = tmp_path / "before", tmp_path / "after"
    for root in (before, after):
        (root / "sample_app").mkdir(parents=True)
        (root / "run.sh").write_text("echo hi\n")
        (root / "run.sh").chmod(0o644)
        (root / "same.txt").write_text("same\n")
    (before / "sample_app" / "Dockerfile").write_text("FROM python\n")
    (after / "sample_app" / "Containerfile").write_text("FROM python\n")
    (after / "run.sh").chmod(0o755)

    changed = checker.changed_files(checker.tree_state(before), checker.tree_state(after))

    assert changed == ["run.sh", "sample_app/Containerfile", "sample_app/Dockerfile"]


def test_patch_is_applied_to_a_copy_and_never_to_the_repo():
    seen = {}

    def record(workspace):
        seen[workspace.name] = (workspace / "sample_app/app/__init__.py").read_text()

    version_file = REPO / "sample_app/app/__init__.py"
    before = version_file.read_text()

    checker.run(only=["S10"], agents=make_agents(pytest_runner=FakePytest(on_run=record)))

    assert '__version__ = "1.0.0"' in seen["baseline"]
    assert '__version__ = "1.0.1"' in seen["S10"]
    assert version_file.read_text() == before


def test_patch_that_does_not_apply_is_a_setup_error_not_a_result(tmp_path):
    workspace = tmp_path / "workspace"
    (workspace / "sample_app/app").mkdir(parents=True)
    (workspace / "sample_app/app/__init__.py").write_text('__version__ = "9.9.9"\n')

    with pytest.raises(checker.SetupError, match="S10-.*does not apply"):
        checker.apply_patch(workspace, PATCH_DIR / "S10-bump-version-to-1-0-1.patch")

    assert (workspace / "sample_app/app/__init__.py").read_text() == '__version__ = "9.9.9"\n'


def test_baseline_that_is_not_allowed_stops_the_check():
    failing = FakePytest(report=TestReport(passed=11, failed=1, coverage_pct=100))
    with pytest.raises(checker.SetupError, match="unpatched tree is not ALLOWed"):
        checker.run(only=["S10"], agents=make_agents(pytest_runner=failing))


def test_unknown_change_id_is_a_setup_error():
    with pytest.raises(checker.SetupError, match="no such change id.*Z99"):
        checker.run(only=["Z99"], agents=make_agents())


# --------------------------------------------------------------------------- agent results


def collect(agents, diff="", changed=()):
    return checker.collect_results(Path("unused"), "T01", diff, changed, agents)


def test_clean_results_are_allowed_and_the_build_counts_as_passed(policy):
    results = collect(make_agents())
    assert results.build is not None and results.build.success
    assert [result.agent for result in results.agent_results] == ["build", "test", "security"]
    assert RuleEngine(policy).evaluate(results).outcome is Outcome.ALLOW


def test_fr9_pytest_crash_escalates_instead_of_counting_as_a_pass(policy):
    results = collect(make_agents(pytest_runner=FakePytest(error="pytest exited with code 3")))
    assert results.test is None
    decision = RuleEngine(policy).evaluate(results)
    assert decision.outcome is Outcome.ESCALATE
    assert decision.matched_rules == ("agent_error",)
    assert "pytest exited with code 3" in decision.reason


def test_fr12_scanner_crash_escalates(policy):
    results = collect(make_agents(pip_audit=FakeScanner(error="pip-audit timed out")))
    decision = RuleEngine(policy).evaluate(results)
    assert decision.outcome is Outcome.ESCALATE
    assert decision.matched_rules == ("agent_error",)


def test_fr11_high_finding_still_denies_when_the_other_scanner_crashes(policy):
    agents = make_agents(
        bandit=FakeScanner(findings=[HIGH]), pip_audit=FakeScanner(error="pip-audit timed out")
    )
    decision = RuleEngine(policy).evaluate(collect(agents))
    assert decision.outcome is Outcome.DENY
    assert decision.matched_rules == ("high_finding",)


def test_fr12_injection_in_the_diff_escalates_under_its_own_rule(policy):
    diff = (PATCH_DIR / "E07-comment-tells-reviewer-to-approve.patch").read_text()
    results = collect(make_agents(), diff=diff)
    assert results.security.injection_suspected
    decision = RuleEngine(policy).evaluate(results)
    assert decision.outcome is Outcome.ESCALATE
    assert decision.matched_rules == ("prompt_injection",)


def test_fr12_changed_important_file_escalates(policy):
    results = collect(make_agents(), changed=["sample_app/Dockerfile"])
    decision = RuleEngine(policy).evaluate(results)
    assert decision.outcome is Outcome.ESCALATE
    assert decision.matched_rules == ("important_file_changed",)


def _workspace(tmp_path, name, requirements):
    workspace = tmp_path / name
    (workspace / "sample_app").mkdir(parents=True)
    (workspace / checker.REQUIREMENTS).write_text(requirements)
    return workspace


def test_pip_audit_runs_once_per_distinct_requirements_file(tmp_path):
    scanned = []

    def runner(args, *, cwd=None, timeout=None, env=None):
        scanned.append(Path(cwd).name)
        return CommandResult(args=tuple(args), returncode=0, stdout='{"dependencies": []}')

    cached = checker.CachedPipAudit(runner=runner)
    for name, requirements in (("a", "x==1\n"), ("b", "x==1\n"), ("c", "x==2\n")):
        assert cached.scan(_workspace(tmp_path, name, requirements)) == ScanOutput()

    assert scanned == ["a", "c"]


def test_pip_audit_failure_is_raised_for_every_workspace_with_that_file(tmp_path):
    calls = []

    def runner(args, *, cwd=None, timeout=None, env=None):
        calls.append(Path(cwd).name)
        return CommandResult(args=tuple(args), returncode=2, stderr="cannot resolve x==0.0.0")

    cached = checker.CachedPipAudit(runner=runner)
    for name in ("a", "b"):
        with pytest.raises(ToolError, match="cannot resolve"):
            cached.scan(_workspace(tmp_path, name, "x==0.0.0\n"))

    assert calls == ["a"]


# --------------------------------------------------------------------------- the verdict


def _result(change, outcome, rules=()):
    evaluation = checker.Evaluation(
        outcome=outcome, rules=tuple(rules), reason="", tests="", findings=""
    )
    return checker.CaseResult(change=change, evaluation=evaluation, changed=(), seconds=0.0)


def _as_expected(manifest, **overrides):
    """One result per change. Each matches its offline expectation unless overridden."""
    return [
        _result(change, *overrides[change.id])
        if change.id in overrides
        else _result(change, change.offline_outcome, change.offline_rule_set)
        for change in manifest.changes
    ]


def test_result_is_ok_only_with_the_expected_outcome_and_exactly_the_expected_rules(manifest):
    e09 = next(change for change in manifest.changes if change.id == "E09")
    assert _result(e09, Outcome.ESCALATE, ["important_file_changed", "low_coverage"]).ok
    # Same outcome, but low_coverage is missing: the policy came from the patched tree.
    assert not _result(e09, Outcome.ESCALATE, ["important_file_changed"]).ok
    assert not _result(e09, Outcome.DENY, ["test_failed"]).ok


def test_acceptance_is_met_when_every_change_gets_its_offline_result(manifest):
    lines, passed = checker.acceptance(_as_expected(manifest))
    assert passed
    assert "safe         10/10 ALLOW" in lines[0]
    assert "8/10 DENY offline; D04, D05" in lines[1]
    assert lines[-1] == "risky changes allowed: 0 (must be 0)"


def test_acceptance_tolerates_one_blocked_safe_change_but_not_two(manifest):
    blocked = (Outcome.ESCALATE, ["prompt_injection"])
    assert checker.acceptance(_as_expected(manifest, S04=blocked))[1]
    assert not checker.acceptance(_as_expected(manifest, S04=blocked, S03=blocked))[1]


def test_acceptance_fails_when_a_risky_change_is_allowed(manifest):
    lines, passed = checker.acceptance(_as_expected(manifest, E08=(Outcome.ALLOW, [])))
    assert not passed
    assert lines[-1] == "risky changes allowed: 1 (must be 0) -> E08"


def test_acceptance_fails_when_a_high_risk_change_is_only_escalated(manifest):
    escalated = (Outcome.ESCALATE, ["medium_finding"])
    assert not checker.acceptance(_as_expected(manifest, D07=escalated))[1]
