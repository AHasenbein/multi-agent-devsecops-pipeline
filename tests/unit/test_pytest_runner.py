"""PytestRunner: parses real pytest JUnit XML and coverage JSON (FR6)."""

from pathlib import Path

import pytest

from devsecops.models import Outcome
from devsecops.policy import RuleEngine
from devsecops.tools import CommandResult, PytestRunner, ToolError
from devsecops.tools.pytest_runner import parse_reports

from .conftest import clean_input

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[2]


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_fr6_passing_run_counts_and_coverage():
    report = parse_reports(fixture("pytest_pass.junit.xml"), fixture("pytest_pass.coverage.json"))
    assert (report.passed, report.failed, report.skipped) == (12, 0, 0)
    assert report.coverage_pct == 100.0
    assert report.failures == []


def test_fr6_failing_run_names_each_failure_with_file_and_line():
    report = parse_reports(
        fixture("pytest_fail.junit.xml"),
        fixture("pytest_fail.coverage.json"),
        path_prefix="sample_app",
    )
    assert (report.passed, report.failed, report.skipped) == (11, 2, 1)
    by_name = {failure.test_name: failure for failure in report.failures}
    assert set(by_name) == {"test_health_returns_ok", "test_fixture_blows_up"}

    health = by_name["test_health_returns_ok"]
    assert health.file == "sample_app/tests/test_main.py"
    assert health.line == 17  # the assert line from the traceback, not the "def" line
    assert health.message.startswith("AssertionError")
    assert "\n" not in health.message

    # A fixture error is an <error>, not a <failure>. It still counts as a failed test.
    assert by_name["test_fixture_blows_up"].file == "sample_app/tests/test_main.py"
    assert by_name["test_fixture_blows_up"].line is not None


def test_fr6_collection_error_counts_as_a_failure_with_zero_coverage():
    """An import error in the app must lead to DENY, so it has to show up as a failed test."""
    report = parse_reports(fixture("pytest_collect_error.junit.xml"), None, "sample_app")
    assert report.failed == 1
    assert report.passed == 0
    assert report.coverage_pct == 0.0
    assert report.failures[0].message == "collection failure"


def test_fr6_no_tests_collected_gives_an_empty_report():
    report = parse_reports(
        fixture("pytest_no_tests.junit.xml"), fixture("pytest_no_tests.coverage.json")
    )
    assert (report.passed, report.failed, report.skipped) == (0, 0, 0)
    assert report.coverage_pct < 80


def test_missing_coverage_without_failures_is_a_tool_error():
    with pytest.raises(ToolError, match="coverage report is missing"):
        parse_reports(fixture("pytest_pass.junit.xml"), None)


@pytest.mark.parametrize("coverage", ["not json", "{}", '{"totals": {"percent_covered": "x"}}'])
def test_unreadable_coverage_is_a_tool_error(coverage):
    with pytest.raises(ToolError, match="unreadable coverage"):
        parse_reports(fixture("pytest_pass.junit.xml"), coverage)


def test_unreadable_junit_is_a_tool_error():
    with pytest.raises(ToolError, match="unreadable JUnit"):
        parse_reports("<testsuites><oops", None)


# ------------------------------------------------------------------ run() with a fake runner


class FakePytest:
    """Stands in for run_command: writes the given reports where pytest was told to."""

    def __init__(self, returncode=0, junit=None, coverage=None, timed_out=False):
        self.returncode, self.junit, self.coverage, self.timed_out = (
            returncode,
            junit,
            coverage,
            timed_out,
        )
        self.calls = []

    def __call__(self, args, *, cwd=None, timeout=None, env=None):
        self.calls.append({"args": list(args), "cwd": cwd, "env": env})
        for arg in args:
            if arg.startswith("--junitxml=") and self.junit is not None:
                Path(arg.split("=", 1)[1]).write_text(self.junit)
            if arg.startswith("--cov-report=json:") and self.coverage is not None:
                Path(arg.split(":", 1)[1]).write_text(self.coverage)
        return CommandResult(
            args=tuple(args), returncode=self.returncode, stdout="out", timed_out=self.timed_out
        )


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "sample_app").mkdir()
    return tmp_path


def test_run_invokes_pytest_in_the_app_dir_with_reports_outside_the_workspace(workspace):
    fake = FakePytest(0, fixture("pytest_pass.junit.xml"), fixture("pytest_pass.coverage.json"))
    report = PytestRunner(runner=fake, python="py").run(workspace)
    assert report.passed == 12

    call = fake.calls[0]
    assert call["args"][:3] == ["py", "-m", "pytest"]
    assert "--cov=app" in call["args"]
    assert call["cwd"] == workspace / "sample_app"
    report_paths = [a.split("=", 1)[1] for a in call["args"] if a.startswith("--junitxml=")]
    assert not Path(report_paths[0]).is_relative_to(workspace)
    assert not Path(call["env"]["COVERAGE_FILE"]).is_relative_to(workspace)


def test_run_prefixes_failure_paths_with_the_app_dir(workspace):
    fake = FakePytest(1, fixture("pytest_fail.junit.xml"), fixture("pytest_fail.coverage.json"))
    report = PytestRunner(runner=fake).run(workspace)
    assert report.failed == 2
    assert report.failures[0].file == "sample_app/tests/test_main.py"


@pytest.mark.parametrize(
    ("fake", "expected"),
    [
        (FakePytest(timed_out=True, returncode=-1), "timed out"),
        (FakePytest(returncode=3), "code 3"),  # pytest internal error
        (FakePytest(returncode=4), "code 4"),  # usage error
        (FakePytest(returncode=0), "no usable report"),  # exit 0 but nothing written
    ],
)
def test_run_raises_tool_error_when_pytest_itself_breaks(workspace, fake, expected):
    with pytest.raises(ToolError, match=expected):
        PytestRunner(runner=fake).run(workspace)


def test_run_raises_when_exit_code_says_failed_but_report_shows_no_failures(workspace):
    """Exit code and report disagree: do not trust a report that looks clean."""
    fake = FakePytest(1, fixture("pytest_pass.junit.xml"), fixture("pytest_pass.coverage.json"))
    with pytest.raises(ToolError, match="reported no failures"):
        PytestRunner(runner=fake).run(workspace)


def test_run_raises_when_app_dir_is_missing(tmp_path):
    with pytest.raises(ToolError, match="not found"):
        PytestRunner(runner=FakePytest()).run(tmp_path)


# ------------------------------------------------------------------ the real thing


def test_fr6_sample_app_passes_its_own_tests_and_would_be_allowed(policy):
    """Phase 2 exit criterion: run real pytest on the real sample app."""
    report = PytestRunner().run(REPO_ROOT)
    assert report.failed == 0, report.failures
    assert report.passed >= 10
    assert report.coverage_pct >= 80
    assert RuleEngine(policy).evaluate(clean_input(test=report)).outcome is Outcome.ALLOW
    assert not (REPO_ROOT / "sample_app" / ".coverage").exists()
