"""BanditScanner and PipAuditScanner: parse real tool output (FR7, FR8)."""

import os
from functools import partial
from pathlib import Path

import pytest

from devsecops.models import Outcome, SecurityReport, Severity
from devsecops.policy import RuleEngine, pip_audit_severity
from devsecops.tools import BanditScanner, CommandResult, PipAuditScanner, ToolError
from devsecops.tools.bandit_scanner import parse_bandit_json
from devsecops.tools.base import run_command, scrubbed_env
from devsecops.tools.pip_audit_scanner import parse_pip_audit_json

from .conftest import clean_input

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[2]


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class FakeRunner:
    def __init__(self, returncode=0, stdout="", stderr="", timed_out=False):
        self.result = dict(returncode=returncode, stdout=stdout, stderr=stderr, timed_out=timed_out)
        self.calls = []

    def __call__(self, args, *, cwd=None, timeout=None, env=None):
        self.calls.append({"args": list(args), "cwd": cwd})
        return CommandResult(args=tuple(args), **self.result)


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "sample_app").mkdir()
    (tmp_path / "sample_app" / "requirements.txt").write_text("fastapi==0.1\n")
    return tmp_path


# ------------------------------------------------------------------ Bandit (FR7)


def test_fr7_bandit_findings_have_rule_file_line_and_severity():
    output = parse_bandit_json(fixture("bandit_findings.json"))
    by_rule = {f.rule_id: f for f in output.findings}

    assert by_rule["B602"].severity is Severity.HIGH  # subprocess with shell=True
    assert by_rule["B324"].severity is Severity.HIGH  # md5
    assert by_rule["B301"].severity is Severity.MEDIUM  # pickle
    assert by_rule["B307"].severity is Severity.MEDIUM  # eval
    assert by_rule["B101"].severity is Severity.LOW  # assert

    shell = by_rule["B602"]
    assert shell.tool == "bandit"
    assert shell.file == "sample_app/app/vuln.py"
    assert shell.line == 9
    assert "shell=True" in shell.message
    assert all(f.file and f.line for f in output.findings)


def test_fr7_file_bandit_could_not_parse_is_a_tool_error():
    """An unscanned file must not count as clean (UC-04-01 exception 2)."""
    output = parse_bandit_json(fixture("bandit_findings.json"))
    assert len(output.tool_errors) == 1
    assert "sample_app/app/syntax_error.py" in output.tool_errors[0]
    assert "syntax error" in output.tool_errors[0]


def test_fr7_clean_bandit_report_has_no_findings():
    output = parse_bandit_json(fixture("bandit_clean.json"))
    assert output.findings == []
    assert output.tool_errors == []


def test_unknown_bandit_severity_is_treated_as_medium():
    report = '{"errors": [], "results": [{"test_id": "B999", "issue_severity": "UNDEFINED"}]}'
    assert parse_bandit_json(report).findings[0].severity is Severity.MEDIUM


@pytest.mark.parametrize("output", ["", "Traceback (most recent call last)", "{}", "[]"])
def test_unreadable_bandit_output_is_a_tool_error(output):
    with pytest.raises(ToolError, match="unreadable JSON"):
        parse_bandit_json(output)


def test_bandit_scan_ignores_nosec_and_in_repo_config(workspace):
    """The change being evaluated must not be able to silence its own scan."""
    fake = FakeRunner(returncode=1, stdout=fixture("bandit_findings.json"))
    output = BanditScanner(runner=fake, python="py").scan(workspace)
    assert len(output.findings) == 8

    args = fake.calls[0]["args"]
    assert args[:5] == ["py", "-m", "bandit", "-r", "sample_app"]
    assert "--ignore-nosec" in args
    assert "--ini" in args
    assert not Path(args[args.index("--ini") + 1]).is_relative_to(workspace)
    assert fake.calls[0]["cwd"] == workspace


@pytest.mark.parametrize(
    ("fake", "expected"),
    [
        (FakeRunner(returncode=2, stderr="bandit: error: boom"), "code 2"),
        (FakeRunner(returncode=-1, timed_out=True), "timed out"),
        (FakeRunner(returncode=0, stdout="not json"), "unreadable JSON"),
    ],
)
def test_bandit_crash_is_a_tool_error(workspace, fake, expected):
    with pytest.raises(ToolError, match=expected):
        BanditScanner(runner=fake).scan(workspace)


def test_bandit_real_run_finds_shell_injection_despite_nosec_and_dot_bandit(tmp_path):
    """Real Bandit against a file that tries both suppression tricks."""
    app = tmp_path / "sample_app"
    app.mkdir()
    (app / "bad.py").write_text(
        "import subprocess\n\n\ndef run(cmd):\n"
        "    return subprocess.call(cmd, shell=True)  # nosec\n"
    )
    (app / ".bandit").write_text("[bandit]\nskips = B602,B404\n")
    (tmp_path / ".bandit").write_text("[bandit]\nskips = B602,B404\n")

    output = BanditScanner().scan(tmp_path)
    shell = [f for f in output.findings if f.rule_id == "B602"]
    assert len(shell) == 1
    assert shell[0].severity is Severity.HIGH
    assert shell[0].file == "sample_app/bad.py"
    assert shell[0].line == 5


def test_fr7_sample_app_has_no_medium_or_high_bandit_findings():
    """Phase 2 exit criterion: the real sample app is clean enough to be allowed."""
    output = BanditScanner().scan(REPO_ROOT, target="sample_app/app")
    assert output.tool_errors == []
    assert [f for f in output.findings if f.severity is not Severity.LOW] == []


# ------------------------------------------------------------------ pip-audit (FR7, FR8)


def test_fr8_every_pip_audit_finding_is_high_by_default():
    output = parse_pip_audit_json(
        fixture("pip_audit_findings.json"), requirements="sample_app/requirements.txt"
    )
    assert len(output.findings) > 10
    assert {f.severity for f in output.findings} == {Severity.HIGH}
    assert {f.tool for f in output.findings} == {"pip-audit"}
    assert {"requests", "jinja2", "urllib3", "idna"} == {f.package for f in output.findings}
    assert output.tool_errors == []

    finding = next(f for f in output.findings if f.rule_id == "PYSEC-2018-28")
    assert finding.package == "requests"
    assert finding.file == "sample_app/requirements.txt"
    assert "CVE-2018-18074" in finding.aliases
    assert finding.message.startswith("requests 2.19.1 (fixed in 2.20.0)")
    assert len(finding.message) <= 300


def test_pip_audit_duplicate_advisories_are_reported_once():
    output = parse_pip_audit_json(fixture("pip_audit_findings.json"))
    keys = [(f.package, f.rule_id) for f in output.findings]
    assert len(keys) == len(set(keys))
    assert keys.count(("requests", "PYSEC-2018-28")) == 1


def test_fr8_policy_exception_downgrades_only_the_listed_advisory(policy):
    """The exception in the test policy is listed by GHSA id; pip-audit reports a PYSEC id."""
    report = fixture("pip_audit_findings.json").replace(
        "GHSA-x84v-xcm2-53pg", "GHSA-aaaa-bbbb-cccc"
    )
    output = parse_pip_audit_json(report, partial(pip_audit_severity, policy))
    by_id = {f.rule_id: f for f in output.findings}
    assert by_id["PYSEC-2018-28"].severity is Severity.MEDIUM  # matched through its alias
    others = [f for f in output.findings if f.rule_id != "PYSEC-2018-28"]
    assert {f.severity for f in others} == {Severity.HIGH}


def test_fr7_clean_pip_audit_report_has_no_findings():
    output = parse_pip_audit_json(fixture("pip_audit_clean.json"))
    assert output.findings == []
    assert output.tool_errors == []


def test_pip_audit_skipped_dependency_is_a_tool_error():
    report = (
        '{"dependencies": [{"name": "private-pkg", "skip_reason": "not found on PyPI"},'
        ' {"name": "ok", "version": "1.0", "vulns": []}], "fixes": []}'
    )
    output = parse_pip_audit_json(report)
    assert output.findings == []
    assert output.tool_errors == ["pip-audit skipped private-pkg: not found on PyPI"]


@pytest.mark.parametrize("output", ["", "ERROR: could not resolve", "{}", "[]"])
def test_unreadable_pip_audit_output_is_a_tool_error(output):
    with pytest.raises(ToolError, match="unreadable JSON"):
        parse_pip_audit_json(output)


def test_pip_audit_scan_passes_the_requirements_file(workspace):
    fake = FakeRunner(returncode=1, stdout=fixture("pip_audit_findings.json"))
    output = PipAuditScanner(runner=fake, python="py").scan(workspace)
    assert output.findings
    args = fake.calls[0]["args"]
    assert args[:5] == ["py", "-m", "pip_audit", "-r", "sample_app/requirements.txt"]
    assert args[args.index("-f") + 1] == "json"
    assert fake.calls[0]["cwd"] == workspace


@pytest.mark.parametrize(
    ("fake", "expected"),
    [
        (FakeRunner(returncode=2, stderr="network unreachable"), "code 2"),
        (FakeRunner(returncode=-1, timed_out=True), "timed out"),
    ],
)
def test_pip_audit_crash_is_a_tool_error(workspace, fake, expected):
    with pytest.raises(ToolError, match=expected):
        PipAuditScanner(runner=fake).scan(workspace)


def test_pip_audit_missing_requirements_file_is_a_tool_error(tmp_path):
    with pytest.raises(ToolError, match="not found"):
        PipAuditScanner(runner=FakeRunner()).scan(tmp_path)


# ------------------------------------------------------------------ scanner output -> decision


def test_fr11_real_scanner_output_leads_to_deny(policy):
    bandit = parse_bandit_json(fixture("bandit_clean.json"))
    audit = parse_pip_audit_json(
        fixture("pip_audit_findings.json"), partial(pip_audit_severity, policy)
    )
    security = SecurityReport(findings=bandit.findings + audit.findings)
    decision = RuleEngine(policy).evaluate(clean_input(security=security))
    assert decision.outcome is Outcome.DENY
    assert decision.matched_rules == ("high_finding",)


# ------------------------------------------------------------------ run_command


def test_qa_pr_01_tools_do_not_see_pipeline_secrets(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-value")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test_value")
    monkeypatch.setenv("CONTROL_API_TOKEN", "control-test-value")
    monkeypatch.setenv("DB_PASSWORD", "pw-test-value")
    monkeypatch.setenv("HARMLESS_SETTING", "visible")

    env = scrubbed_env({"COVERAGE_FILE": "/tmp/x"})
    assert "ANTHROPIC_API_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert "CONTROL_API_TOKEN" not in env
    assert "DB_PASSWORD" not in env
    assert env["HARMLESS_SETTING"] == "visible"
    assert env["COVERAGE_FILE"] == "/tmp/x"
    assert "PATH" in env

    result = run_command(["env"])
    assert result.returncode == 0
    assert "sk-ant-test-value" not in result.stdout
    assert "ghp_test_value" not in result.stdout
    assert "HARMLESS_SETTING=visible" in result.stdout
    assert os.environ["GITHUB_TOKEN"] == "ghp_test_value"  # our own environment is untouched


def test_run_command_reports_missing_program_and_timeout():
    with pytest.raises(ToolError, match="command not found"):
        run_command(["definitely-not-a-real-program-xyz"])
    result = run_command(["sleep", "5"], timeout=0.2)
    assert result.timed_out
    assert result.returncode == -1
