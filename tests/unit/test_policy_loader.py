"""policy.yaml loading and validation (FR3, FR8, FR10)."""

from pathlib import Path

import pytest

from devsecops.models import BUILTIN_RULES, Severity
from devsecops.policy import PolicyError, load_policy, parse_policy

from .conftest import POLICY_YAML

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_repo_policy_yaml_is_valid():
    policy = load_policy(REPO_ROOT / "policy.yaml")
    assert policy.thresholds.min_coverage_pct == 80
    assert policy.timers.review_timeout_s == 86400
    assert policy.timers.health_interval_s == 10
    assert policy.timers.health_fail_threshold == 3
    assert policy.llm.claude_retries == 3
    assert policy.llm.schema_retries == 2
    assert "devsecops/**" in policy.important_files
    assert policy.reviewers


def test_parses_exceptions_and_defaults(policy):
    assert [e.id for e in policy.pip_audit_exceptions] == ["GHSA-aaaa-bbbb-cccc", "PYSEC-2024-1"]
    assert policy.pip_audit_exceptions[0].severity == Severity.MEDIUM
    assert policy.timers.rollback_sla_s == 120  # default when the timers block is omitted
    assert policy.rules == BUILTIN_RULES


def test_policy_set_is_immutable(policy):
    with pytest.raises(Exception):  # noqa: B017 - pydantic raises ValidationError
        policy.version = 2


def test_missing_file_raises_policy_error(tmp_path):
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path / "nope.yaml")


@pytest.mark.parametrize(
    "text",
    [
        "version: [unclosed",  # not YAML
        "- just\n- a list",  # not a mapping
        "",  # empty
    ],
)
def test_malformed_yaml_raises_policy_error(text):
    with pytest.raises(PolicyError):
        parse_policy(text)


def _with(replacement_from: str, replacement_to: str) -> str:
    assert replacement_from in POLICY_YAML
    return POLICY_YAML.replace(replacement_from, replacement_to)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (_with("min_coverage_pct: 80", "min_coverage_pct: 180"), "min_coverage_pct"),
        (_with("min_coverage_pct: 80", "min_coverage_pct: eighty"), "min_coverage_pct"),
        (_with("version: 1", "version: 1\nunknown_key: true"), "unknown_key"),
        (_with("reviewers:\n  - alice\n  - bob", "reviewers: []"), "reviewers"),
        (_with("  - alice\n  - bob", "  - <github-login>"), "placeholder"),
        (_with("thresholds:\n  min_coverage_pct: 80\n", ""), "thresholds"),
        (POLICY_YAML + "timers:\n  health_interval_s: 0\n", "health_interval_s"),
        (POLICY_YAML + "llm:\n  schema_retries: -1\n", "schema_retries"),
    ],
)
def test_invalid_policy_is_rejected(text, expected):
    """FR3: an invalid policy must fail setup instead of running with weakened rules."""
    with pytest.raises(PolicyError, match=expected):
        parse_policy(text)


def test_pip_audit_exception_needs_reason_and_cannot_be_high():
    """FR8: every exception is justified, and only downgrades."""
    no_reason = _with('    reason: "not reachable in sample app"\n', "")
    with pytest.raises(PolicyError, match="reason"):
        parse_policy(no_reason)
    as_high = _with("severity: MEDIUM", "severity: HIGH")
    with pytest.raises(PolicyError, match="severity"):
        parse_policy(as_high)


@pytest.mark.parametrize(
    ("rules_yaml", "expected"),
    [
        ("rules:\n  - {id: test_failed, kind: deny, description: x}\n", "cannot be removed"),
        ("rules:\n  - {id: made_up, kind: deny, description: x}\n", "unknown rule"),
    ],
)
def test_policy_cannot_remove_or_invent_rules(rules_yaml, expected):
    with pytest.raises(PolicyError, match=expected):
        parse_policy(POLICY_YAML + rules_yaml)


def test_policy_cannot_downgrade_a_deny_rule_to_escalate():
    """FR11: policy.yaml cannot turn 'failing test' or 'HIGH finding' into an escalation."""
    rules = "rules:\n" + "".join(
        "  - {{id: {}, kind: {}, description: x}}\n".format(
            rule.id, "escalate" if rule.id == "high_finding" else rule.kind
        )
        for rule in BUILTIN_RULES
    )
    with pytest.raises(PolicyError, match="cannot be changed"):
        parse_policy(POLICY_YAML + rules)


@pytest.mark.parametrize(
    "path",
    [
        "sample_app/pytest.ini",
        "sample_app/conftest.py",
        "sample_app/tests/conftest.py",
        "sample_app/.coveragerc",
        "sample_app/.bandit",
        ".bandit",
        "policy.yaml",
        "devsecops/tools/bandit_scanner.py",
        ".github/workflows/pipeline.yml",
    ],
)
def test_fr12_repo_policy_treats_tool_config_as_important(path):
    """A change to test, coverage or scanner config could weaken the checks, so it escalates."""
    from devsecops.policy import is_important_file

    assert is_important_file(load_policy(REPO_ROOT / "policy.yaml"), path)


@pytest.mark.parametrize("path", ["sample_app/app/main.py", "sample_app/tests/test_main.py"])
def test_repo_policy_leaves_ordinary_app_changes_alone(path):
    from devsecops.policy import is_important_file

    assert not is_important_file(load_policy(REPO_ROOT / "policy.yaml"), path)
