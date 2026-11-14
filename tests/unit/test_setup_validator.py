"""SetupValidator (FR3)."""

from pathlib import Path

from devsecops.orchestrator.setup_validator import SetupValidator

REPO_POLICY = Path(__file__).resolve().parents[2] / "policy.yaml"
ENV = {"GITHUB_TOKEN": "ghp_test_value_123", "CONTROL_API_TOKEN": "control_test_value_456"}


class Docker:
    def __init__(self, available=True):
        self.available = available

    def is_available(self):
        return self.available


def test_fr3_no_problems_when_docker_policy_and_secrets_are_in_place():
    assert SetupValidator(Docker(), REPO_POLICY, environ=ENV).problems() == []


def test_fr3_docker_down_is_reported():
    problems = SetupValidator(Docker(available=False), REPO_POLICY, environ=ENV).problems()
    assert problems == ["Docker is not installed or the daemon is not running"]


def test_fr3_missing_or_invalid_policy_is_reported(tmp_path):
    missing = SetupValidator(Docker(), tmp_path / "policy.yaml", environ=ENV).problems()
    assert len(missing) == 1 and "cannot read policy file" in missing[0]

    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nreviewers: []\n")
    invalid = SetupValidator(Docker(), bad, environ=ENV).problems()
    assert len(invalid) == 1 and "invalid policy" in invalid[0]


def test_fr3_missing_secret_is_reported_by_name_only():
    env = {"GITHUB_TOKEN": "ghp_test_value_123", "CONTROL_API_TOKEN": "  "}
    problems = SetupValidator(Docker(), REPO_POLICY, environ=env).problems()
    assert problems == ["environment variable CONTROL_API_TOKEN is not set"]
    assert "ghp_test_value_123" not in " ".join(problems)  # QA-PR-01


def test_fr3_every_problem_is_listed_at_once(tmp_path):
    problems = SetupValidator(Docker(False), tmp_path / "x.yaml", environ={}).problems()
    assert len(problems) == 4
