import pytest

from devsecops.models import (
    AgentResult,
    AgentStatus,
    BuildResult,
    PolicyInput,
    PolicySet,
    SecurityReport,
    TestReport,
)
from devsecops.policy import parse_policy

POLICY_YAML = """
version: 1
thresholds:
  min_coverage_pct: 80
pip_audit_exceptions:
  - id: GHSA-aaaa-bbbb-cccc
    severity: MEDIUM
    reason: "not reachable in sample app"
  - id: PYSEC-2024-1
    severity: LOW
    reason: "dev-only dependency"
important_files:
  - policy.yaml
  - .github/workflows/**
  - sample_app/Dockerfile
  - sample_app/requirements.txt
  - devsecops/**
reviewers:
  - alice
  - bob
"""


@pytest.fixture
def policy() -> PolicySet:
    return parse_policy(POLICY_YAML)


def clean_input(run_id: str = "run-1", **overrides) -> PolicyInput:
    """A run where everything passed. Tests override one field to trip one rule."""
    values = {
        "run_id": run_id,
        "build": BuildResult(image_tag="sample_app:abc123", success=True),
        "test": TestReport(passed=12, failed=0, skipped=0, coverage_pct=93.5),
        "security": SecurityReport(),
        "agent_results": [
            AgentResult(agent=name, status=AgentStatus.OK) for name in ("build", "test", "security")
        ],
        "changed_files": ["sample_app/app/main.py"],
    }
    values.update(overrides)
    return PolicyInput(**values)
