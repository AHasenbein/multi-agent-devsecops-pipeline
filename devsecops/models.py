"""Shared domain models (CLAUDE.md §4).

Every model is plain data. Behaviour lives in ``policy/``, ``evidence/`` and the agents.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- enums


class Outcome(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


class AgentStatus(StrEnum):
    OK = "OK"
    FAILED = "FAILED"
    ERROR = "ERROR"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Verdict(StrEnum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    TIMEOUT = "TIMEOUT"


class RunStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    AWAITING_REVIEW = "AWAITING_REVIEW"
    DENIED = "DENIED"
    DEPLOYING = "DEPLOYING"
    MONITORING = "MONITORING"
    DEPLOYED = "DEPLOYED"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    ERROR = "ERROR"


class DeployStatus(StrEnum):
    STARTED = "STARTED"
    FAILED_TO_START = "FAILED_TO_START"
    HEALTHY = "HEALTHY"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"


class EventType(StrEnum):
    """Allowed ``event_type`` values for evidence rows."""

    RUN_STARTED = "RUN_STARTED"
    SETUP_FAILED = "SETUP_FAILED"
    BUILD_RESULT = "BUILD_RESULT"
    TEST_REPORT = "TEST_REPORT"
    SECURITY_REPORT = "SECURITY_REPORT"
    AGENT_ERROR = "AGENT_ERROR"
    DECISION = "DECISION"
    REVIEW_REQUESTED = "REVIEW_REQUESTED"
    REVIEW_VERDICT = "REVIEW_VERDICT"
    DEPLOY_RESULT = "DEPLOY_RESULT"
    HEALTH_CHECK = "HEALTH_CHECK"
    ROLLBACK = "ROLLBACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    RUN_FINISHED = "RUN_FINISHED"


# --------------------------------------------------------------------------- run + agent results


class PipelineRun(BaseModel):
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    commit_sha: str = Field(min_length=1)
    branch: str
    author: str
    event: Literal["push", "pull_request"]
    pr_number: int | None = None
    started_at: datetime = Field(default_factory=utc_now)
    status: RunStatus = RunStatus.PENDING


class AgentResult(BaseModel):
    agent: str
    status: AgentStatus
    summary: str = ""
    data: dict = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class BuildResult(BaseModel):
    image_tag: str
    success: bool
    errors: list[str] = Field(default_factory=list)
    log_tail: str = ""


class TestFailure(BaseModel):
    __test__ = False  # not a pytest class

    test_name: str
    file: str | None = None
    line: int | None = None
    message: str = ""


class TestReport(BaseModel):
    __test__ = False  # not a pytest class

    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    skipped: int = Field(default=0, ge=0)
    coverage_pct: float = Field(ge=0, le=100)
    failures: list[TestFailure] = Field(default_factory=list)


class Finding(BaseModel):
    tool: Literal["bandit", "pip-audit", "injection"]
    rule_id: str
    file: str | None = None
    line: int | None = None
    package: str | None = None
    severity: Severity
    message: str = ""
    # Other IDs for the same advisory (pip-audit reports e.g. a PYSEC id plus CVE/GHSA aliases).
    aliases: list[str] = Field(default_factory=list)


class SecurityReport(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    tool_errors: list[str] = Field(default_factory=list)
    injection_suspected: bool = False


# --------------------------------------------------------------------------- policy data


class Rule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    kind: Literal["deny", "escalate"]
    description: str


# The rule catalogue is fixed by FR5 and FR10-FR12. policy.yaml tunes thresholds and lists;
# it cannot remove a rule or turn a deny rule into an escalate rule.
BUILTIN_RULES: tuple[Rule, ...] = (
    Rule(id="build_failed", kind="deny", description="The Docker build failed (FR5)."),
    Rule(id="test_failed", kind="deny", description="At least one test failed (FR11)."),
    Rule(id="high_finding", kind="deny", description="A HIGH security finding exists (FR11)."),
    Rule(
        id="medium_finding",
        kind="escalate",
        description="A MEDIUM security finding exists (FR12).",
    ),
    Rule(
        id="low_coverage",
        kind="escalate",
        description="Test coverage is below the minimum (FR12).",
    ),
    Rule(
        id="important_file_changed",
        kind="escalate",
        description="The change touches an important file (FR12).",
    ),
    Rule(
        id="agent_error",
        kind="escalate",
        description="An agent or scan tool failed, or a result is missing (FR9, FR12).",
    ),
    Rule(
        id="prompt_injection",
        kind="escalate",
        description="The change may contain a prompt injection (FR12).",
    ),
)


class Thresholds(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    min_coverage_pct: float = Field(default=80, ge=0, le=100)


class PipAuditException(BaseModel):
    """A pip-audit advisory that is downgraded from the default HIGH (FR8)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1)
    severity: Literal[Severity.MEDIUM, Severity.LOW]
    reason: str = Field(min_length=1)

    @field_validator("id", "reason")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value.strip()


class Timers(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    review_timeout_s: int = Field(default=86400, gt=0)
    review_notify_sla_s: int = Field(default=60, gt=0)
    health_interval_s: int = Field(default=10, gt=0)
    health_window_s: int = Field(default=300, gt=0)
    health_fail_threshold: int = Field(default=3, gt=0)
    rollback_sla_s: int = Field(default=120, gt=0)


class LlmSettings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    claude_retries: int = Field(default=3, ge=0)
    claude_max_extra_delay_s: float = Field(default=30, ge=0)
    schema_retries: int = Field(default=2, ge=0)


class PolicySet(BaseModel):
    """The contents of policy.yaml. Data only: ``RuleEngine`` does the evaluating."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: int = Field(ge=1)
    thresholds: Thresholds
    pip_audit_exceptions: tuple[PipAuditException, ...] = ()
    important_files: tuple[str, ...]
    reviewers: tuple[str, ...] = Field(min_length=1)
    timers: Timers = Field(default_factory=Timers)
    llm: LlmSettings = Field(default_factory=LlmSettings)
    rules: tuple[Rule, ...] = BUILTIN_RULES

    @field_validator("important_files", "reviewers")
    @classmethod
    def _clean_entries(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = tuple(v.strip() for v in values)
        for value in cleaned:
            if not value:
                raise ValueError("entries must not be blank")
            if value.startswith("<") and value.endswith(">"):
                raise ValueError(f"placeholder {value!r} must be replaced with a real value")
        return cleaned

    @model_validator(mode="after")
    def _rules_match_catalogue(self) -> "PolicySet":
        expected = {rule.id: rule.kind for rule in BUILTIN_RULES}
        given = {rule.id: rule.kind for rule in self.rules}
        if len(given) != len(self.rules):
            raise ValueError("rules: duplicate rule id")
        unknown = sorted(set(given) - set(expected))
        if unknown:
            raise ValueError(f"rules: unknown rule id(s) {unknown}")
        missing = sorted(set(expected) - set(given))
        if missing:
            raise ValueError(f"rules: required rule(s) {missing} cannot be removed")
        changed = sorted(rid for rid, kind in given.items() if kind != expected[rid])
        if changed:
            raise ValueError(f"rules: kind of {changed} cannot be changed")
        return self


# --------------------------------------------------------------------------- decision + review


class PolicyInput(BaseModel):
    """Everything the RuleEngine looks at for one run."""

    run_id: str
    build: BuildResult | None = None
    test: TestReport | None = None
    security: SecurityReport | None = None
    agent_results: list[AgentResult] = Field(default_factory=list)
    changed_files: list[str] = Field(default_factory=list)


class Approval(BaseModel):
    model_config = ConfigDict(frozen=True)

    run_id: str
    commit_sha: str
    reviewer: str
    verdict: Verdict
    reviewed_at: datetime = Field(default_factory=utc_now)


class ReleaseDecision(BaseModel):
    """The result of a run. Immutable: the outcome is set once by the RuleEngine (FR11, FR13)."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    outcome: Outcome
    matched_rules: tuple[str, ...] = ()
    reason: str
    reason_source: Literal["claude", "template"] = "template"

    def with_reason(self, reason: str, source: Literal["claude", "template"]) -> "ReleaseDecision":
        """Return a copy with new reason text. Outcome and matched rules are carried over as-is."""
        return ReleaseDecision(
            run_id=self.run_id,
            outcome=self.outcome,
            matched_rules=self.matched_rules,
            reason=reason,
            reason_source=source,
        )

    def is_deployable(self, approval: Approval | None = None) -> bool:
        """True only for ALLOW, or for ESCALATE with an APPROVE verdict for this run."""
        if self.outcome is Outcome.ALLOW:
            return True
        if self.outcome is Outcome.ESCALATE:
            return (
                approval is not None
                and approval.run_id == self.run_id
                and approval.verdict is Verdict.APPROVE
            )
        return False


# --------------------------------------------------------------------------- deploy + monitor


class Container(BaseModel):
    id: str
    name: str
    image_tag: str
    status: str


class DeploymentRecord(BaseModel):
    run_id: str
    image_tag: str
    previous_image_tag: str | None = None
    previous_container: str | None = None
    status: DeployStatus


class HealthCheck(BaseModel):
    at: datetime = Field(default_factory=utc_now)
    ok: bool
    status_code: int | None = None
    latency_ms: float | None = None
    error: str | None = None


class SandboxStatus(BaseModel):
    live: bool
    last_health: HealthCheck | None = None
    last_deployment: DeploymentRecord | None = None


# --------------------------------------------------------------------------- evidence


class RunRecord(BaseModel):
    """One evidence row."""

    model_config = ConfigDict(frozen=True)

    seq: int
    run_id: str
    event_type: EventType
    payload_json: str
    created_at: str
    prev_hash: str
    hash: str
