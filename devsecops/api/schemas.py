"""Request and response models of the Control API (CLAUDE.md §7)."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from devsecops.evidence.store import ChainVerification
from devsecops.models import (
    Approval,
    Finding,
    Outcome,
    ReleaseDecision,
    RunStatus,
    SandboxStatus,
    TestFailure,
)

_SHA = r"^[0-9a-fA-F]{40}$"


class RunRequest(BaseModel):
    """What the workflow in the app repo sends for a push or a pull request."""

    model_config = ConfigDict(extra="forbid")

    commit_sha: str = Field(pattern=_SHA)
    # The commit the change is compared with: github.event.before for a push, the base
    # branch's commit for a pull request. Without it the commit's own parent is used.
    base_sha: str | None = Field(default=None, pattern=_SHA)
    branch: str = Field(min_length=1, max_length=255)
    author: str = Field(min_length=1, max_length=255)
    event: Literal["push", "pull_request"]
    pr_number: int | None = Field(default=None, gt=0)


class RunAccepted(BaseModel):
    run_id: str


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(min_length=1, max_length=64)
    commit_sha: str = Field(pattern=_SHA)
    reviewer: str = Field(min_length=1, max_length=255)
    verdict: Literal["APPROVE", "REJECT"]


class ApprovalAccepted(BaseModel):
    run_id: str
    reviewer: str
    verdict: str


class EvidenceEntry(BaseModel):
    seq: int
    event_type: str
    created_at: str
    payload: dict[str, Any]
    hash: str


class RunSummary(BaseModel):
    run_id: str
    commit_sha: str
    branch: str
    author: str
    event: str
    pr_number: int | None = None
    started_at: datetime
    status: RunStatus
    outcome: Outcome | None = None


class RunView(RunSummary):
    """Everything about one run (FR19, FR20, UC-09)."""

    # True once the run has a decision or has ended without one. The workflow polls for it.
    decided: bool
    decision: ReleaseDecision | None = None
    findings: list[Finding] = Field(default_factory=list)
    failed_tests: list[TestFailure] = Field(default_factory=list)
    review_deadline: str | None = None
    approval: Approval | None = None
    evidence: list[EvidenceEntry] = Field(default_factory=list)
    chain: ChainVerification
    sandbox: SandboxStatus
