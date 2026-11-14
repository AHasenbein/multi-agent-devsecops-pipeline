"""PipelineState: the shared state every graph node reads and adds to.

Values are plain JSON data (``model_dump(mode="json")``), so the SQLite checkpointer can
store a paused run and a restarted daemon can pick it up again.
"""

import operator
from typing import Annotated, Any, TypedDict

from devsecops.models import PipelineRun, RunStatus


class PipelineState(TypedDict, total=False):
    run: dict[str, Any]  # PipelineRun
    workspace: str  # checkout of the commit being evaluated
    diff: str  # unified diff of the change
    changed_files: list[str]
    status: str  # RunStatus
    setup_problems: list[str]
    build: dict[str, Any] | None  # BuildResult
    test: dict[str, Any] | None  # TestReport
    security: dict[str, Any] | None  # SecurityReport
    # Test and Security run in parallel and both add here, so this key merges by appending.
    agent_results: Annotated[list[dict[str, Any]], operator.add]
    decision: dict[str, Any] | None  # ReleaseDecision
    review_deadline: str | None
    approval: dict[str, Any] | None  # Approval
    deployment: dict[str, Any] | None  # DeploymentRecord


def initial_state(
    run: PipelineRun, workspace: str, diff: str = "", changed_files: list[str] | None = None
) -> PipelineState:
    return PipelineState(
        run=run.model_dump(mode="json"),
        workspace=str(workspace),
        diff=diff,
        changed_files=list(changed_files or []),
        status=RunStatus.RUNNING.value,
        agent_results=[],
    )
