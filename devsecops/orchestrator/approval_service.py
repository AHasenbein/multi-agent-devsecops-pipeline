"""Accepts or refuses a reviewer's answer for an escalated run (FR14, invariant 8).

An answer counts only if the reviewer is listed in policy.yaml and the run id and commit
match a run that is paused for review right now. The timeout sweeper (FR15) is Phase 5.
"""

from collections.abc import Callable
from typing import Any

from devsecops.models import Approval, PolicySet, Verdict
from devsecops.orchestrator.orchestrator import Orchestrator, ReviewNotPending


class ApprovalRefused(Exception):
    """The answer was not accepted. The API turns this into a 403."""


class ApprovalService:
    def __init__(self, policy: PolicySet, orchestrator: Orchestrator) -> None:
        # GitHub logins are not case-sensitive.
        self._reviewers = {login.casefold() for login in policy.reviewers}
        self._orchestrator = orchestrator

    def submit(
        self, run_id: str, commit_sha: str, reviewer: str, verdict: Verdict
    ) -> tuple[Approval, Callable[[], dict[str, Any]]]:
        """Check the answer and claim the run. Returns the approval and a function that
        continues the run (deploy and monitoring included), to be called exactly once."""
        if verdict is Verdict.TIMEOUT:
            # Only the pipeline's own timer may time a review out.
            raise ApprovalRefused("verdict must be APPROVE or REJECT")
        if reviewer.strip().casefold() not in self._reviewers:
            raise ApprovalRefused("reviewer is not listed in policy.yaml")
        approval = Approval(
            run_id=run_id, commit_sha=commit_sha, reviewer=reviewer.strip(), verdict=verdict
        )
        try:
            return approval, self._orchestrator.begin_resume(approval)
        except ReviewNotPending as exc:
            raise ApprovalRefused(str(exc)) from exc
