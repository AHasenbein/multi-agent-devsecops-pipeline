"""The interface between the orchestrator and whatever delivers notifications."""

from datetime import datetime
from typing import Literal, Protocol

from devsecops.models import PipelineRun, PolicyInput, ReleaseDecision

CommitState = Literal["pending", "success", "failure", "error"]


class Notifier(Protocol):
    """The orchestrator swallows and logs any exception these raise: a failed notification
    must not change a decision or stop a rollback."""

    def set_status(self, run: PipelineRun, state: CommitState, description: str) -> None:
        """Set the commit status for the run's commit."""

    def post_decision(
        self, run: PipelineRun, decision: ReleaseDecision, results: PolicyInput
    ) -> None:
        """Publish the decision: outcome, matched rules, reason, and the top findings and
        failed tests with file and line (QA-US-01). ``results`` holds those details."""

    def request_review(
        self,
        run: PipelineRun,
        decision: ReleaseDecision,
        reviewers: tuple[str, ...],
        deadline: datetime,
    ) -> None:
        """Tell the reviewers that an escalated run is waiting for them (FR14)."""

    def alert(self, run: PipelineRun, title: str, body: str) -> None:
        """Something needs the developer now: setup problem, review timeout, failed
        rollback (FR3, FR15, FR18)."""


class NullNotifier:
    """Does nothing. For local runs and tests that do not look at notifications."""

    def set_status(self, run: PipelineRun, state: CommitState, description: str) -> None:
        pass

    def post_decision(
        self, run: PipelineRun, decision: ReleaseDecision, results: PolicyInput
    ) -> None:
        pass

    def request_review(
        self,
        run: PipelineRun,
        decision: ReleaseDecision,
        reviewers: tuple[str, ...],
        deadline: datetime,
    ) -> None:
        pass

    def alert(self, run: PipelineRun, title: str, body: str) -> None:
        pass
