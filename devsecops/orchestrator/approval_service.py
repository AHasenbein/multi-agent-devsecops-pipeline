"""Accepts or refuses a reviewer's answer for an escalated run (FR14, invariant 8), and
times out the reviews nobody answered (FR15).

An answer counts only if the reviewer is listed in policy.yaml and the run id and commit
match a run that is paused for review right now.

The review deadline is read from the run's REVIEW_REQUESTED evidence record, not from a
table of its own. The evidence store survives a restart, so a deadline that passed while
the daemon was down is still found at its next start.
"""

import json
import logging
from collections.abc import Callable
from datetime import datetime
from typing import Any

from devsecops.evidence import EvidenceStore
from devsecops.models import Approval, EventType, PolicySet, Verdict, utc_now
from devsecops.orchestrator.orchestrator import Orchestrator, ReviewNotPending

log = logging.getLogger(__name__)

# The reviewer name on a verdict the pipeline's own timer gave.
TIMEOUT_REVIEWER = "system"


class ApprovalRefused(Exception):
    """The answer was not accepted. The API turns this into a 403."""


class ApprovalService:
    def __init__(
        self,
        policy: PolicySet,
        orchestrator: Orchestrator,
        evidence: EvidenceStore,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        # GitHub logins are not case-sensitive.
        self._reviewers = {login.casefold() for login in policy.reviewers}
        self._orchestrator = orchestrator
        self._evidence = evidence
        self._clock = clock

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

    def expire_overdue(self, now: datetime | None = None) -> list[str]:
        """Deny every paused review whose deadline has passed (FR15). Returns the ids of
        the runs it timed out.

        A run whose reviewer answered in the same moment is skipped: the answer wins. One
        run that cannot be timed out does not stop the others."""
        now = now or self._clock()
        expired: list[str] = []
        for entry in reversed(self._evidence.list_runs()):  # oldest first
            # A paused run's last record is always its REVIEW_REQUESTED.
            if entry.last_event_type != EventType.REVIEW_REQUESTED.value:
                continue
            run_id = entry.run_id
            try:
                commit_sha, deadline = self._review_deadline(run_id)
                if deadline is None or deadline >= now:
                    continue
                approval = Approval(
                    run_id=run_id,
                    commit_sha=commit_sha,
                    reviewer=TIMEOUT_REVIEWER,
                    verdict=Verdict.TIMEOUT,
                )
                continue_run = self._orchestrator.begin_resume(approval)
            except ReviewNotPending:
                continue  # a reviewer got there first, or the run is no longer waiting
            except Exception:  # noqa: BLE001 - one broken run must not stop the others
                log.exception("run %s: could not time out the review", run_id)
                continue
            try:
                continue_run()  # TIMEOUT goes straight to DENIED: nothing is deployed
            except Exception:  # noqa: BLE001
                log.exception("run %s: timing out the review failed", run_id)
                continue
            log.info("run %s: review deadline passed, change denied", run_id)
            expired.append(run_id)
        return expired

    def _review_deadline(self, run_id: str) -> tuple[str, datetime | None]:
        requests = [
            record
            for record in self._evidence.get_run(run_id)
            if record.event_type is EventType.REVIEW_REQUESTED
        ]
        if not requests:
            return "", None
        payload = json.loads(requests[-1].payload_json)
        return payload["commit_sha"], datetime.fromisoformat(payload["deadline_at"])
