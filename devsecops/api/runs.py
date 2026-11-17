"""Starting runs and viewing them (FR1, FR2, FR19, FR20)."""

import json
import logging
import threading
from collections.abc import Callable
from typing import Any, Protocol

from fastapi import APIRouter, HTTPException, Query, status

from devsecops.api.schemas import EvidenceEntry, RunAccepted, RunRequest, RunSummary, RunView
from devsecops.evidence import EvidenceStore
from devsecops.models import (
    Approval,
    DeploymentRecord,
    EventType,
    Finding,
    HealthCheck,
    PipelineRun,
    ReleaseDecision,
    RunRecord,
    RunStatus,
    SandboxStatus,
    TestFailure,
)
from devsecops.orchestrator.orchestrator import Orchestrator
from devsecops.tools.git_workspace import Checkout

log = logging.getLogger(__name__)

# Runs in these states are over. Anything else is still moving or waiting for a reviewer.
_ENDED = {
    RunStatus.ALLOWED,
    RunStatus.DENIED,
    RunStatus.DEPLOYED,
    RunStatus.ROLLED_BACK,
    RunStatus.ROLLBACK_FAILED,
    RunStatus.ERROR,
}
_NO_COMMIT = "0" * 40

Submit = Callable[[Callable[[], Any]], Any]


class Workspaces(Protocol):
    def prepare(self, run_id: str, commit_sha: str, base_sha: str | None = None) -> Checkout: ...

    def remove(self, run_id: str) -> None: ...


class RunService:
    def __init__(
        self,
        orchestrator: Orchestrator,
        evidence: EvidenceStore,
        workspaces: Workspaces,
        submit: Submit,
        sandbox_probe: Callable[[], HealthCheck],
    ) -> None:
        self._orchestrator = orchestrator
        self._evidence = evidence
        self._workspaces = workspaces
        self._submit = submit
        self._sandbox_probe = sandbox_probe
        # Runs that were accepted but have not written their first record yet (the few
        # seconds of the checkout). Everything after that is read from the evidence store.
        self._accepted: dict[str, PipelineRun] = {}
        self._guard = threading.Lock()

    # ------------------------------------------------------------------ start (FR1)

    def start(self, request: RunRequest) -> PipelineRun:
        """Accept the run and return at once. The pipeline itself runs in the background."""
        run = PipelineRun(
            commit_sha=request.commit_sha.lower(),
            branch=request.branch,
            author=request.author,
            event=request.event,
            pr_number=request.pr_number,
        )
        base_sha = (request.base_sha or "").lower()
        with self._guard:
            self._accepted[run.run_id] = run
        self._submit(
            lambda: self._execute(run, base_sha if base_sha and base_sha != _NO_COMMIT else None)
        )
        return run

    def _execute(self, run: PipelineRun, base_sha: str | None) -> None:
        try:
            try:
                checkout = self._workspaces.prepare(run.run_id, run.commit_sha, base_sha)
            except Exception as exc:  # noqa: BLE001 - the run still gets a record
                log.exception("run %s: checkout failed", run.run_id)
                self._orchestrator.record_failed_start(run, [f"checkout failed: {exc}"])
                return
            # Returns when the run ends or pauses for review. A paused run continues from
            # its checkpoint and needs only the image that was built, not the checkout.
            self._orchestrator.start_run(run, checkout.path, checkout.diff, checkout.changed_files)
        except Exception:  # noqa: BLE001 - nothing above us would report it
            log.exception("run %s failed outside the pipeline", run.run_id)
        finally:
            self._workspaces.remove(run.run_id)
            with self._guard:
                self._accepted.pop(run.run_id, None)

    # ------------------------------------------------------------------ view (FR20)

    def summaries(self, limit: int) -> list[RunSummary]:
        """Newest first."""
        with self._guard:
            accepted = list(self._accepted.values())
        recorded = [entry.run_id for entry in self._evidence.list_runs()]
        known = set(recorded)
        waiting = [run.run_id for run in reversed(accepted) if run.run_id not in known]
        found = (self._summary(run_id) for run_id in [*waiting, *recorded][:limit])
        return [summary for summary in found if summary is not None]

    def view(self, run_id: str) -> RunView | None:
        records = self._evidence.get_run(run_id)
        state = self._orchestrator.get_state(run_id) or {}
        summary = self._summary(run_id, records, state)
        if summary is None:
            return None

        decision = _model(ReleaseDecision, state.get("decision"))
        security = state.get("security") or {}
        test = state.get("test") or {}
        return RunView(
            **summary.model_dump(),
            decided=decision is not None or summary.status in _ENDED,
            decision=decision,
            findings=[Finding.model_validate(f) for f in security.get("findings", [])],
            failed_tests=[TestFailure.model_validate(f) for f in test.get("failures", [])],
            review_deadline=state.get("review_deadline"),
            approval=_model(Approval, state.get("approval")),
            evidence=[
                EvidenceEntry(
                    seq=record.seq,
                    event_type=record.event_type.value,
                    created_at=record.created_at,
                    payload=json.loads(record.payload_json),
                    hash=record.hash,
                )
                for record in records
            ],
            chain=self._evidence.verify_chain(),
            sandbox=self._sandbox_status(records, state),
        )

    # ------------------------------------------------------------------ internals

    def _summary(
        self,
        run_id: str,
        records: list[RunRecord] | None = None,
        state: dict[str, Any] | None = None,
    ) -> RunSummary | None:
        records = self._evidence.get_run(run_id) if records is None else records
        state = (self._orchestrator.get_state(run_id) or {}) if state is None else state
        started = _payloads(records, EventType.RUN_STARTED)
        if started:
            run = PipelineRun.model_validate(started[0])
        else:
            with self._guard:
                run = self._accepted.get(run_id)
            if run is None:
                return None

        # The RUN_FINISHED record is the last word: a crashed run has one even when its
        # checkpoint still says RUNNING.
        finished = _payloads(records, EventType.RUN_FINISHED)
        decisions = _payloads(records, EventType.DECISION)
        if finished:
            run_status = RunStatus(finished[-1]["status"])
        elif state.get("status"):
            run_status = RunStatus(state["status"])
        else:
            run_status = RunStatus.RUNNING if started else RunStatus.PENDING
        return RunSummary(
            run_id=run.run_id,
            commit_sha=run.commit_sha,
            branch=run.branch,
            author=run.author,
            event=run.event,
            pr_number=run.pr_number,
            started_at=run.started_at,
            status=run_status,
            outcome=decisions[-1].get("outcome") if decisions else None,
        )

    def _sandbox_status(self, records: list[RunRecord], state: dict[str, Any]) -> SandboxStatus:
        """What the sandbox says now. If it does not answer, the last check this run
        recorded is shown instead (UC-09)."""
        now = self._sandbox_probe()
        last_health = now
        if now.status_code is None:  # no answer at all
            recorded = _payloads(records, EventType.HEALTH_CHECK)
            if recorded:
                last_health = HealthCheck.model_validate(recorded[-1])
        return SandboxStatus(
            live=now.ok,
            last_health=last_health,
            last_deployment=_model(DeploymentRecord, state.get("deployment")),
        )


def _payloads(records: list[RunRecord], event_type: EventType) -> list[dict[str, Any]]:
    return [json.loads(r.payload_json) for r in records if r.event_type is event_type]


def _model(model: type, value: Any) -> Any:
    return model.model_validate(value) if value else None


def runs_router(service: RunService) -> APIRouter:
    router = APIRouter(prefix="/runs", tags=["runs"])

    @router.post("", status_code=status.HTTP_202_ACCEPTED)
    def start_run(request: RunRequest) -> RunAccepted:
        return RunAccepted(run_id=service.start(request).run_id)

    @router.get("")
    def list_runs(limit: int = Query(default=50, ge=1, le=500)) -> list[RunSummary]:
        return service.summaries(limit)

    @router.get("/{run_id}")
    def get_run(run_id: str) -> RunView:
        view = service.view(run_id)
        if view is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such run")
        return view

    return router
