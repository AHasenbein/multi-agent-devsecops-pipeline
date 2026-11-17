"""Orchestrator: starts runs, resumes paused ones, and reports their state."""

import logging
import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

from devsecops.models import Approval, EventType, PipelineRun, RunStatus
from devsecops.orchestrator.graph import REVIEW_NODE, PipelineDeps, build_graph
from devsecops.orchestrator.state import initial_state

log = logging.getLogger(__name__)

_INTERRUPTED = (
    "The Control API stopped while this run was in progress, so the run was not completed."
    " Push the commit again to run it."
)
_INTERRUPTED_DEPLOY = (
    " The run was deploying or being monitored: the sandbox may hold a version whose"
    " health nobody finished checking."
)
# A run in one of these states had been cleared to deploy and may have changed the sandbox.
_DEPLOY_STATUSES = {RunStatus.DEPLOYING.value, RunStatus.MONITORING.value}


class ReviewNotPending(Exception):
    """The run is not paused for review, or the approval is for a different commit."""


def sqlite_checkpointer(db_path: str | Path) -> SqliteSaver:
    """Checkpoints on disk, so a run paused for review survives a daemon restart."""
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    saver = SqliteSaver(conn)
    saver.setup()
    return saver


class Orchestrator:
    def __init__(self, deps: PipelineDeps, checkpointer: Any) -> None:
        self._deps = deps
        self._graph = build_graph(deps, checkpointer)
        self._resume_guard = threading.Lock()
        self._resuming: set[str] = set()

    @staticmethod
    def _config(run_id: str) -> dict:
        return {"configurable": {"thread_id": run_id}}

    def start_run(
        self,
        run: PipelineRun,
        workspace: str | Path,
        diff: str = "",
        changed_files: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run the pipeline until it finishes or pauses for review. Returns the state.
        This blocks (monitoring alone takes 5 minutes), so the API calls it in a thread."""
        # FR2: the first record has the run id, commit, author and start time.
        self._deps.evidence.append(run.run_id, EventType.RUN_STARTED, run)
        self._notify_pending(run)
        state = initial_state(run, str(workspace), diff, changed_files)
        return self._invoke(run.run_id, state)

    def record_failed_start(self, run: PipelineRun, errors: list[str]) -> None:
        """A run was accepted but could not begin (for example its commit could not be
        checked out). It still gets a complete record and the developer is told (FR2, FR3)."""
        self._deps.evidence.append(run.run_id, EventType.RUN_STARTED, run)
        self._deps.evidence.append(
            run.run_id, EventType.AGENT_ERROR, {"agent": "orchestrator", "errors": errors}
        )
        self._deps.evidence.append(
            run.run_id, EventType.RUN_FINISHED, {"status": RunStatus.ERROR.value, "outcome": None}
        )
        self._notify("alert", run, "Pipeline run could not start", _bullets(errors))
        self._notify("set_status", run, "error", f"ERROR (run {run.run_id})")

    def fail_interrupted_runs(self) -> Callable[[], None]:
        """Close every run that an earlier daemon process left unfinished. Call this once
        when the daemon starts, before it serves a request, so that a run of this process
        cannot be mistaken for one.

        A run paused for review is not interrupted: it continues from its checkpoint when
        a reviewer answers. Any other run without a RUN_FINISHED record was cut off and
        nothing will move it again, so it gets its final ERROR record here.

        The records are written before this returns. The returned function tells the
        developer on GitHub; the caller runs it in the background, because GitHub may be
        slow or down and the daemon should not wait for it."""
        evidence = self._deps.evidence
        notices: list[tuple[PipelineRun, str]] = []
        for entry in reversed(evidence.list_runs()):  # oldest first
            if entry.last_event_type == EventType.RUN_FINISHED.value:
                continue
            run_id = entry.run_id
            try:
                records = evidence.get_run(run_id)
                if any(r.event_type is EventType.RUN_FINISHED for r in records):
                    continue
                if self.is_awaiting_review(run_id):
                    continue
                state = self.get_state(run_id) or {}
                error = _INTERRUPTED
                if state.get("status") in _DEPLOY_STATUSES:
                    error += _INTERRUPTED_DEPLOY
                outcome = (state.get("decision") or {}).get("outcome")
                evidence.append(
                    run_id, EventType.AGENT_ERROR, {"agent": "orchestrator", "errors": [error]}
                )
                evidence.append(
                    run_id,
                    EventType.RUN_FINISHED,
                    {"status": RunStatus.ERROR.value, "outcome": outcome},
                )
                log.warning("run %s was interrupted by a restart; closed as ERROR", run_id)
                started = [r for r in records if r.event_type is EventType.RUN_STARTED]
                if started:
                    run = PipelineRun.model_validate_json(started[0].payload_json)
                    notices.append((run, error))
            except Exception:  # noqa: BLE001 - one unreadable run must not stop the daemon
                log.exception("run %s: could not close the interrupted run", run_id)

        def tell_developers() -> None:
            for run, error in notices:
                self._notify("alert", run, "Pipeline run interrupted", error)
                self._notify("set_status", run, "error", f"ERROR (run {run.run_id})")

        return tell_developers

    def resume(self, approval: Approval) -> dict[str, Any]:
        """Continue a run paused in ESCALATE with the reviewer's verdict (or TIMEOUT).
        Blocks until the run finishes, which includes deploy and monitoring."""
        return self.begin_resume(approval)()

    def begin_resume(self, approval: Approval) -> Callable[[], dict[str, Any]]:
        """Check the approval and claim the run. The returned function continues the run
        and must be called exactly once; the API calls it in a background thread, after it
        has answered the reviewer.

        Checking that the reviewer is allowed to approve is the ApprovalService's job;
        this checks that the run is really waiting and that the commit matches."""
        run_id = approval.run_id
        # Two answers for one run: only the first one counts. The guard covers the check
        # only. It must not be held while the run deploys and monitors (5 minutes), or
        # every other reviewer's answer would wait behind it.
        with self._resume_guard:
            if run_id in self._resuming:
                raise ReviewNotPending(f"run {run_id} is already being resumed")
            snapshot = self._graph.get_state(self._config(run_id))
            if REVIEW_NODE not in snapshot.next:
                raise ReviewNotPending(f"run {run_id} is not waiting for review")
            if snapshot.values["run"]["commit_sha"] != approval.commit_sha:
                raise ReviewNotPending(f"run {run_id} is for a different commit than the approval")
            self._resuming.add(run_id)

        def continue_run() -> dict[str, Any]:
            try:
                return self._invoke(run_id, Command(resume=approval.model_dump(mode="json")))
            finally:
                with self._resume_guard:
                    self._resuming.discard(run_id)

        return continue_run

    def get_state(self, run_id: str) -> dict[str, Any] | None:
        values = self._graph.get_state(self._config(run_id)).values
        return dict(values) if values else None

    def is_awaiting_review(self, run_id: str) -> bool:
        return REVIEW_NODE in self._graph.get_state(self._config(run_id)).next

    # ------------------------------------------------------------------ internals

    def _invoke(self, run_id: str, graph_input: Any) -> dict[str, Any]:
        try:
            state = dict(self._graph.invoke(graph_input, self._config(run_id)))
        except Exception as exc:  # noqa: BLE001 - record the crash instead of losing the run
            log.exception("run %s crashed", run_id)
            self._deps.deploy_lock.release(run_id)
            error = f"{type(exc).__name__}: {exc}"
            self._deps.evidence.append(
                run_id, EventType.AGENT_ERROR, {"agent": "orchestrator", "errors": [error]}
            )
            self._deps.evidence.append(
                run_id, EventType.RUN_FINISHED, {"status": RunStatus.ERROR.value, "outcome": None}
            )
            state = self.get_state(run_id) or {}
            state["status"] = RunStatus.ERROR.value
        state.pop("__interrupt__", None)
        return state

    def _notify_pending(self, run: PipelineRun) -> None:
        self._notify("set_status", run, "pending", f"pipeline running (run {run.run_id})")

    def _notify(self, method: str, *args: Any) -> None:
        try:
            getattr(self._deps.notifier, method)(*args)
        except Exception:  # noqa: BLE001 - a failed notification never changes the run
            log.exception("notifier.%s failed", method)


def _bullets(lines: list[str]) -> str:
    return "\n".join(f"- {line}" for line in lines)
