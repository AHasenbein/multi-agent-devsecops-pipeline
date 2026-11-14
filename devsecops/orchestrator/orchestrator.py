"""Orchestrator: starts runs, resumes paused ones, and reports their state."""

import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

from devsecops.models import Approval, EventType, PipelineRun, RunStatus
from devsecops.orchestrator.graph import REVIEW_NODE, PipelineDeps, build_graph
from devsecops.orchestrator.state import initial_state

log = logging.getLogger(__name__)


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

    def resume(self, approval: Approval) -> dict[str, Any]:
        """Continue a run paused in ESCALATE with the reviewer's verdict (or TIMEOUT).

        Checking that the reviewer is allowed to approve is the ApprovalService's job;
        this checks that the run is really waiting and that the commit matches."""
        with self._resume_guard:  # two answers for one run: only the first one counts
            snapshot = self._graph.get_state(self._config(approval.run_id))
            if REVIEW_NODE not in snapshot.next:
                raise ReviewNotPending(f"run {approval.run_id} is not waiting for review")
            if snapshot.values["run"]["commit_sha"] != approval.commit_sha:
                raise ReviewNotPending(
                    f"run {approval.run_id} is for a different commit than the approval"
                )
            return self._invoke(approval.run_id, Command(resume=approval.model_dump(mode="json")))

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
        try:
            self._deps.notifier.set_status(run, "pending", f"pipeline running (run {run.run_id})")
        except Exception:  # noqa: BLE001
            log.exception("notifier.set_status failed")
