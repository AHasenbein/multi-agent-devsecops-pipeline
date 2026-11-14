"""The LangGraph pipeline (CLAUDE.md §5).

    setup_check -> build -> test || security -> policy -> DENY: finish
                                                       -> ALLOW: deploy -> monitor -> finish
                                                       -> ESCALATE: request_review ->
                                                          human_review (pause) -> deploy | finish

Nodes call agents, write evidence and send notifications. Agents never do the last two.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from devsecops.agents import Agent, policy_input_from_state
from devsecops.evidence import EvidenceStore
from devsecops.models import (
    AgentStatus,
    Approval,
    DeploymentRecord,
    DeployStatus,
    EventType,
    HealthCheck,
    Outcome,
    PipelineRun,
    PolicySet,
    ReleaseDecision,
    RunStatus,
    Verdict,
    utc_now,
)
from devsecops.notifications import CommitState, Notifier
from devsecops.orchestrator.locks import DeployLock, DeployLockTimeout
from devsecops.orchestrator.state import PipelineState

log = logging.getLogger(__name__)

REVIEW_NODE = "human_review"


@dataclass
class PipelineDeps:
    policy: PolicySet
    evidence: EvidenceStore
    notifier: Notifier
    deploy_lock: DeployLock
    build_agent: Agent
    test_agent: Agent
    security_agent: Agent
    policy_agent: Agent
    deployment_agent: Agent
    monitoring_agent: Agent
    setup_check: Callable[[], list[str]] = lambda: []
    deploy_lock_timeout_s: float = 3600


_FINAL_COMMIT_STATE: dict[RunStatus, CommitState] = {
    RunStatus.DEPLOYED: "success",
    RunStatus.ALLOWED: "success",
    RunStatus.DENIED: "failure",
    RunStatus.ROLLED_BACK: "failure",
    RunStatus.ROLLBACK_FAILED: "failure",
    RunStatus.ERROR: "error",
}


def build_graph(deps: PipelineDeps, checkpointer: Any):
    evidence = deps.evidence

    # ------------------------------------------------------------------ helpers

    def run_of(state: PipelineState) -> PipelineRun:
        return PipelineRun.model_validate(state["run"])

    def notify(method: str, *args: Any) -> None:
        try:
            getattr(deps.notifier, method)(*args)
        except Exception:  # noqa: BLE001 - a failed notification never changes the run
            log.exception("notifier.%s failed", method)

    def execute(agent: Agent, state: PipelineState, event: EventType, **options: Any):
        """Run an agent and save its result. An ERROR is saved as AGENT_ERROR."""
        result = agent.execute(state, **options)
        run_id = state["run"]["run_id"]
        if result.status is AgentStatus.ERROR:
            evidence.append(run_id, EventType.AGENT_ERROR, result)
            return result, None
        evidence.append(
            run_id, event, {"agent": result.agent, "agent_status": result.status, **result.data}
        )
        return result, result.data

    def deploys(state: PipelineState) -> bool:
        """CLAUDE.md §11 item 2: pull request runs evaluate only. Pushes deploy."""
        return state["run"]["event"] == "push"

    def authorized(state: PipelineState) -> bool:
        """Deploy only on ALLOW, or ESCALATE with an APPROVE for this run (G6)."""
        if not state.get("decision"):
            return False
        decision = ReleaseDecision.model_validate(state["decision"])
        approval = Approval.model_validate(state["approval"]) if state.get("approval") else None
        return decision.is_deployable(approval)

    # ------------------------------------------------------------------ nodes

    def setup_check(state: PipelineState) -> dict:
        problems = deps.setup_check()
        if not problems:
            return {"setup_problems": []}
        run = run_of(state)
        evidence.append(run.run_id, EventType.SETUP_FAILED, {"problems": problems})
        notify("alert", run, "Pipeline setup problem", "\n".join(f"- {p}" for p in problems))
        return {"setup_problems": problems, "status": RunStatus.ERROR.value}

    def build(state: PipelineState) -> dict:
        result, data = execute(deps.build_agent, state, EventType.BUILD_RESULT)
        return {"build": data, "agent_results": [result.model_dump(mode="json")]}

    def test(state: PipelineState) -> dict:
        result, data = execute(deps.test_agent, state, EventType.TEST_REPORT)
        return {"test": data, "agent_results": [result.model_dump(mode="json")]}

    def security(state: PipelineState) -> dict:
        result, data = execute(deps.security_agent, state, EventType.SECURITY_REPORT)
        return {"security": data, "agent_results": [result.model_dump(mode="json")]}

    def policy(state: PipelineState) -> dict:
        run = run_of(state)
        result, data = execute(deps.policy_agent, state, EventType.DECISION)
        if data is None:
            # No decision exists, so nothing can be deployed.
            notify("alert", run, "Policy evaluation failed", result.summary)
            return {"decision": None, "status": RunStatus.ERROR.value}
        decision = ReleaseDecision.model_validate(data)
        notify("post_decision", run, decision, policy_input_from_state(state))
        if decision.outcome is Outcome.DENY:
            return {"decision": data, "status": RunStatus.DENIED.value}
        if decision.outcome is Outcome.ESCALATE:
            return {"decision": data, "status": RunStatus.AWAITING_REVIEW.value}
        status = RunStatus.DEPLOYING if deploys(state) else RunStatus.ALLOWED
        return {"decision": data, "status": status.value}

    def request_review(state: PipelineState) -> dict:
        """Runs once. The pause is in the next node, because LangGraph re-runs a paused
        node from its start on resume and the reviewers must not be notified twice."""
        run = run_of(state)
        decision = ReleaseDecision.model_validate(state["decision"])
        deadline = utc_now() + timedelta(seconds=deps.policy.timers.review_timeout_s)
        evidence.append(
            run.run_id,
            EventType.REVIEW_REQUESTED,
            {
                "commit_sha": run.commit_sha,
                "reviewers": list(deps.policy.reviewers),
                "deadline_at": deadline.isoformat(),
            },
        )
        notify("set_status", run, "pending", "ESCALATE: waiting for a reviewer")
        notify("request_review", run, decision, deps.policy.reviewers, deadline)
        return {"review_deadline": deadline.isoformat()}

    def human_review(state: PipelineState) -> dict:
        run = run_of(state)
        answer = interrupt({"run_id": run.run_id, "commit_sha": run.commit_sha})
        approval = Approval.model_validate(answer)
        evidence.append(run.run_id, EventType.REVIEW_VERDICT, approval)
        update = {"approval": approval.model_dump(mode="json")}
        if approval.verdict is Verdict.APPROVE and authorized({**state, **update}):
            status = RunStatus.DEPLOYING if deploys(state) else RunStatus.ALLOWED
            return {**update, "status": status.value}
        if approval.verdict is Verdict.TIMEOUT:
            notify(
                "alert",
                run,
                "Review timed out: change denied",
                "No reviewer answered before the deadline, so the change is denied (FR15).",
            )
        return {**update, "status": RunStatus.DENIED.value}

    def deploy(state: PipelineState) -> dict:
        run = run_of(state)
        if not authorized(state):  # defense in depth: the edges already check this
            evidence.append(
                run.run_id,
                EventType.AGENT_ERROR,
                {"agent": "deployment", "errors": ["deploy refused: run is not authorized"]},
            )
            return {"status": RunStatus.ERROR.value}
        try:
            deps.deploy_lock.acquire(run.run_id, deps.deploy_lock_timeout_s)
        except DeployLockTimeout as exc:
            evidence.append(
                run.run_id, EventType.AGENT_ERROR, {"agent": "deployment", "errors": [str(exc)]}
            )
            notify("alert", run, "Deploy did not start", str(exc))
            return {"status": RunStatus.ERROR.value}

        result, data = execute(deps.deployment_agent, state, EventType.DEPLOY_RESULT)
        results = [result.model_dump(mode="json")]
        if data is not None and data["status"] == DeployStatus.STARTED.value:
            return {
                "deployment": data,
                "agent_results": results,
                "status": RunStatus.MONITORING.value,
            }

        # The deploy did not start, so there is nothing to monitor: give the lock back.
        deps.deploy_lock.release(run.run_id)
        if data is None:
            notify("alert", run, "Deploy failed", result.summary)
            return {"agent_results": results, "status": RunStatus.ERROR.value}
        record = DeploymentRecord.model_validate(data)
        if record.status is DeployStatus.ROLLBACK_FAILED:
            evidence.append(run.run_id, EventType.ROLLBACK_FAILED, record)
            notify("alert", run, "ROLLBACK FAILED: sandbox needs attention", record.error or "")
            status = RunStatus.ROLLBACK_FAILED
        elif record.previous_container:
            status = RunStatus.ROLLED_BACK  # new version never started; old one is running
        else:
            status = RunStatus.ERROR
        return {"deployment": data, "agent_results": results, "status": status.value}

    def monitor(state: PipelineState) -> dict:
        run = run_of(state)
        try:
            deps.deploy_lock.acquire(run.run_id, deps.deploy_lock_timeout_s)  # no-op if held

            def save_check(check: HealthCheck) -> None:
                evidence.append(run.run_id, EventType.HEALTH_CHECK, check)

            result = deps.monitoring_agent.execute(state, on_check=save_check)
            results = [result.model_dump(mode="json")]
            if result.status is AgentStatus.ERROR:
                evidence.append(run.run_id, EventType.AGENT_ERROR, result)
                notify("alert", run, "Monitoring failed: sandbox state unknown", result.summary)
                return {"agent_results": results, "status": RunStatus.ERROR.value}

            record = DeploymentRecord.model_validate(result.data["deployment"])
            data = record.model_dump(mode="json")
            if record.status is DeployStatus.HEALTHY:
                evidence.append(run.run_id, EventType.DEPLOY_RESULT, record)
                status = RunStatus.DEPLOYED
            elif record.status is DeployStatus.ROLLED_BACK:
                evidence.append(run.run_id, EventType.ROLLBACK, record)
                status = RunStatus.ROLLED_BACK
            else:
                evidence.append(run.run_id, EventType.ROLLBACK_FAILED, record)
                notify("alert", run, "ROLLBACK FAILED: sandbox needs attention", record.error or "")
                status = RunStatus.ROLLBACK_FAILED
            return {"deployment": data, "agent_results": results, "status": status.value}
        finally:
            deps.deploy_lock.release(run.run_id)

    def finish(state: PipelineState) -> dict:
        run = run_of(state)
        status = RunStatus(state.get("status", RunStatus.ERROR.value))
        if status not in _FINAL_COMMIT_STATE:
            status = RunStatus.ERROR  # a run must not end in a "still going" state
        outcome = (state.get("decision") or {}).get("outcome")
        evidence.append(
            run.run_id, EventType.RUN_FINISHED, {"status": status.value, "outcome": outcome}
        )
        notify("set_status", run, _FINAL_COMMIT_STATE[status], f"{status.value} (run {run.run_id})")
        return {"status": status.value}

    # ------------------------------------------------------------------ routing

    def after_setup(state: PipelineState) -> str:
        return "finish" if state.get("setup_problems") else "build"

    def after_build(state: PipelineState) -> list[str]:
        # FR5: a failed build goes straight to the rules, which DENY it.
        built = (state.get("build") or {}).get("success") is True
        return ["test", "security"] if built else ["policy"]

    def after_policy(state: PipelineState) -> str:
        outcome = (state.get("decision") or {}).get("outcome")
        if outcome == Outcome.ESCALATE.value:
            return "request_review"
        if outcome == Outcome.ALLOW.value and deploys(state) and authorized(state):
            return "deploy"
        return "finish"

    def after_review(state: PipelineState) -> str:
        return "deploy" if deploys(state) and authorized(state) else "finish"

    def after_deploy(state: PipelineState) -> str:
        return "monitor" if state.get("status") == RunStatus.MONITORING.value else "finish"

    # ------------------------------------------------------------------ wiring

    graph = StateGraph(PipelineState)
    for name, node in (
        ("setup_check", setup_check),
        ("build", build),
        ("test", test),
        ("security", security),
        ("policy", policy),
        ("request_review", request_review),
        (REVIEW_NODE, human_review),
        ("deploy", deploy),
        ("monitor", monitor),
        ("finish", finish),
    ):
        graph.add_node(name, node)

    graph.add_edge(START, "setup_check")
    graph.add_conditional_edges("setup_check", after_setup, ["build", "finish"])
    graph.add_conditional_edges("build", after_build, ["test", "security", "policy"])
    graph.add_edge(["test", "security"], "policy")
    graph.add_conditional_edges("policy", after_policy, ["request_review", "deploy", "finish"])
    graph.add_edge("request_review", REVIEW_NODE)
    graph.add_conditional_edges(REVIEW_NODE, after_review, ["deploy", "finish"])
    graph.add_conditional_edges("deploy", after_deploy, ["monitor", "finish"])
    graph.add_edge("monitor", "finish")
    graph.add_edge("finish", END)
    return graph.compile(checkpointer=checkpointer)
