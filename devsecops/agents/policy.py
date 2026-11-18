"""Policy Agent: asks the RuleEngine for the decision, then asks for a reason (FR10-FR13)."""

import logging
from collections.abc import Callable, Mapping
from typing import Any

from devsecops.agents.base import Agent
from devsecops.models import (
    AgentResult,
    BuildResult,
    PolicyInput,
    ReleaseDecision,
    SecurityReport,
    TestReport,
)
from devsecops.policy.rule_engine import RuleEngine

log = logging.getLogger(__name__)

# Writes the human-readable reason for a decision that is already made. Returns None (or
# raises) when it has nothing to offer; the template reason is then kept.
# ``devsecops.llm.ClaudeClient.write_reason`` is the real one.
ReasonWriter = Callable[[ReleaseDecision, PolicyInput], str | None]


def policy_input_from_state(state: Mapping[str, Any]) -> PolicyInput:
    """Collect the evidence the rules look at. Missing results stay None (fail closed)."""

    def load(model: type, key: str) -> Any:
        return model.model_validate(state[key]) if state.get(key) is not None else None

    return PolicyInput(
        run_id=state["run"]["run_id"],
        build=load(BuildResult, "build"),
        test=load(TestReport, "test"),
        security=load(SecurityReport, "security"),
        agent_results=[AgentResult.model_validate(r) for r in state.get("agent_results", [])],
        changed_files=list(state.get("changed_files", [])),
    )


class PolicyAgent(Agent):
    name = "policy"
    output_model = ReleaseDecision

    def __init__(
        self,
        engine: RuleEngine,
        reason_writer: ReasonWriter | None = None,
        schema_retries: int = 2,
    ) -> None:
        super().__init__(schema_retries)
        self._engine = engine
        self._reason_writer = reason_writer

    def run(self, state: Mapping[str, Any], **options: Any) -> Any:
        results = policy_input_from_state(state)
        # The outcome is final here, before any LLM is involved (invariant 1).
        decision = self._engine.evaluate(results)
        if self._reason_writer is None:
            return decision
        try:
            reason = self._reason_writer(decision, results)
        except Exception:  # noqa: BLE001 - the reason is optional, the decision is not
            log.exception("reason writer failed; keeping the template reason")
            return decision
        if not reason or not reason.strip():
            return decision
        return decision.with_reason(reason.strip(), "claude")

    def summarize(self, output: ReleaseDecision) -> str:
        rules = ", ".join(output.matched_rules) or "no rule matched"
        return f"{output.outcome.value} ({rules})"
