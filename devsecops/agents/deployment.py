"""Deployment Agent: keeps the old container and starts the new one (FR16)."""

from collections.abc import Mapping
from typing import Any

from devsecops.agents.base import Agent
from devsecops.models import AgentStatus, DeploymentRecord, DeployStatus
from devsecops.tools.sandbox import Sandbox


class DeploymentAgent(Agent):
    name = "deployment"
    output_model = DeploymentRecord

    def __init__(self, sandbox: Sandbox, schema_retries: int = 2) -> None:
        super().__init__(schema_retries)
        self._sandbox = sandbox

    def run(self, state: Mapping[str, Any], **options: Any) -> Any:
        return self._sandbox.deploy(state["run"]["run_id"], state["build"]["image_tag"])

    def status_of(self, output: DeploymentRecord) -> AgentStatus:
        return AgentStatus.OK if output.status is DeployStatus.STARTED else AgentStatus.FAILED

    def summarize(self, output: DeploymentRecord) -> str:
        text = f"{output.image_tag}: {output.status.value}"
        return f"{text} ({output.error})"[:300] if output.error else text
