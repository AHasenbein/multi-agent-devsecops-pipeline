"""Build Agent: builds the app into a Docker image (FR4, FR5)."""

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from devsecops.agents.base import Agent
from devsecops.models import AgentStatus, BuildResult
from devsecops.tools.docker_client import DockerClient


class BuildAgent(Agent):
    name = "build"
    output_model = BuildResult

    def __init__(
        self,
        docker: DockerClient,
        app_dir: str = "sample_app",
        image_name: str = "sample_app",
        schema_retries: int = 2,
    ) -> None:
        super().__init__(schema_retries)
        self._docker = docker
        self._app_dir = app_dir
        self._image_name = image_name

    def run(self, state: Mapping[str, Any], **options: Any) -> Any:
        commit = re.sub(r"[^A-Za-z0-9_.-]", "-", state["run"]["commit_sha"])[:12]
        image_tag = f"{self._image_name}:{commit}"
        return self._docker.build(Path(state["workspace"]) / self._app_dir, image_tag)

    def status_of(self, output: BuildResult) -> AgentStatus:
        return AgentStatus.OK if output.success else AgentStatus.FAILED

    def summarize(self, output: BuildResult) -> str:
        if output.success:
            return f"built {output.image_tag}"
        return f"build failed: {output.errors[0] if output.errors else 'no error text'}"[:300]
