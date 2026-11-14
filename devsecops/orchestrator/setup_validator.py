"""Checks that the host can run a pipeline before a run starts (FR3)."""

import os
from collections.abc import Mapping
from pathlib import Path

from devsecops.policy.loader import PolicyError, load_policy
from devsecops.tools.docker_client import DockerClient


class SetupValidator:
    def __init__(
        self,
        docker: DockerClient,
        policy_path: str | Path,
        required_env: tuple[str, ...] = ("GITHUB_TOKEN", "CONTROL_API_TOKEN"),
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._docker = docker
        self._policy_path = Path(policy_path)
        self._required_env = required_env
        self._environ = os.environ if environ is None else environ

    def problems(self) -> list[str]:
        """Empty when everything is in place. Messages name what is missing, never a value."""
        found: list[str] = []
        if not self._docker.is_available():
            found.append("Docker is not installed or the daemon is not running")
        try:
            load_policy(self._policy_path)
        except PolicyError as exc:
            found.append(str(exc))
        for name in self._required_env:
            if not self._environ.get(name, "").strip():
                found.append(f"environment variable {name} is not set")
        return found
