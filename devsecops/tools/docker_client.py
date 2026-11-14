"""Docker adapter: build images and run, stop, start, rename and roll back containers
(FR4, FR16, FR17). It drives the ``docker`` CLI so it can be faked with a command runner."""

from pathlib import Path

from devsecops.models import BuildResult, Container
from devsecops.tools.base import CommandResult, Runner, ToolError, run_command

_LOG_TAIL = 4000
_MAX_ERRORS = 20
_INSPECT_FORMAT = "{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.State.Status}}"


class DockerError(ToolError):
    """A docker command failed."""


class DockerClient:
    def __init__(
        self,
        runner: Runner = run_command,
        docker: str = "docker",
        build_timeout_s: float = 600,
        command_timeout_s: float = 60,
    ) -> None:
        self._runner = runner
        self._docker = docker
        self._build_timeout_s = build_timeout_s
        self._command_timeout_s = command_timeout_s

    # ------------------------------------------------------------------ setup check (FR3)

    def is_available(self) -> bool:
        try:
            result = self._runner(
                [self._docker, "info", "--format", "{{.ServerVersion}}"],
                timeout=self._command_timeout_s,
            )
        except ToolError:
            return False
        return result.returncode == 0 and not result.timed_out

    # ------------------------------------------------------------------ build (FR4)

    def build(
        self, context_dir: str | Path, image_tag: str, dockerfile: str | None = None
    ) -> BuildResult:
        """A failed build is a result (success=False), not an exception: it leads to DENY."""
        args = [self._docker, "build", "--tag", image_tag]
        if dockerfile:
            args += ["--file", dockerfile]
        args.append(str(context_dir))
        result = self._runner(args, timeout=self._build_timeout_s)
        if result.timed_out:
            return BuildResult(
                image_tag=image_tag,
                success=False,
                errors=[f"docker build timed out after {self._build_timeout_s:g} s"],
                log_tail=result.tail(_LOG_TAIL),
            )
        if result.returncode != 0:
            return BuildResult(
                image_tag=image_tag,
                success=False,
                errors=_build_errors(result),
                log_tail=result.tail(_LOG_TAIL),
            )
        return BuildResult(image_tag=image_tag, success=True, log_tail=result.tail(_LOG_TAIL))

    # ------------------------------------------------------------------ containers (FR16)

    def run(
        self, image_tag: str, name: str, host_port: int = 8080, container_port: int = 8080
    ) -> Container:
        """Start a detached container, published on localhost only."""
        self._docker_ok(
            [
                "run",
                "--detach",
                "--name",
                name,
                "--publish",
                f"127.0.0.1:{host_port}:{container_port}",
                image_tag,
            ]
        )
        container = self.inspect(name)
        if container is None:
            raise DockerError(f"container {name} was started but cannot be inspected")
        return container

    def stop(self, name: str) -> None:
        self._docker_ok(["stop", name])

    def start(self, name: str) -> None:
        self._docker_ok(["start", name])

    def rename(self, name: str, new_name: str) -> None:
        self._docker_ok(["rename", name, new_name])

    def remove(self, name: str) -> None:
        self._docker_ok(["rm", "--force", name])

    def inspect(self, name: str) -> Container | None:
        """The container with this name, or None if there is none."""
        result = self._runner(
            [self._docker, "inspect", "--type", "container", "--format", _INSPECT_FORMAT, name],
            timeout=self._command_timeout_s,
        )
        if result.timed_out:
            raise DockerError(f"docker inspect {name} timed out")
        if result.returncode != 0:
            return None
        parts = result.stdout.strip().split("|")
        if len(parts) != 4:
            raise DockerError(f"docker inspect {name}: unexpected output {result.stdout!r}")
        container_id, container_name, image, status = parts
        return Container(
            id=container_id, name=container_name.lstrip("/"), image_tag=image, status=status
        )

    # ------------------------------------------------------------------ rollback (FR17)

    def rollback(self, name: str, previous_name: str) -> Container:
        """Replace the container ``name`` with the kept container ``previous_name``.

        Raises DockerError if the old version cannot be brought back (FR18).
        """
        if self.inspect(previous_name) is None:
            raise DockerError(f"no previous container {previous_name} to roll back to")
        if self.inspect(name) is not None:
            self.remove(name)  # frees the name and the published port
        self.rename(previous_name, name)
        self.start(name)
        container = self.inspect(name)
        if container is None or container.status != "running":
            status = container.status if container else "missing"
            raise DockerError(f"rolled back container {name} is not running (status: {status})")
        return container

    # ------------------------------------------------------------------ helpers

    def _docker_ok(self, args: list[str]) -> CommandResult:
        result = self._runner([self._docker, *args], timeout=self._command_timeout_s)
        if result.timed_out:
            raise DockerError(f"docker {args[0]} timed out after {self._command_timeout_s:g} s")
        if result.returncode != 0:
            raise DockerError(
                f"docker {args[0]} failed with code {result.returncode}: {result.tail(500)}"
            )
        return result


def _build_errors(result: CommandResult) -> list[str]:
    lines = [line.strip() for line in (result.stderr + "\n" + result.stdout).splitlines()]
    errors = [line for line in lines if "error" in line.lower()]
    if not errors:
        errors = [line for line in lines if line][-3:] or [
            f"docker build failed with code {result.returncode}"
        ]
    return list(dict.fromkeys(errors))[:_MAX_ERRORS]
