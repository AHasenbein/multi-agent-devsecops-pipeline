"""Shared pieces for the tool adapters: running a command, and the error they raise."""

import os
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, Field

from devsecops.models import Finding

# Environment variables with these words in the name are never passed to a tool (QA-PR-01).
# The tools run code from the change being evaluated, so they must not see pipeline secrets.
_SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL", re.IGNORECASE)


class ToolError(Exception):
    """A tool crashed, timed out, or produced output that cannot be read.

    This is different from the tool reporting a problem with the change. A failing test is a
    result; pytest crashing is a ToolError, which the agents turn into an ERROR (ESCALATE).
    """


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    def tail(self, limit: int = 2000) -> str:
        text = (self.stdout + "\n" + self.stderr).strip()
        return text[-limit:]


Runner = Callable[..., CommandResult]


class ScanOutput(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    tool_errors: list[str] = Field(default_factory=list)


def scrubbed_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {name: value for name, value in os.environ.items() if not _SECRET_NAME.search(name)}
    env.update(extra or {})
    return env


def run_command(
    args: Sequence[str],
    *,
    cwd: str | Path | None = None,
    timeout: float | None = None,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    """Run a command without a shell. ``env`` adds variables to a secret-free environment."""
    args = tuple(str(arg) for arg in args)
    try:
        done = subprocess.run(  # noqa: S603 - argument list, no shell
            args,
            cwd=cwd,
            env=scrubbed_env(env),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolError(f"{args[0]}: command not found") from exc
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            args=args,
            returncode=-1,
            stdout=_text(exc.stdout),
            stderr=_text(exc.stderr),
            timed_out=True,
        )
    return CommandResult(
        args=args, returncode=done.returncode, stdout=done.stdout, stderr=done.stderr
    )


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value
