"""Checks out the commit being evaluated into a directory of its own (FR1, FR4).

The Control API does not trust a path handed to it by the workflow: it fetches the commit
from the app repo itself, so each run has a private checkout that no other job can change.
The diff and the list of changed files come from the same checkout.
"""

import base64
import os
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from devsecops.tools.base import CommandResult, Runner, ToolError, run_command

_SHA = re.compile(r"[0-9a-f]{40}")
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_NO_COMMIT = "0" * 40  # GitHub sends this as "before" when a branch is new
_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # git's well-known empty tree
# Branch tips and pull request heads. Enough to find any commit a push or PR event names.
_REFSPECS = ("+refs/heads/*:refs/remotes/origin/*", "+refs/pull/*/head:refs/remotes/pull/*")


class WorkspaceError(ToolError):
    """The commit could not be checked out. The message never contains the token."""


@dataclass(frozen=True)
class Checkout:
    path: Path
    diff: str
    changed_files: list[str]


class GitWorkspaces:
    def __init__(
        self,
        root: str | Path,
        remote_url: str,
        token: str | None = None,
        runner: Runner = run_command,
        timeout_s: float = 120,
    ) -> None:
        self._root = Path(root)
        self._remote_url = remote_url
        self._token = token or None
        self._runner = runner
        self._timeout_s = timeout_s

    def prepare(self, run_id: str, commit_sha: str, base_sha: str | None = None) -> Checkout:
        """Check out ``commit_sha`` for this run and work out what the change is.

        The change is everything between ``base_sha`` and the commit (for a push: the commit
        that was on the branch before; for a pull request: the base branch). Without a usable
        base it is the commit compared with its first parent."""
        commit_sha = commit_sha.lower()
        if not _SHA.fullmatch(commit_sha):
            raise WorkspaceError("commit_sha must be a full 40-character commit id")
        path = self._path(run_id)
        if path.exists():
            raise WorkspaceError(f"a checkout for run {run_id} already exists")
        path.mkdir(parents=True)

        try:
            self._git(path, "init", "-q")
            # The URL is passed to fetch directly, so nothing about the remote is saved.
            fetched = self._git(
                path, "fetch", "-q", "--no-tags", self._remote_url, *_REFSPECS, check=False
            )
            if not self._has_commit(path, commit_sha):
                # Not on a branch tip or PR head we fetched: ask for the commit by id.
                direct = self._git(
                    path, "fetch", "-q", "--no-tags", self._remote_url, commit_sha, check=False
                )
                if not self._has_commit(path, commit_sha):
                    failed = fetched if fetched.returncode != 0 else direct
                    raise WorkspaceError(
                        f"commit {commit_sha} was not found in the app repo" + self._detail(failed)
                    )
            self._git(path, "checkout", "-q", "--detach", commit_sha)
            _make_readable(path)

            base = self._base(path, commit_sha, base_sha)
            diff = self._git(path, "diff", "--no-color", "--no-ext-diff", base, commit_sha).stdout
            # --no-renames: a renamed file is listed under both names, so moving an
            # important file away still shows its old path.
            names = self._git(
                path, "diff", "--name-only", "--no-renames", "-z", base, commit_sha
            ).stdout
        except BaseException:
            shutil.rmtree(path, ignore_errors=True)
            raise
        return Checkout(path=path, diff=diff, changed_files=[n for n in names.split("\0") if n])

    def remove(self, run_id: str) -> None:
        """Delete the run's checkout. Safe to call when there is none."""
        shutil.rmtree(self._path(run_id), ignore_errors=True)

    # ------------------------------------------------------------------ internals

    def _path(self, run_id: str) -> Path:
        if not _RUN_ID.fullmatch(run_id):
            raise WorkspaceError("run_id is not usable as a directory name")
        return self._root / run_id

    def _base(self, path: Path, commit_sha: str, base_sha: str | None) -> str:
        base_sha = (base_sha or "").lower()
        if _SHA.fullmatch(base_sha) and base_sha != _NO_COMMIT:
            if not self._has_commit(path, base_sha):
                self._git(path, "fetch", "-q", "--no-tags", self._remote_url, base_sha, check=False)
            if self._has_commit(path, base_sha):
                # The common ancestor, so a pull request is compared with where it branched
                # off and not with newer commits on the base branch.
                merge_base = self._git(path, "merge-base", base_sha, commit_sha, check=False)
                found = merge_base.stdout.strip()
                return found if merge_base.returncode == 0 and found else base_sha
        parent = f"{commit_sha}^1"
        return parent if self._has_commit(path, parent) else _EMPTY_TREE

    def _has_commit(self, path: Path, rev: str) -> bool:
        return self._git(path, "cat-file", "-e", f"{rev}^{{commit}}", check=False).returncode == 0

    def _git(self, path: Path, *args: str, check: bool = True) -> CommandResult:
        result = self._runner(
            ["git", "-C", str(path), *args], timeout=self._timeout_s, env=self._env()
        )
        if check and (result.returncode != 0 or result.timed_out):
            raise WorkspaceError(f"git {args[0]} failed" + self._detail(result))
        return result

    def _env(self) -> Mapping[str, str]:
        # Never ask for a password on a terminal, and ignore the host user's git settings.
        env = {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        if self._token:
            # The token travels in the environment, not in the command line or the URL, so
            # it is not visible in the process list and is not written to .git/config. The
            # setting is scoped to github.com, so no other server is ever sent it.
            env.update(
                {
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "http.https://github.com/.extraHeader",
                    "GIT_CONFIG_VALUE_0": f"Authorization: Basic {self._basic()}",
                }
            )
        return env

    def _basic(self) -> str:
        return base64.b64encode(f"x-access-token:{self._token}".encode()).decode()

    def _detail(self, result: CommandResult) -> str:
        if result.timed_out:
            return f" (timed out after {self._timeout_s:g} s)"
        text = result.stderr.strip()
        if self._token:  # before cutting, so a cut can never leave part of the token
            text = text.replace(self._token, "***").replace(self._basic(), "***")
        return f": {text[-300:]}" if text else ""


def _make_readable(root: Path) -> None:
    """Give the checked-out files the modes git would give them under umask 022.

    The Control API runs with umask 077 (scripts/install_daemon.sh), so git creates the
    work tree owner-only. ``docker build`` copies those modes into the image, and the app's
    non-root user then cannot read its own code: the container exits at start. The
    checkout stays private all the same, because it sits inside the owner-only state
    directory. ``.git`` is left alone; it is not part of the build.
    """
    for current, subdirs, files in os.walk(root):
        directory = Path(current)
        if directory == root and ".git" in subdirs:
            subdirs.remove(".git")
        directory.chmod(0o755)
        for name in files:
            file = directory / name
            if file.is_symlink():
                continue
            file.chmod(0o755 if file.stat().st_mode & 0o100 else 0o644)
