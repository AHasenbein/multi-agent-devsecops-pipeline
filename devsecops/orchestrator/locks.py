"""The global deploy lock (CLAUDE.md §1 invariant 7).

Deploy + monitor is serialized so two runs cannot overwrite each other's rollback target.
It is a file lock, so it also holds across processes on the host, and the OS releases it
if the process dies.
"""

import fcntl
import os
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path


class DeployLockTimeout(Exception):
    """Another run held the deploy lock for longer than this run was willing to wait."""


class DeployLock:
    def __init__(
        self,
        path: str | Path,
        poll_s: float = 0.2,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._path = Path(path)
        self._poll_s = poll_s
        self._sleep = sleep
        self._clock = clock
        self._held: dict[str, int] = {}  # run_id -> open file descriptor
        self._guard = threading.Lock()

    def acquire(self, run_id: str, timeout_s: float = 3600) -> None:
        """Take the lock for ``run_id``. A run that already holds it keeps it (no deadlock
        when a deploy step is retried)."""
        with self._guard:
            if run_id in self._held:
                return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = self._clock() + timeout_s
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if self._clock() >= deadline:
                        raise DeployLockTimeout(
                            f"run {run_id} waited {timeout_s:g} s for the deploy lock "
                            f"(held by run {self.holder() or 'unknown'})"
                        ) from None
                    self._sleep(self._poll_s)
            os.ftruncate(fd, 0)
            os.pwrite(fd, run_id.encode(), 0)
        except BaseException:
            os.close(fd)
            raise
        with self._guard:
            self._held[run_id] = fd

    def release(self, run_id: str) -> None:
        """Give the lock back. Safe to call when ``run_id`` does not hold it."""
        with self._guard:
            fd = self._held.pop(run_id, None)
        if fd is None:
            return
        try:
            os.ftruncate(fd, 0)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    @contextmanager
    def hold(self, run_id: str, timeout_s: float = 3600) -> Iterator[None]:
        self.acquire(run_id, timeout_s)
        try:
            yield
        finally:
            self.release(run_id)

    def holder(self) -> str | None:
        """The run_id written by the current holder, for messages only."""
        try:
            return self._path.read_text().strip() or None
        except OSError:
            return None
