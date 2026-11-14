"""The global deploy lock (CLAUDE.md §1 invariant 7).

Deploy + monitor is serialized so two runs cannot overwrite each other's rollback target.
It is a file lock, so it also holds across processes on the host.
"""

import fcntl
import os
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

    @contextmanager
    def hold(self, run_id: str, timeout_s: float = 1800) -> Iterator[None]:
        """Hold the lock for the ``with`` block. The OS releases it if the process dies."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            deadline = self._clock() + timeout_s
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
            try:
                yield
            finally:
                os.ftruncate(fd, 0)
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def holder(self) -> str | None:
        """The run_id written by the current holder, for messages only."""
        try:
            return self._path.read_text().strip() or None
        except OSError:
            return None
