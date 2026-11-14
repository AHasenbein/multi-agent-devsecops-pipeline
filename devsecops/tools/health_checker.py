"""Sends GET /health to the sandbox app and records the result (FR17)."""

import time

import httpx

from devsecops.models import HealthCheck


class HealthChecker:
    def __init__(self, client: httpx.Client | None = None, timeout_s: float = 5.0) -> None:
        self._client = client or httpx.Client(follow_redirects=False)
        self._timeout_s = timeout_s

    def check(self, url: str) -> HealthCheck:
        """Never raises: a sandbox that cannot be reached is a failed check, not a crash."""
        started = time.perf_counter()
        try:
            response = self._client.get(url, timeout=self._timeout_s)
        except httpx.HTTPError as exc:
            return HealthCheck(ok=False, error=f"{type(exc).__name__}: {exc}"[:300])
        latency_ms = round((time.perf_counter() - started) * 1000, 1)
        ok = response.status_code == 200
        return HealthCheck(
            ok=ok,
            status_code=response.status_code,
            latency_ms=latency_ms,
            error=None if ok else f"unexpected status {response.status_code}",
        )
