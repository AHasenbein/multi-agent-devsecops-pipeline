"""HealthChecker: GET /health on the sandbox (FR17)."""

import httpx
import pytest
from fastapi.testclient import TestClient

from devsecops.tools import HealthChecker

URL = "http://127.0.0.1:8080/health"


def checker(handler) -> HealthChecker:
    return HealthChecker(client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_fr17_healthy_app_gives_ok_with_status_and_latency():
    result = checker(lambda request: httpx.Response(200, json={"status": "ok"})).check(URL)
    assert result.ok
    assert result.status_code == 200
    assert result.latency_ms is not None and result.latency_ms >= 0
    assert result.error is None
    assert result.at.tzinfo is not None


@pytest.mark.parametrize("status", [500, 503, 404, 302])
def test_fr17_non_200_status_is_a_failed_check(status):
    result = checker(lambda request: httpx.Response(status)).check(URL)
    assert not result.ok
    assert result.status_code == status
    assert str(status) in result.error


@pytest.mark.parametrize(
    "error",
    [httpx.ConnectError("connection refused"), httpx.ReadTimeout("timed out")],
)
def test_fr17_unreachable_sandbox_is_a_failed_check_not_an_exception(error):
    def handler(request):
        raise error

    result = checker(handler).check(URL)
    assert not result.ok
    assert result.status_code is None
    assert type(error).__name__ in result.error


def test_real_connection_refused_is_a_failed_check():
    result = HealthChecker(timeout_s=1).check("http://127.0.0.1:1/health")
    assert not result.ok
    assert result.error


@pytest.mark.filterwarnings("ignore:You should not use the 'timeout' argument")
def test_fr17_sample_app_health_endpoint_passes_the_check(monkeypatch):
    """Phase 2 exit criterion: the checker and the sample app agree on what healthy means."""
    import sys
    from pathlib import Path

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "sample_app"))
    for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
        monkeypatch.delitem(sys.modules, name)
    from app.main import app

    result = HealthChecker(client=TestClient(app)).check("/health")
    assert result.ok
    assert result.status_code == 200
