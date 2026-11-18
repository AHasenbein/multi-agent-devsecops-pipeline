"""The Control API application (CLAUDE.md §2 and §7).

A long-running daemon on the team host, not something a workflow job starts:

    uvicorn devsecops.api.main:create_app_from_env --factory --host 127.0.0.1 --port 8000

It needs CONTROL_API_TOKEN, GITHUB_TOKEN and DEVSECOPS_APP_REPO in its environment. Every
route except GET /health asks for ``Authorization: Bearer <CONTROL_API_TOKEN>``.

When it starts, it closes the runs that the previous process left unfinished as ERROR
(CLAUDE.md §11 item 12). Runs paused for review are kept. While it runs, a background
thread denies the reviews whose deadline has passed (FR15).
"""

import functools
import hmac
import logging
import os
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from devsecops.api.approvals import approvals_router
from devsecops.api.runs import RunService, Workspaces, runs_router
from devsecops.evidence import EvidenceStore
from devsecops.models import HealthCheck, PolicySet, utc_now
from devsecops.orchestrator.approval_service import ApprovalService
from devsecops.orchestrator.orchestrator import Orchestrator

log = logging.getLogger(__name__)

Submit = Callable[[Callable[[], Any]], Any]


@dataclass
class ApiServices:
    """Everything the routes need. Tests pass fakes; ``create_app_from_env`` passes the
    real ones."""

    policy: PolicySet
    evidence: EvidenceStore
    orchestrator: Orchestrator
    workspaces: Workspaces
    token: str  # CONTROL_API_TOKEN
    sandbox_probe: Callable[[], HealthCheck]
    submit: Submit  # runs a function in the background
    shutdown: Callable[[], None] = lambda: None
    sweep_interval_s: float = 30  # how often overdue reviews are timed out (FR15)
    clock: Callable[[], datetime] = utc_now


class ReviewSweeper:
    """Times out overdue reviews (FR15) on a thread of its own: once at start, which
    covers deadlines that passed while the daemon was down, then every interval."""

    def __init__(self, service: ApprovalService, interval_s: float) -> None:
        self._service = service
        self._interval_s = interval_s
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="review-sweeper", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._service.expire_overdue()
            except Exception:  # noqa: BLE001 - the sweeper must outlive one bad sweep
                log.exception("review sweep failed")
            self._stop.wait(self._interval_s)


def create_app(services: ApiServices) -> FastAPI:
    if not services.token.strip():
        # Fail closed: without a token nobody could be told apart from anybody.
        raise ValueError("CONTROL_API_TOKEN is not set")
    expected = services.token.strip().encode()
    bearer = HTTPBearer(auto_error=False)

    def authenticated(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),  # noqa: B008
    ) -> None:
        given = credentials.credentials.encode() if credentials else b""
        if not hmac.compare_digest(given, expected):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "missing or wrong bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Before the first request is served: a run that the previous process left
        # unfinished gets its final ERROR record. GitHub is told in the background.
        services.submit(services.orchestrator.fail_interrupted_runs())
        sweeper = ReviewSweeper(approval_service, services.sweep_interval_s)
        sweeper.start()
        try:
            yield
        finally:
            sweeper.stop()
            services.shutdown()

    # No generated docs pages: they would be the only routes open without the token.
    app = FastAPI(
        title="DevSecOps Control API",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    protected = [Depends(authenticated)]
    approval_service = ApprovalService(
        services.policy, services.orchestrator, services.evidence, services.clock
    )
    run_service = RunService(
        services.orchestrator,
        services.evidence,
        services.workspaces,
        services.submit,
        services.sandbox_probe,
    )
    app.include_router(runs_router(run_service), dependencies=protected)
    app.include_router(
        approvals_router(approval_service, services.submit),
        dependencies=protected,
    )

    @app.get("/policies", dependencies=protected, tags=["policies"])
    def get_policies() -> dict[str, Any]:
        """The active policy: the trusted copy the daemon loaded when it started."""
        return services.policy.model_dump(mode="json")

    @app.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


def create_app_from_env() -> FastAPI:
    """The real daemon: real tools, GitHub, and state under DEVSECOPS_STATE_DIR."""
    # Imported here so that tests of the routes do not need Docker or GitHub wiring.
    from devsecops.agents import (
        BuildAgent,
        DeploymentAgent,
        MonitoringAgent,
        PolicyAgent,
        SecurityAgent,
        TestAgent,
    )
    from devsecops.config import load_settings
    from devsecops.notifications.github_notifier import GitHubNotifier
    from devsecops.orchestrator.graph import PipelineDeps
    from devsecops.orchestrator.locks import DeployLock
    from devsecops.orchestrator.orchestrator import sqlite_checkpointer
    from devsecops.orchestrator.setup_validator import SetupValidator
    from devsecops.policy import RuleEngine, load_policy, pip_audit_severity
    from devsecops.tools import (
        BanditScanner,
        DockerClient,
        GitWorkspaces,
        HealthChecker,
        InjectionDetector,
        PipAuditScanner,
        PytestRunner,
        Sandbox,
    )

    settings = load_settings()
    app_repo = settings.require_app_repo()
    # Secrets are read here, at the point of use, and never stored in Settings.
    github_token = os.environ.get("GITHUB_TOKEN", "").strip()
    policy = load_policy(settings.policy_path)  # the trusted copy, never the evaluated one
    state_dir = settings.state_dir
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    docker = DockerClient()
    sandbox = Sandbox(docker)
    evidence = EvidenceStore(state_dir / "evidence.db")
    deps = PipelineDeps(
        policy=policy,
        evidence=evidence,
        notifier=GitHubNotifier(app_repo, github_token, policy),
        deploy_lock=DeployLock(state_dir / "deploy.lock"),
        build_agent=BuildAgent(docker, app_dir=settings.app_dir, image_name=settings.app_image),
        test_agent=TestAgent(PytestRunner(), app_dir=settings.app_dir),
        security_agent=SecurityAgent(
            BanditScanner(),
            PipAuditScanner(functools.partial(pip_audit_severity, policy)),
            InjectionDetector(),
            app_dir=settings.app_dir,
        ),
        # No reason writer yet: Claude is Phase 7. Decisions carry the template reason.
        policy_agent=PolicyAgent(RuleEngine(policy)),
        deployment_agent=DeploymentAgent(sandbox),
        monitoring_agent=MonitoringAgent(sandbox, HealthChecker(timeout_s=2), policy.timers),
        setup_check=SetupValidator(docker, settings.policy_path).problems,
    )
    # Each run occupies one thread until it ends or pauses (monitoring alone is 5 minutes).
    executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="pipeline-run")
    probe = HealthChecker(timeout_s=2)
    return create_app(
        ApiServices(
            policy=policy,
            evidence=evidence,
            orchestrator=Orchestrator(deps, sqlite_checkpointer(state_dir / "checkpoints.db")),
            workspaces=GitWorkspaces(
                state_dir / "workspaces", f"https://github.com/{app_repo}.git", github_token
            ),
            token=os.environ.get("CONTROL_API_TOKEN", ""),
            sandbox_probe=lambda: probe.check(sandbox.health_url),
            submit=executor.submit,
            shutdown=lambda: executor.shutdown(wait=False),
        )
    )
