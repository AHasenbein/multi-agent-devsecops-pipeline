"""Run the whole pipeline on this checkout with the real tools, without GitHub.

    uv run python scripts/run_local.py                 # evaluate + deploy (takes ~5 min: FR17)
    uv run python scripts/run_local.py --fast          # 1 s health checks for 10 s
    uv run python scripts/run_local.py --event pull_request   # evaluate only, no deploy
    uv run python scripts/run_local.py --workspace /path/to/app/checkout --fast

The app's directory inside the workspace, its image name and the trusted policy path come
from devsecops/config.py (DEVSECOPS_APP_DIR, DEVSECOPS_APP_IMAGE, DEVSECOPS_POLICY_PATH).
The defaults fit this repo, where the app is sample_app/.

Needs Docker running. Evidence and checkpoints go to .local-run/ (gitignored).
An escalated run pauses; the script then asks for approve or reject on the terminal.
"""

import argparse
import functools
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from devsecops.agents import (  # noqa: E402
    BuildAgent,
    DeploymentAgent,
    MonitoringAgent,
    PolicyAgent,
    SecurityAgent,
    TestAgent,
)
from devsecops.config import load_settings  # noqa: E402
from devsecops.evidence import EvidenceStore  # noqa: E402
from devsecops.models import Approval, PipelineRun, Timers, Verdict  # noqa: E402
from devsecops.notifications import NullNotifier  # noqa: E402
from devsecops.orchestrator.graph import PipelineDeps  # noqa: E402
from devsecops.orchestrator.locks import DeployLock  # noqa: E402
from devsecops.orchestrator.orchestrator import Orchestrator, sqlite_checkpointer  # noqa: E402
from devsecops.orchestrator.setup_validator import SetupValidator  # noqa: E402
from devsecops.policy import RuleEngine, load_policy, pip_audit_severity  # noqa: E402
from devsecops.tools import (  # noqa: E402
    BanditScanner,
    DockerClient,
    HealthChecker,
    InjectionDetector,
    PipAuditScanner,
    PytestRunner,
    Sandbox,
    run_command,
)


class PrintNotifier(NullNotifier):
    def set_status(self, run, state, description):
        print(f"  [status] {state}: {description}")

    def post_decision(self, run, decision, results):
        print(f"  [decision] {decision.outcome.value}  rules={list(decision.matched_rules)}")

    def request_review(self, run, decision, reviewers, deadline):
        print(f"  [review] waiting for {', '.join(reviewers)} until {deadline:%Y-%m-%d %H:%M} UTC")

    def alert(self, run, title, body):
        print(f"  [ALERT] {title}\n          {body}")


def git(workspace: Path, *args: str) -> str:
    result = run_command(["git", "-C", str(workspace), *args])
    return result.stdout.strip() if result.returncode == 0 else ""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", type=Path, default=REPO_ROOT)
    parser.add_argument("--event", choices=["push", "pull_request"], default="push")
    parser.add_argument("--fast", action="store_true", help="1 s health checks for 10 s")
    args = parser.parse_args()
    workspace = args.workspace.resolve()

    settings = load_settings()
    policy_path = settings.policy_path  # the trusted copy, never the workspace's
    policy = load_policy(policy_path)
    timers = Timers(health_interval_s=1, health_window_s=10) if args.fast else policy.timers
    state_dir = REPO_ROOT / ".local-run"
    state_dir.mkdir(exist_ok=True)

    docker = DockerClient()
    sandbox = Sandbox(docker)
    evidence = EvidenceStore(state_dir / "evidence.db")
    deps = PipelineDeps(
        policy=policy,
        evidence=evidence,
        notifier=PrintNotifier(),
        deploy_lock=DeployLock(state_dir / "deploy.lock"),
        build_agent=BuildAgent(docker, app_dir=settings.app_dir, image_name=settings.app_image),
        test_agent=TestAgent(PytestRunner(), app_dir=settings.app_dir),
        security_agent=SecurityAgent(
            BanditScanner(),
            PipAuditScanner(functools.partial(pip_audit_severity, policy)),
            InjectionDetector(),
            app_dir=settings.app_dir,
        ),
        policy_agent=PolicyAgent(RuleEngine(policy)),
        deployment_agent=DeploymentAgent(sandbox),
        monitoring_agent=MonitoringAgent(sandbox, HealthChecker(timeout_s=2), timers),
        setup_check=SetupValidator(docker, policy_path, required_env=()).problems,
    )
    orchestrator = Orchestrator(deps, sqlite_checkpointer(state_dir / "checkpoints.db"))

    run = PipelineRun(
        commit_sha=git(workspace, "rev-parse", "HEAD") or "local",
        branch=git(workspace, "rev-parse", "--abbrev-ref", "HEAD") or "local",
        author=git(workspace, "log", "-1", "--format=%an") or "local",
        event=args.event,
    )
    diff = git(workspace, "show", "--format=", "HEAD")
    changed = [
        line
        for line in git(workspace, "show", "--format=", "--name-only", "HEAD").splitlines()
        if line
    ]

    print(f"run {run.run_id}  commit {run.commit_sha[:12]}  event {run.event}")
    print(f"  changed files in HEAD: {changed or '(none)'}")
    state = orchestrator.start_run(run, workspace, diff, changed)

    if orchestrator.is_awaiting_review(run.run_id):
        print("\n" + state["decision"]["reason"])
        answer = input("\nESCALATED. approve or reject? [a/r] ").strip().lower()
        verdict = Verdict.APPROVE if answer.startswith("a") else Verdict.REJECT
        state = orchestrator.resume(
            Approval(
                run_id=run.run_id,
                commit_sha=run.commit_sha,
                reviewer=policy.reviewers[0],
                verdict=verdict,
            )
        )

    print(f"\nfinal status: {state['status']}")
    if state.get("decision"):
        print(state["decision"]["reason"])
    print("\nrun record:")
    for record in evidence.get_run(run.run_id):
        payload = json.loads(record.payload_json)
        detail = payload.get("outcome") or payload.get("status") or payload.get("ok", "")
        print(f"  {record.seq:>4}  {record.event_type.value:<16} {detail}")
    chain = evidence.verify_chain()
    print(f"evidence chain: ok={chain.ok} ({chain.records_checked} records)")
    if state["status"] == "DEPLOYED":
        print(f"sandbox: {sandbox.health_url.replace('/health', '/docs')}")


if __name__ == "__main__":
    main()
