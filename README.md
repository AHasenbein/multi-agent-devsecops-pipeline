# Multi-Agent DevSecOps Pipeline

CMPSC 320 Software Engineering term project (Fall 2026), team **Fast API DevSecOps**.

A LangGraph orchestrator runs six agents (Build, Test, Security, Policy, Deployment, Monitoring) against a FastAPI app on every push or pull request to that app's `main`. Rules in `policy.yaml` decide **ALLOW / DENY / ESCALATE**. Claude writes only the explanation. Allowed changes deploy to a Docker sandbox and roll back automatically on failed health checks. Every run is saved to an append-only SQLite evidence store.

See [`CLAUDE.md`](CLAUDE.md) for the full build plan, architecture, and requirement traceability.

## Two repos

The project is split across two repos so that a self-hosted GitHub Actions runner never runs a stranger's code:

| Repo | Visibility | Holds |
|---|---|---|
| this one | public | the pipeline's code, `policy.yaml`, the tests, and `sample_app/` as the example app and test fixture |
| the app repo | **private**, write access for the team only | the copy of the app that is pushed to, evaluated and deployed, plus `.github/workflows/pipeline.yml` |

The self-hosted runner is registered to the private app repo only. Pull requests to this repo run `ci.yml` on GitHub's own machines and never reach the team host. The host runs the Control API from a pinned commit of this repo and reads `policy.yaml` from that install, never from the commit being evaluated.

The runner is installed on the team host, an always-on server, by `scripts/install_runner.sh`. It runs there as a systemd service next to Docker and the Control API, under the name `team-host` with the label `devsecops-host`. The server's address and login are kept out of this repo (`CLAUDE.md` §2).

The app repo's name and layout reach the pipeline through environment variables (`devsecops/config.py`): `DEVSECOPS_APP_REPO`, `DEVSECOPS_APP_DIR`, `DEVSECOPS_APP_IMAGE` and `DEVSECOPS_POLICY_PATH`. The defaults fit this repo's `sample_app/`, so the commands below need none of them.

## Development

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync                  # install the pipeline and dev tools
uv run pytest            # run the pipeline's tests
uv run ruff check .      # lint
cd sample_app && uv run --project .. python -m pytest --cov=app   # run the sample app's tests
```

Every pull request and every push to `main` runs these same checks on GitHub (`.github/workflows/ci.yml`): lint, the tests on Python 3.11 and 3.15, the Docker sandbox tests, and the seeded-change check. A pull request should be green before it is merged.

To see the pipeline work on a checkout without GitHub. These two need Docker, so run them on the team host over SSH, not on a laptop (`CLAUDE.md` §2):

```bash
uv run python scripts/run_local.py --fast   # build, test, scan, decide, deploy, monitor
uv run python scripts/demo_sandbox.py       # deploy a broken change and watch it roll back
```

To start the Control API, the daemon that the app repo's workflow calls (`CLAUDE.md` §7). It runs on the team host, with `DEVSECOPS_APP_REPO`, `CONTROL_API_TOKEN` and `GITHUB_TOKEN` in its environment:

```bash
uv run uvicorn devsecops.api.main:create_app_from_env --factory --host 127.0.0.1 --port 8000
```

Every route except `GET /health` needs `Authorization: Bearer <CONTROL_API_TOKEN>`. Evidence, checkpoints and per-run checkouts go to `DEVSECOPS_STATE_DIR` (default `~/.devsecops`).

To check the 30 seeded changes in `test_changes/` against the agents and the rules (no Docker needed, about a minute; see `test_changes/README.md`):

```bash
uv run python scripts/check_seeded_changes.py
```

Build status by phase is tracked in `CLAUDE.md` §9. Phases 1 to 3 are implemented (core domain, tool adapters and `sample_app/`, agents and the LangGraph pipeline), plus the Docker sandbox from Phase 6. From Phase 4 the Control API and the GitHub notifier are implemented; `pipeline.yml` in the app repo and the daemon's install script are not yet, so no real push has gone through the pipeline.
