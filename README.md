# Multi-Agent DevSecOps Pipeline

CMPSC 320 Software Engineering term project (Fall 2026), team **Fast API DevSecOps**.

A LangGraph orchestrator runs six agents (Build, Test, Security, Policy, Deployment, Monitoring) against a sample FastAPI app on every push or pull request to `main`. Rules in `policy.yaml` decide **ALLOW / DENY / ESCALATE**. Claude writes only the explanation. Allowed changes deploy to a Docker sandbox and roll back automatically on failed health checks. Every run is saved to an append-only SQLite evidence store.

See [`CLAUDE.md`](CLAUDE.md) for the full build plan, architecture, and requirement traceability.

> This repo stays **private** until the final demo, because it uses a self-hosted GitHub Actions runner.

## Development

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync                  # install the pipeline and dev tools
uv run pytest            # run the pipeline's tests
uv run ruff check .      # lint
cd sample_app && uv run --project .. python -m pytest --cov=app   # run the sample app's tests
```

Every pull request and every push to `main` runs these same checks on GitHub (`.github/workflows/ci.yml`): lint, the tests on Python 3.11 and 3.15, the Docker sandbox tests, and the seeded-change check. A pull request should be green before it is merged.

To see the pipeline work on this checkout without GitHub (needs Docker running):

```bash
uv run python scripts/run_local.py --fast   # build, test, scan, decide, deploy, monitor
uv run python scripts/demo_sandbox.py       # deploy a broken change and watch it roll back
```

To check the 30 seeded changes in `test_changes/` against the agents and the rules (no Docker needed, about a minute; see `test_changes/README.md`):

```bash
uv run python scripts/check_seeded_changes.py
```

Build status by phase is tracked in `CLAUDE.md` §9. Phases 1 to 3 are implemented (core domain, tool adapters and `sample_app/`, agents and the LangGraph pipeline), plus the Docker sandbox from Phase 6.
