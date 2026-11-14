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

Build status by phase is tracked in `CLAUDE.md` §9. Phases 1 (core domain) and 2 (tool adapters and `sample_app/`) are implemented.
