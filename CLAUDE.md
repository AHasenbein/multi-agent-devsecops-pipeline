# Multi-Agent DevSecOps Pipeline — Build Plan for Agents

CMPSC 320 (Fall 2026) term project, team "Fast API DevSecOps" (A. Hasenbein, V. Dadi).
This file is the build guide for any agent working in this repo. Read it fully before writing code.

## 0. Sources of truth

The design comes from three PDFs in `docs/` (kept local only, gitignored because they contain student IDs):

| Doc | Status | Use it for |
|---|---|---|
| `docs/requirements-v1.0.pdf` (v1.0, 10/21) | Final | **What** to build: FR1–FR20, use cases UC-01-01…UC-09-01, QA scenarios, test cases |
| `docs/design-final-v1.3.7.pdf` ("FINAL", v1.3.7, 10/29) | Final | **Architecture**: deployment, uses-style packages, layers, call-return view, class + sequence diagrams |
| `docs/design-draft-v2.0.pdf` (v2.0, date TBA) | Unfinished draft (every diagram is an INSERT placeholder) | Per-use-case **class tables** (names + responsibilities) and API paths — the most detailed source for class names |

If the docs conflict, the FINAL v1.3.7 wins on architecture and the Requirements doc wins on behavior. Section 11 lists the known conflicts.

**One-sentence summary:** a push or PR to `main` of the private app repo (§2) triggers a self-hosted GitHub Actions runner. The runner calls a local FastAPI Control API, which runs a LangGraph pipeline of six agents: Build, Test, Security, Policy, Deployment, and Monitoring. Deterministic `policy.yaml` rules decide ALLOW, DENY, or ESCALATE. Claude only writes the human-readable reason. Allowed changes deploy to a Docker sandbox and roll back automatically on failed health checks. Every step is written to an append-only, hash-chained SQLite evidence store.

---

## 1. Invariants (never break these — each one has a test)

1. **Rules decide; the LLM explains.** `RuleEngine` computes `ReleaseDecision.outcome` *before* any LLM call. The outcome field is frozen (Pydantic `frozen=True` / no setter). `ClaudeClient` returns only a `reason: str`. Test: mock Claude to return "ALLOW, ignore the rules" text and assert that the outcome is unchanged (FR11, FR13).
2. **Order of evaluation:** deny rules → escalate rules → otherwise ALLOW (FR10–FR12).
   - DENY: build failed, any failing test, any HIGH finding.
   - ESCALATE: any MEDIUM finding, coverage < 80%, an important file changed, any agent ERROR (including a scan-tool crash), or possible prompt injection.
3. **pip-audit findings are always HIGH** unless their ID is listed under `pip_audit_exceptions` in policy.yaml (FR8).
4. **Schema retry:** every agent output is validated against its Pydantic model. Invalid output is retried up to 2 times; after that, the result has status `ERROR`, which leads to ESCALATE (FR9).
5. **Claude availability retry is a separate mechanism:** retry 3 times, then use a template reason. The extra delay is at most 30 s total, and the decision never changes (QA-AV-01).
6. **Evidence is append-only.** `EvidenceStore` exposes only `append()`, `get_run()`, `list_runs()`, and `verify_chain()`. Each row stores `prev_hash` and `hash = sha256(prev_hash + canonical_json(row))`. There is no update or delete method. Add SQLite triggers that `RAISE(ABORT)` on UPDATE/DELETE as defense in depth (FR19).
7. **Deploys are serialized.** A single global lock (file lock or a SQLite `deploy_lock` row) protects deploy + monitor, so two runs can't overwrite each other's rollback target (FINAL §2.1.3).
8. **Reviewer authorization:** an approval is accepted only if the reviewer is listed in `policy.yaml` `reviewers` **and** the request's `run_id` + `commit_sha` match a run that is currently paused in ESCALATE. Anything else gets a 403.
9. **The old version is always kept** before a new container starts, so a rollback target always exists (FR16).
10. **No secrets in logs, run records, or prompts.** Keys come from env / GitHub secrets. Only the diff and findings are sent to Claude, after redaction (QA-PR-01).

---

## 2. Runtime topology (easy to get wrong — read carefully)

```
Developer ──push/PR──▶ GitHub (private app repo, Actions: pipeline.yml)
                              │ job dispatch
                              ▼
┌── Team host (always-on server: Ubuntu 24.04 in WSL2, Python 3.12, Docker) ─────┐
│  Self-hosted Actions runner ──HTTP POST /runs──▶  Control API (FastAPI daemon)  │
│                                                   │  (pinned install of this    │
│                                                   ▼   public repo + policy.yaml)│
│                                  LangGraph orchestrator (+ SQLite checkpointer) │
│                                     │ agents ──▶ tools adapters ──▶ docker/pytest/bandit/pip-audit
│                                     │ llm ──HTTPS──▶ Claude API                 │
│                                     │ evidence ──▶ SQLite (evidence.db)         │
│                                     │ notifications ──HTTPS──▶ GitHub REST      │
│                                     ▼                                           │
│                       Docker sandbox: sample_app container on :8080             │
│                       (+ previous container kept stopped for rollback)          │
└─────────────────────────────────────────────────────────────────────────────────┘
```

- **The team host is the always-on server, never a developer laptop** (decided 11/15). Docker, the sandbox, the self-hosted runner and the Control API all live in one Ubuntu 24.04 WSL2 distro named `devsecops` on that server, set up by `scripts/provision_host.sh`. Laptops only edit code and push.
  - **Do not start Docker or the sandbox on a laptop.** `scripts/run_local.py`, `scripts/demo_sandbox.py` and `pytest -m docker` run on the host over SSH, from the checkout in the `devsecops` user's home directory. Everything else (`pytest -m "not docker"`, ruff, `scripts/check_seeded_changes.py`) needs no Docker and runs anywhere. CI runs the Docker tests on GitHub's machines.
  - **The server's address, login and hostname never go in this repo**, which is public. Keep them in the gitignored `.env` or your SSH config.
  - The distro stays up through `instanceIdleTimeout=-1` in the server's `.wslconfig` and a logon task that starts it. Docker starts with it through systemd.
- **The Control API is a long-running daemon on the host** (systemd/launchd or `uvicorn` in tmux). It is **not** started per Actions job. Escalated runs can stay paused for up to 24 h, so pipeline state must persist across process restarts. Use the LangGraph SQLite checkpointer plus an `approvals` table with a `deadline_at` column.
- **The GitHub workflow is a thin trigger.** It calls `POST /runs` with the commit info, then polls `GET /runs/{id}` until a decision exists and exits non-zero on DENY. Deploy + monitoring (5 min) continue asynchronously after the decision is posted.
- **There are two different FastAPI apps.** Keep them in separate directories with separate dependencies.
  - `devsecops/` — the pipeline's Control API (port e.g. 8000).
  - `sample_app/` — the app *being evaluated and deployed* (container port 8080, exposes `GET /health`).
- **There are two repos** (decided 11/15; the design PDFs assume one, so the final report must say why we split). A self-hosted runner on a public repo would let a stranger's pull request run code on the team host.
  - **This repo is public.** It holds the pipeline code, `policy.yaml`, the tests, the 30 seeded patches, and `sample_app/` as the example app and test fixture. Its only workflow is `ci.yml`, which runs on GitHub's machines. **Never add a workflow with `runs-on: self-hosted` to this repo.**
  - **The app repo is private**, with write access for the two of us only (and the grader if needed). It holds the copy of the app that is pushed to, evaluated and deployed, plus `.github/workflows/pipeline.yml`. It is the only repo the self-hosted runner is registered to. It keeps this repo's layout: `sample_app/`, `.github/workflows/`, and a top-level `policy.yaml` that the pipeline never reads (E09 changes it to show that).
  - **The host runs a pinned install of this repo** (a tag or commit, never "latest main") and reads `policy.yaml` from that install. Moving the pin is a deliberate step, because whatever commit is pinned runs on our machine.
  - **Nothing in `devsecops/` may assume the app sits next to the pipeline.** The app repo's name, the app's directory inside a checkout, the image name and the policy path come from `devsecops/config.py` (`DEVSECOPS_APP_REPO`, `DEVSECOPS_APP_DIR`, `DEVSECOPS_APP_IMAGE`, `DEVSECOPS_POLICY_PATH`). The defaults fit this repo's `sample_app/`, so tests and local runs need no setup.

---

## 3. Repo layout

```
multi-agent-devsecops-pipeline/
├── CLAUDE.md                     # this file
├── pyproject.toml                # pipeline deps: fastapi, uvicorn, langgraph, langgraph-checkpoint-sqlite,
│                                 #   pydantic, pyyaml, anthropic, httpx, bandit, pip-audit, pytest, pytest-cov, docker
├── policy.yaml                   # trusted copy = the one in the host's pinned install; see §6 and §11
├── .github/workflows/ci.yml      # lint + tests on GitHub's machines. pipeline.yml lives in the private app repo (§2)
├── devsecops/
│   ├── api/                      # FR1, FR14, FR20 — RunsController, ApprovalController, policies, health
│   │   ├── main.py               # FastAPI app factory
│   │   ├── runs.py
│   │   ├── approvals.py
│   │   └── schemas.py            # request/response models (RunView, RunSummary)
│   ├── orchestrator/             # FR2, FR3, FR9, FR15
│   │   ├── graph.py              # StateGraph build + conditional edges
│   │   ├── state.py              # PipelineState
│   │   ├── orchestrator.py       # Orchestrator.start_run(commit), resume(run_id, verdict)
│   │   ├── approval_service.py   # notify, record verdict, timeout sweeper
│   │   ├── setup_validator.py    # checks docker, secrets, policy.yaml
│   │   └── locks.py              # deploy lock
│   ├── agents/                   # FR4–FR18
│   │   ├── base.py               # abstract Agent: execute(state) -> AgentResult (schema retry ×2)
│   │   ├── build.py  test.py  security.py  policy.py  deployment.py  monitoring.py
│   ├── tools/                    # FR4, FR6, FR7, FR17 — one adapter per external tool
│   │   ├── docker_client.py      # build, run, stop, start, rename, rollback
│   │   ├── pytest_runner.py
│   │   ├── bandit_scanner.py
│   │   ├── pip_audit_scanner.py
│   │   ├── injection_detector.py
│   │   └── health_checker.py
│   ├── llm/                      # FR9, FR13
│   │   ├── claude_client.py      # write_reason(); 3 retries -> template fallback
│   │   ├── prompts.py
│   │   └── redact.py
│   ├── policy/                   # FR8, FR10–FR12
│   │   ├── loader.py             # PolicySet from YAML (validated w/ Pydantic)
│   │   └── rule_engine.py
│   ├── evidence/                 # FR19
│   │   └── store.py              # EvidenceStore (append-only, hash chain)
│   ├── notifications/            # FR3, FR5, FR14, FR18
│   │   └── github_notifier.py    # commit status, PR comment, alerts
│   ├── models.py                 # shared domain models (§4)
│   └── config.py                 # host settings from env: app repo, app dir, image name, policy path (§2)
├── sample_app/                   # the example FastAPI app + test fixture; the private app repo holds the deployed copy
│   ├── app/main.py               # includes GET /health
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
├── test_changes/                 # the 30 seeded changes as patch files + expected outcome manifest
│   ├── manifest.yaml             # id, category, expected decision and matched rules
│   ├── README.md                 # how to run the offline check and how to add a change
│   └── *.patch
├── scripts/
│   ├── check_seeded_changes.py   # offline: applies each patch to a temp copy, runs the tools + RuleEngine
│   ├── run_seeded_changes.py     # applies each patch on a branch of the private app repo, pushes, collects decisions
│   ├── provision_host.sh         # one-time setup of the team host: Docker Engine, git, uv, the devsecops user (§2)
│   └── install_daemon.sh
└── tests/
    ├── unit/                     # rule engine, evidence chain, each agent with fake tools
    ├── integration/              # graph paths ALLOW/DENY/ESCALATE with fakes
    └── system/                   # TS-04-01, TS-06-01, TS-08-01, QA measures
```

Dependency direction (no cycles): `api → orchestrator → agents → {tools, llm, policy}`. `orchestrator → {evidence, notifications}`. Agents never call Docker or Claude directly. They go through `tools/` and `llm/` so they can be mocked.

Layers (FINAL v1.3.7, Fig. 6). Each layer calls only the layer below it:

| Layer | Contents |
|---|---|
| Interface | FastAPI routes, GitHub status/comments |
| Application | LangGraph, agents, policy rules, review handling |
| Infrastructure | tool adapters, Claude client, evidence store, notifications |
| Resources | Docker, SQLite, policy.yaml, GitHub, Claude API |

---

## 4. Domain models (`devsecops/models.py`, Pydantic v2)

Names are taken from the v2.0 class tables and the FINAL class diagram. **Naming decisions:** use `DockerClient` (not `DockerAdapter`). `RuleEngine` evaluates, and `PolicySet` is data only (FINAL's `PolicySet.evaluate()` is implemented as `RuleEngine(policy_set).evaluate(results)`).

```python
class Outcome(StrEnum): ALLOW, DENY, ESCALATE
class AgentStatus(StrEnum): OK, FAILED, ERROR
class Severity(StrEnum): LOW, MEDIUM, HIGH
class Verdict(StrEnum): APPROVE, REJECT, TIMEOUT
class RunStatus(StrEnum): PENDING, RUNNING, AWAITING_REVIEW, DENIED, DEPLOYING, MONITORING,
                          DEPLOYED, ROLLED_BACK, ROLLBACK_FAILED, ERROR
class DeployStatus(StrEnum): STARTED, FAILED_TO_START, HEALTHY, ROLLED_BACK, ROLLBACK_FAILED

PipelineRun:   run_id (uuid), commit_sha, branch, author, event ("push"|"pull_request"), pr_number?, started_at, status
AgentResult:   agent, status: AgentStatus, summary: str, data: dict, errors: list[str]
BuildResult:   image_tag, success, errors: list[str], log_tail
TestFailure:   test_name, file, line, message
TestReport:    passed, failed, skipped, coverage_pct, failures: list[TestFailure]
Finding:       tool ("bandit"|"pip-audit"|"injection"), rule_id, file?, line?, package?, severity, message
SecurityReport: findings: list[Finding], tool_errors: list[str], injection_suspected: bool
Rule:          id, kind ("deny"|"escalate"), description
PolicySet:     version, thresholds, pip_audit_exceptions, important_files, reviewers, timers, rules
ReleaseDecision (frozen): run_id, outcome, matched_rules: list[str], reason: str, reason_source ("claude"|"template")
Approval:      run_id, commit_sha, reviewer, verdict: Verdict, reviewed_at
Container:     id, name, image_tag, status
DeploymentRecord: run_id, image_tag, previous_image_tag, previous_container, status: DeployStatus
HealthCheck:   at, ok, status_code?, latency_ms?, error?
RunRecord (evidence row): seq, run_id, event_type, payload_json, created_at, prev_hash, hash
SandboxStatus: live: bool, last_health: HealthCheck?, last_deployment: DeploymentRecord?
```

`ReleaseDecision.is_deployable(approval)` returns True only for ALLOW, or for ESCALATE with an APPROVE verdict.

Evidence `event_type` values: `RUN_STARTED, SETUP_FAILED, BUILD_RESULT, TEST_REPORT, SECURITY_REPORT, AGENT_ERROR, DECISION, REVIEW_REQUESTED, REVIEW_VERDICT, DEPLOY_RESULT, HEALTH_CHECK, ROLLBACK, ROLLBACK_FAILED, RUN_FINISHED`.

---

## 5. LangGraph graph (`orchestrator/graph.py`)

Architecture style: **pipe-and-filter over a shared `PipelineState`**, with call-return control from the orchestrator.

```
START → setup_check ─(fail)→ finish_error
              │ok
              ▼
           build ─(build failed)→ policy        # build failure goes straight to the DENY rule (FR5)
              │ok
              ▼
      test ∥ security   (may run in parallel; both write into state)
              ▼
           policy  (RuleEngine → outcome; then Claude reason; save DECISION; post to GitHub)
       ┌──────┼──────────────┐
     DENY   ALLOW         ESCALATE
       │      │              ▼
       │      │       human_review  ← interrupt(); resumed by POST /runs/approval or by the timeout sweeper
       │      │        APPROVE│  REJECT/TIMEOUT → finish_denied
       │      ▼◀──────────────┘
       │   deploy (acquire deploy lock) ─(failed to start)→ restore old → finish
       │      ▼
       │   monitor (10 s × 5 min; 3 consecutive fails → rollback; rollback fail → alert) → release lock
       ▼      ▼
     finish (RUN_FINISHED record, final commit status)
```

- Use `StateGraph(PipelineState)` with conditional edges after `build` and `policy`.
- Compile with a **SQLite checkpointer** (`langgraph-checkpoint-sqlite`) and `thread_id = run_id`, so a paused review survives a restart.
- `human_review` uses LangGraph `interrupt()`. The approval endpoint resumes it with `Command(resume=verdict)`.
- **Timeout sweeper:** a background task in the Control API runs every 30–60 s. It finds approvals with `deadline_at < now` and resumes those runs with `TIMEOUT`. Because it reads from the DB, it works after a restart (FR15).
- Run each graph invocation in a background task or thread so that `POST /runs` returns immediately with a `run_id`.
- Concurrency (QA-SC-01): runs are isolated by `run_id`. Only deploy/monitor is serialized via the lock. Use SQLite WAL mode.

---

## 6. `policy.yaml` schema

```yaml
version: 1
thresholds:
  min_coverage_pct: 80
pip_audit_exceptions:            # IDs downgraded from HIGH; must include justification
  - id: GHSA-xxxx-xxxx-xxxx
    severity: MEDIUM
    reason: "not reachable in sample app"
important_files:                 # paths in the private app repo; changes here → ESCALATE
  - policy.yaml                  # the app repo's copy is never read, but changing it is suspicious
  - .github/workflows/**
  - sample_app/Dockerfile
  - sample_app/requirements.txt
reviewers:                       # GitHub logins allowed to approve
  - <github-login>
timers:
  review_timeout_s: 86400        # 24 h (tests: 120)
  review_notify_sla_s: 60
  health_interval_s: 10
  health_window_s: 300
  health_fail_threshold: 3
  rollback_sla_s: 120
llm:
  claude_retries: 3
  claude_max_extra_delay_s: 30
  schema_retries: 2
```

The loader validates this file with Pydantic. An invalid policy fails `SetupValidator`, which notifies the developer (FR3).

---

## 7. Control API endpoints (`devsecops/api/`)

| Method & path | Purpose | FR |
|---|---|---|
| `POST /runs` | body `{commit_sha, branch, author, event, pr_number?}` → `202 {run_id}`; runs `SetupValidator` first | FR1–FR3 |
| `GET /runs` | list `RunSummary` | FR20 |
| `GET /runs/{id}` | `RunView`: status, decision, findings, evidence entries, `verify_chain()` result, `SandboxStatus` (live, or last recorded if the sandbox is down) | FR19, FR20, UC-09 |
| `POST /runs/approval` | body `{run_id, commit_sha, reviewer, verdict}` → 200, or 403 if the reviewer isn't listed or run/commit don't match a paused run | FR14 |
| `GET /policies` | active PolicySet as JSON | — |
| `GET /health` | Control API health | — |

Protect the API with a shared bearer token stored as a GitHub secret + host env var, and bind it to localhost unless reviewers need remote access.

---

## 8. Requirements traceability (FR → module → test)

| FR | Requirement (short) | Module | Test |
|---|---|---|---|
| FR1 | push/PR to main starts run | `.github/workflows/pipeline.yml` (in the private app repo), `api/runs.py` | system: push triggers run |
| FR2 | run record with run id, commit, author, start | `orchestrator`, `evidence` | unit: RUN_STARTED fields |
| FR3 | notify if Actions/orchestrator misconfigured | `setup_validator`, `notifications` | unit: missing docker/secret/policy → error status |
| FR4 | build Docker image, save errors | `agents/build`, `tools/docker_client` | unit w/ fake docker |
| FR5 | build fail → stop, DENY, notify | `graph` edge, `rule_engine` | integration: build-fail path |
| FR6 | pytest results + coverage saved | `agents/test`, `tools/pytest_runner` | unit: parse junit/coverage json |
| FR7 | Bandit + pip-audit findings with severity | `agents/security`, scanners | unit: parse fixture outputs |
| FR8 | pip-audit → HIGH unless excepted | `pip_audit_scanner`, `policy` | unit |
| FR9 | JSON schema, 2 retries → ERROR | `agents/base.py` | unit: bad output ×3 → ERROR → ESCALATE |
| FR10 | one decision from policy.yaml | `rule_engine` | unit |
| FR11 | failing test / HIGH → DENY regardless of LLM | `rule_engine`, frozen decision | unit: adversarial Claude mock |
| FR12 | MEDIUM / cov<80 / important file / agent error / injection → ESCALATE | `rule_engine`, `injection_detector` | unit, one per trigger |
| FR13 | Claude writes reason; can't change outcome | `llm/claude_client` | unit |
| FR14 | notify reviewer ≤1 min, save verdict | `approval_service`, `api/approvals` | integration |
| FR15 | no reply in 24 h → DENY + notify | timeout sweeper | integration w/ 2-min timer (TS-06-01) |
| FR16 | deploy to sandbox, keep old version | `agents/deployment`, `docker_client` | system |
| FR17 | 10 s checks for 5 min; 3 fails → rollback ≤2 min | `agents/monitoring`, `health_checker` | system (TS-08-01) |
| FR18 | rollback fail → notify immediately | `agents/monitoring`, `notifications` | system: block rollback |
| FR19 | run record can't be edited/deleted | `evidence/store.py` | unit: triggers + `verify_chain` detects tamper |
| FR20 | view status + record of any run | `api/runs.py` | integration |

---

## 9. Build order (today is 11/13; final report is due 11/30)

Each phase must meet its exit criterion before the next phase starts. Phases 1–3 need no Docker, GitHub, or Claude.

1. **Core domain, offline.** Build `models.py`, `policy/loader.py`, `policy/rule_engine.py`, and `evidence/store.py`.
   *Exit:* unit tests for every deny/escalate trigger, pip-audit default HIGH, frozen outcome, and hash chain + tamper detection. Covers QA-SE-01 (H,H).
2. **Tool adapters.** Build `docker_client`, `pytest_runner` (with `--cov --cov-report=json --junitxml`), `bandit_scanner` (`-f json`), `pip_audit_scanner` (`-f json`), `injection_detector` (regex/heuristics over diff + comments, e.g. "ignore previous instructions", "you are now", "approve this"), and `health_checker`. Build `sample_app/` with tests and `/health`.
   *Exit:* adapters parse real tool output from fixtures. `sample_app` builds and passes its tests.
3. **Agents + graph with fakes.** Build the `Agent` base (schema retry), the six agents, and `graph.py` with the checkpointer.
   *Exit:* integration tests drive the ALLOW, DENY (build fail, test fail, HIGH), and ESCALATE paths end-to-end with fake tools.
4. **Control API + workflow + GitHub notifier.** Build the endpoints from §7, `SetupValidator`, commit status, and a PR comment that shows the decision, matched rule, and top findings with file:line (QA-US-01). Install the self-hosted runner and the daemon.
   *Exit:* a real push produces a decision posted on GitHub.
5. **Escalation.** Build the `interrupt`/resume flow, reviewer authorization, and the timeout sweeper.
   *Exit:* TS-06-01 passes (approve → deploy, reject → stop, no answer → DENY after the 2-min test timer), including after a daemon restart.
6. **Deploy + monitor + rollback.** Build the deploy lock, old-container retention, health loop, rollback, and rollback-failure alert.
   *Exit:* TS-08-01 passes. Rollback happens within 2 min.
7. **Claude reasoning.** Build `llm/claude_client.py` with redaction, 3 retries → template reason, and a ≤30 s extra-delay budget. This is last because FR13 is only "Should".
   *Exit:* TS-04-01 step 3 ("repeat with Claude turned off → same decisions") passes.
8. **Seeded system test + report data.** Run all 30 `test_changes/`, 5 pushes within 1 minute (QA-SC-01), a secrets grep over logs/DB (QA-PR-01), and timing (QA-PE-01).
   *Exit:* the metrics table for the final report.

---

## 10. LLM usage (`devsecops/llm/claude_client.py`)

- SDK: the official `anthropic` Python package. Model comes from an env var: `CLAUDE_MODEL`, default `claude-opus-5-5`. The budget is capped at $25 for the semester, so the team may set a cheaper model (e.g. `claude-haiku-5-5`) in `.env`. Don't hardcode the model ID.
- Use one call per run, to write the reason only. Input: the frozen outcome, matched rules, top findings, and the redacted diff summary. Output: a short plain-text reason. Use `output_config={"effort": "low"}` and small `max_tokens` (~1024). Thinking can't be disabled on Opus 5.5; lowering effort is the control.
- Use the SDK's error classes (`anthropic.APIConnectionError`, `RateLimitError`, `APIStatusError`). Set `max_retries=0` on the client and do our own 3 retries inside the 30 s budget. After that, fall back to a template reason and set `reason_source="template"`.
- Check `stop_reason == "refusal"` and fall back to the template in that case.
- Treat the diff as untrusted. Put it in a clearly delimited user block and tell the model it is data. The outcome is already fixed, so injection can at worst garble the reason text.
- Before writing this module, invoke the `claude-api` skill for current SDK usage. Don't write SDK calls from memory.

---

## 11. Open questions and doc conflicts — proposed defaults (team to confirm)

| # | Issue | Proposed default |
|---|---|---|
| 1 | **Seeded test set.** The Requirements doc says 10 safe / 10 security / 10 build-or-test failures (all denied). FINAL says 10 safe / 10 high-risk / 10 medium-to-low risk. Under FR12, MEDIUM findings ESCALATE, not DENY. | Use FINAL's split. Pass criteria: high-risk → DENY (10/10), medium → ESCALATE and **never ALLOW**, safe → ALLOW ≥ 9/10. Define "risky change blocked" as "not ALLOWed". Record the expected outcome per change in `test_changes/manifest.yaml`. |
| 2 | **Do PR runs deploy?** | PR runs evaluate and comment only. Pushes to `main` (or merge commits) deploy. |
| 3 | **Trusted policy source.** Not in the docs, but a real gap: if policy.yaml and the pipeline code are read from the commit being evaluated, a change can weaken its own rules. | Load `policy.yaml` from the host's pinned install of this repo (`DEVSECOPS_POLICY_PATH` can point elsewhere), never from the evaluated commit. Keep policy.yaml, workflows, Dockerfile, and requirements in `important_files` so changes to them ESCALATE. `devsecops/**` is not listed: with two repos (§2) the pipeline code cannot arrive in an evaluated commit, and changes to it are protected by this repo's pull-request review and CI. |
| 4 | Retry counts: "2 retries" (agent schema) vs "3 retries" (Claude). | These are two separate mechanisms (§1 items 4–5). Both are configurable. |
| 5 | Layer count: v2.0 has 5 layers, FINAL has 4. | Use FINAL's 4 layers (§3). |
| 6 | `DockerClient` vs `DockerAdapter`; `RuleEngine` vs `PolicySet.evaluate()`. | `DockerClient`; `RuleEngine` evaluates, `PolicySet` holds data. |
| 7 | How the reviewer is notified within 1 min. | A GitHub PR comment / commit status mentioning the reviewers, with a link to the approval endpoint. A small CLI (`scripts/approve.py`) wraps `POST /runs/approval`. |
| 8 | Append-only on SQLite can't stop a host admin. | Application-level append-only + triggers + hash chain + restricted file permissions (as FINAL states). Document this limitation in the report. |
| 9 | What gets sent to Claude. | Only the diff and findings, after `redact.py` strips anything that looks like a key/token/password. Never send env values or full files. |
| 10 | Self-hosted runner vs. public repo. | **Decided 11/15: two repos** (§2). This repo is public; the app, `pipeline.yml` and the runner belong to a private app repo. |

---

## 12. Tests to implement (from the Requirements doc §3)

- **TS-04-01 Risky change is denied:** push a failing-test change → DENY with the test name shown. Push a HIGH-finding change → DENY, nothing deployed. Repeat with Claude off → same decisions.
- **TS-06-01 Reviewer decision:** escalated run, review timeout set to 120 s. Approve → deploys. Reject → stops and is saved. No answer → DENY after the timeout.
- **TS-08-01 Failed deploy rolls back:** deploy a broken `/health` → 3 failed checks in about 30 s → old version back within 2 min. Block the rollback → developer notified.
- **QA measures:** decision ≤ 10 min (QA-PE-01); 5 pushes in 1 min → 5 correct records, each ≤ 15 min (QA-SC-01); no API key in any log/record (QA-PR-01); Claude down → all 5 runs still get decisions with ≤ 30 s extra delay (QA-AV-01); 4 of 5 test users can name the deny cause from the PR comment within 2 min (QA-US-01, manual).

All timers come from `policy.yaml` `timers` / `config.py` so tests can shorten them.

---

## 13. Working rules for agents

- Python 3.11+, type hints, Pydantic v2, `ruff` + `pytest`. Keep the agents thin and put logic in `policy/` and `tools/`.
- Every new rule or agent behavior gets a unit test that names the FR it covers.
- Never commit `.env`, API keys, or `evidence.db`. Use GitHub secrets in the private app repo for `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, and `CONTROL_API_TOKEN`. This public repo holds no secrets.
- Each change goes on a branch and is reviewed by the other teammate (process constraint from the Requirements doc).
- Out of scope: production deploys, non-Python languages, container image scanning, Kubernetes, and real user data.
