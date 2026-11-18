"""One real request to Claude through OpenRouter, to check the Phase 7 settings (CLAUDE.md §10).

Run it on the team host, where the only OPENROUTER_API_KEY is:

    set -a; . ./.env; set +a
    uv run python scripts/try_claude.py
    DEVSECOPS_CLAUDE_EFFORT=none uv run python scripts/try_claude.py   # without output_config

It sends a made-up DENY decision (a failing test and a HIGH Bandit finding), exactly as the
daemon would, and prints the reason, the model that answered, the stop reason and the
token usage. On an error it prints the HTTP status and OpenRouter's error message, which
says what it did not accept (for example output_config). It never prints the key.

What it settles: whether the base URL, sending the key as a bearer token, the model name
and output_config={"effort": "low"} all work.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import os  # noqa: E402

import anthropic  # noqa: E402

from devsecops.config import load_settings  # noqa: E402
from devsecops.llm import ClaudeClient, openrouter_sdk  # noqa: E402
from devsecops.models import (  # noqa: E402
    AgentResult,
    AgentStatus,
    BuildResult,
    Finding,
    PolicyInput,
    SecurityReport,
    Severity,
    TestFailure,
    TestReport,
)
from devsecops.policy import RuleEngine, load_policy  # noqa: E402


def example_input() -> PolicyInput:
    return PolicyInput(
        run_id="try-claude",
        build=BuildResult(image_tag="sample_app:try", success=True),
        test=TestReport(
            passed=11,
            failed=1,
            coverage_pct=92.0,
            failures=[
                TestFailure(
                    test_name="test_list_notes_newest_first",
                    file="sample_app/tests/test_main.py",
                    line=41,
                    message="assert ['b', 'a'] == ['a', 'b']",
                )
            ],
        ),
        security=SecurityReport(
            findings=[
                Finding(
                    tool="bandit",
                    rule_id="B602",
                    file="sample_app/app/main.py",
                    line=27,
                    severity=Severity.HIGH,
                    message="subprocess call with shell=True identified, security issue.",
                )
            ]
        ),
        agent_results=[
            AgentResult(agent=name, status=AgentStatus.OK) for name in ("build", "test", "security")
        ],
        changed_files=["sample_app/app/main.py", "sample_app/tests/test_main.py"],
    )


def main() -> int:
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        print("OPENROUTER_API_KEY is not set. Run: set -a; . ./.env; set +a", file=sys.stderr)
        return 2

    policy = load_policy(load_settings().policy_path)
    results = example_input()
    decision = RuleEngine(policy).evaluate(results)
    client = ClaudeClient.from_env(policy, key)
    params = client.request_params(decision, results)
    base_url = os.environ.get("CLAUDE_BASE_URL", "").strip() or "https://openrouter.ai/api"

    print(f"base URL:      {base_url}  (key sent as a bearer token)")
    print(f"model:         {params['model']}")
    print(f"output_config: {params.get('output_config', '(not sent)')}")
    print(f"decision:      {decision.outcome.value} {list(decision.matched_rules)}")
    print()

    sdk = openrouter_sdk(base_url, key)  # the same client the daemon uses
    try:
        response = sdk.with_options(timeout=policy.llm.claude_max_extra_delay_s).messages.create(
            **params
        )
    except anthropic.APIStatusError as exc:
        print(f"FAILED: HTTP {exc.status_code}")
        print(f"error:  {exc.body if exc.body is not None else exc.message}")
        if exc.status_code == 400 and "output_config" in params:
            print("\nIf the error names output_config or effort, try DEVSECOPS_CLAUDE_EFFORT=none.")
        return 1
    except anthropic.APIConnectionError as exc:
        print(f"FAILED: {type(exc).__name__}: could not reach {base_url}")
        return 1

    text = " ".join(b.text for b in response.content if b.type == "text").strip()
    print(f"answered by:   {response.model}")
    print(f"stop_reason:   {response.stop_reason}")
    print(f"usage:         {response.usage.input_tokens} in, {response.usage.output_tokens} out")
    print(f"block types:   {[b.type for b in response.content]}")
    print()
    print("reason:")
    print(text or "(no text)")
    return 0 if text and response.stop_reason != "refusal" else 1


if __name__ == "__main__":
    sys.exit(main())
