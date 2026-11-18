"""Claude writes the reason text for a decision the rules already made (FR13, QA-AV-01).

Claude models are called through OpenRouter's Anthropic-compatible Messages endpoint with
the official ``anthropic`` SDK (CLAUDE.md §10). ``write_reason`` never raises and never
changes the decision: whenever Claude cannot help in time it returns None, and the
PolicyAgent keeps the template reason.

Retries are ours, not the SDK's (``max_retries=0``): up to ``retries`` more attempts on
connection errors, timeouts, 429 and 5xx, all inside ``budget_s`` seconds counted from the
first call. Any other error (401 bad key, 402 out of credits, 400) gives up at once.
"""

import logging
import os
import time
from collections.abc import Callable, Mapping
from typing import Any

import anthropic

from devsecops.llm.prompts import SYSTEM, build_user_message
from devsecops.models import PolicyInput, PolicySet, ReleaseDecision

log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://openrouter.ai/api"  # the SDK adds /v1/messages
DEFAULT_MODEL = "anthropic/claude-sonnet-5.5"
DEFAULT_EFFORT = "low"
MAX_TOKENS = 1024
MAX_REASON_CHARS = 600
# An attempt with less time than this left is not worth starting.
MIN_ATTEMPT_S = 1.0
BACKOFF_S = (1.0, 2.0, 4.0)

ReasonWriter = Callable[[ReleaseDecision, PolicyInput], str | None]


def openrouter_sdk(base_url: str, api_key: str) -> anthropic.Anthropic:
    """The SDK client for OpenRouter. The key goes as a bearer token (``auth_token``), as
    OpenRouter expects. Passing it explicitly also stops the SDK from reading
    ANTHROPIC_API_KEY from the environment, so no Anthropic key is ever sent to OpenRouter.
    Retries are ours (``max_retries=0``)."""
    return anthropic.Anthropic(base_url=base_url, auth_token=api_key.strip(), max_retries=0)


class ClaudeClient:
    def __init__(
        self,
        api_key: str,
        *,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        effort: str | None = DEFAULT_EFFORT,
        retries: int = 3,
        budget_s: float = 30.0,
        max_tokens: int = MAX_TOKENS,
        rule_descriptions: Mapping[str, str] | None = None,
        client: Any = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not api_key.strip() and client is None:
            raise ValueError("an OpenRouter API key is required")
        self._client = client or openrouter_sdk(base_url, api_key)
        self.model = model
        self._effort = effort or None
        self._retries = retries
        self._budget_s = budget_s
        self._max_tokens = max_tokens
        self._rule_descriptions = dict(rule_descriptions or {})
        self._clock = clock
        self._sleep = sleep

    @classmethod
    def from_env(cls, policy: PolicySet, api_key: str, **kwargs: Any) -> "ClaudeClient":
        """The daemon's client: model, base URL and effort from the environment, retry
        count and time budget from policy.yaml."""
        effort = os.environ.get("DEVSECOPS_CLAUDE_EFFORT", DEFAULT_EFFORT).strip()
        return cls(
            api_key,
            model=os.environ.get("CLAUDE_MODEL", "").strip() or DEFAULT_MODEL,
            base_url=os.environ.get("CLAUDE_BASE_URL", "").strip() or DEFAULT_BASE_URL,
            effort=None if effort.lower() in ("", "none", "off") else effort,
            retries=policy.llm.claude_retries,
            budget_s=policy.llm.claude_max_extra_delay_s,
            rule_descriptions={rule.id: rule.description for rule in policy.rules},
            **kwargs,
        )

    def request_params(self, decision: ReleaseDecision, results: PolicyInput) -> dict[str, Any]:
        """The arguments for ``messages.create``. Holds no secret: the key is on the client."""
        params: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self._max_tokens,
            "system": SYSTEM,
            "messages": [
                {
                    "role": "user",
                    "content": build_user_message(decision, results, self._rule_descriptions),
                }
            ],
        }
        if self._effort:
            params["output_config"] = {"effort": self._effort}
        return params

    def write_reason(self, decision: ReleaseDecision, results: PolicyInput) -> str | None:
        """A ReasonWriter: the reason text, or None to keep the template. Never raises."""
        try:
            params = self.request_params(decision, results)
        except Exception:  # noqa: BLE001
            log.exception("run %s: could not build the Claude request", decision.run_id)
            return None

        start = self._clock()
        attempts = 1 + self._retries
        for attempt in range(attempts):
            left = self._budget_s - (self._clock() - start)
            if left < MIN_ATTEMPT_S:
                break
            try:
                response = self._client.with_options(timeout=left).messages.create(**params)
            except (anthropic.APIConnectionError, anthropic.RateLimitError) as exc:
                # APITimeoutError is an APIConnectionError: the attempt ran out of budget.
                problem = type(exc).__name__
            except anthropic.APIStatusError as exc:
                if exc.status_code < 500:
                    log.warning(
                        "run %s: Claude request refused (HTTP %s); using the template reason",
                        decision.run_id,
                        exc.status_code,
                    )
                    return None
                problem = f"HTTP {exc.status_code}"
            except Exception as exc:  # noqa: BLE001 - never let the reason break a run
                log.warning(
                    "run %s: Claude request failed (%s); using the template reason",
                    decision.run_id,
                    type(exc).__name__,
                )
                return None
            else:
                return self._reason_from(decision, response)

            log.warning(
                "run %s: Claude attempt %d/%d failed (%s)",
                decision.run_id,
                attempt + 1,
                attempts,
                problem,
            )
            if attempt + 1 == attempts:
                break
            wait = BACKOFF_S[min(attempt, len(BACKOFF_S) - 1)]
            left = self._budget_s - (self._clock() - start)
            if left - wait < MIN_ATTEMPT_S:
                break  # no time left for another attempt after waiting
            self._sleep(wait)

        log.warning("run %s: Claude unavailable; using the template reason", decision.run_id)
        return None

    def _reason_from(self, decision: ReleaseDecision, response: Any) -> str | None:
        if getattr(response, "stop_reason", None) == "refusal":
            log.warning("run %s: Claude declined; using the template reason", decision.run_id)
            return None
        text = " ".join(
            block.text for block in getattr(response, "content", []) or [] if block.type == "text"
        )
        text = " ".join(text.split())
        if not text:
            log.warning("run %s: Claude returned no text; using the template", decision.run_id)
            return None
        if len(text) > MAX_REASON_CHARS:
            cut = text[: MAX_REASON_CHARS - 1]
            text = (cut.rsplit(" ", 1)[0] if " " in cut else cut) + "…"
        return text


def reason_writer_from_env(policy: PolicySet) -> ReasonWriter | None:
    """Claude's ReasonWriter when OPENROUTER_API_KEY is set; otherwise None, and every
    decision keeps its template reason. The key is read here, at the point of use."""
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        return None
    return ClaudeClient.from_env(policy, key).write_reason
