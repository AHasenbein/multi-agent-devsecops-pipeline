"""Tells the developer and the reviewers what happened, on GitHub (FR3, FR5, FR14, FR18).

A commit status shows the state of the run next to the commit. A comment (on the pull
request, or on the commit for a push) opens with the decision, a bold one-line main issue
and the explanation, then lists the rules that matched and the failed tests and findings
with file and line. LOW findings are folded away so they cannot bury the cause.

Test names, messages and tool output come from the change being evaluated, so they are
untrusted. They are only ever put inside code spans or code blocks, where they cannot
mention people, add links or imitate the pipeline's own headings. The explanation is
written from that same text, so it is shown as a fully escaped blockquote (_quote_block)
that reads as a normal paragraph but cannot do any of those things either.
"""

import re
import string
from datetime import datetime

import httpx

from devsecops.models import (
    Finding,
    Outcome,
    PipelineRun,
    PolicyInput,
    PolicySet,
    ReleaseDecision,
    Severity,
)
from devsecops.notifications.base import CommitState

_SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
_STATUS_DESCRIPTION_LIMIT = 140  # GitHub's limit for a commit status description
_HEADLINE = {
    Outcome.ALLOW: "ALLOW: the change passed every rule",
    Outcome.DENY: "DENY: the change is blocked",
    Outcome.ESCALATE: "ESCALATE: a reviewer must decide",
}


class GitHubNotifier:
    def __init__(
        self,
        repo: str,
        token: str,
        policy: PolicySet,
        client: httpx.Client | None = None,
        api_url: str = "https://api.github.com",
        context: str = "devsecops/pipeline",
        approve_workflow: str = "approve.yml",
        max_items: int = 10,
        timeout_s: float = 10.0,
    ) -> None:
        self._repo = repo
        self._policy = policy
        self._client = client or httpx.Client(follow_redirects=False)
        self._api_url = api_url.rstrip("/")
        self._context = context
        self._approve_workflow = approve_workflow
        self._max_items = max_items
        self._timeout_s = timeout_s
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    # ------------------------------------------------------------------ Notifier

    def set_status(self, run: PipelineRun, state: CommitState, description: str) -> None:
        self._post(
            f"statuses/{run.commit_sha}",
            {
                "state": state,
                "description": _one_line(description, _STATUS_DESCRIPTION_LIMIT),
                "context": self._context,
            },
        )

    def post_decision(
        self, run: PipelineRun, decision: ReleaseDecision, results: PolicyInput
    ) -> None:
        self._comment(run, self.decision_comment(run, decision, results))

    def request_review(
        self,
        run: PipelineRun,
        decision: ReleaseDecision,
        reviewers: tuple[str, ...],
        deadline: datetime,
    ) -> None:
        # The reviewers come from the trusted policy.yaml, so these mentions are ours.
        mentions = " ".join(f"@{login}" for login in reviewers)
        lines = [
            "## DevSecOps pipeline: review needed",
            "",
            f"{mentions} this change was escalated and waits for one of you.",
            "",
            f"- **Run:** `{run.run_id}`",
            f"- **Commit:** `{run.commit_sha}`",
            f"- **Rules matched:** {_code_list(decision.matched_rules)}",
            f"- **Answer by:** {deadline:%Y-%m-%d %H:%M} UTC. Without an answer the change"
            " is denied.",
            "",
            f"To answer, run the `{self._approve_workflow}` workflow in this repository"
            " (Actions tab, **Run workflow**) with the run and commit above and `verdict` set"
            " to `APPROVE` or `REJECT`. From a terminal:",
            "",
            # Every value in this block is ours: the repo from the host's settings, the
            # run id we generated, and a commit id the API accepted as 40 hex digits.
            "```text",
            f"gh workflow run {self._approve_workflow} -R {self._repo}"
            f" -f run_id={run.run_id} -f commit_sha={run.commit_sha} -f verdict=APPROVE",
            "```",
            "",
            "The workflow records whoever started it as the reviewer.",
        ]
        self._comment(run, "\n".join(lines))

    def alert(self, run: PipelineRun, title: str, body: str) -> None:
        lines = [
            f"## DevSecOps pipeline alert: {_one_line(title, 120)}",
            "",
            f"- **Run:** `{run.run_id}`",
            f"- **Commit:** `{run.commit_sha}`",
        ]
        if body.strip():
            lines += ["", _code_block(body, 2000)]
        self._comment(run, "\n".join(lines))

    # ------------------------------------------------------------------ comment text

    def decision_comment(
        self, run: PipelineRun, decision: ReleaseDecision, results: PolicyInput
    ) -> str:
        """The decision and its main cause first, then the explanation, then the details.

        scripts/run_seeded_changes.py reads the Decision/Commit/Run fields from the part
        before the first "###" heading, so they stay there.
        """
        descriptions = {rule.id: rule.description for rule in self._policy.rules}
        lines = [f"## DevSecOps pipeline: {_HEADLINE[decision.outcome]}", ""]
        cause = self._main_cause(decision, results, descriptions)
        if cause:
            lines += [f"**Main issue:** {cause}", ""]
        lines += [
            f"- **Decision:** {decision.outcome.value}",
            f"- **Commit:** `{run.commit_sha}`",
            f"- **Run:** `{run.run_id}`",
        ]

        writer = "Claude" if decision.reason_source == "claude" else "a fixed template"
        lines += [
            "",
            "### Explanation",
            _quote_block(decision.reason, 3000),
            "",
            f"_The decision comes from the rules in `policy.yaml`. The explanation was written"
            f" by {writer} and cannot change it._",
        ]

        lines += ["", "### Rules that matched"]
        if decision.matched_rules:
            lines += [
                f"- `{_plain(rule_id)}`: {descriptions.get(rule_id, '')}".rstrip(": ")
                for rule_id in decision.matched_rules
            ]
        else:
            lines.append("- None. No deny or escalate rule matched.")

        if results.build is not None and not results.build.success:
            lines += ["", "### Build failed"]
            lines += self._listed(results.build.errors, lambda error: f"- {_code(error, 300)}")

        failures = results.test.failures if results.test else []
        if failures:
            lines += ["", f"### Failed tests ({len(failures)})"]
            lines += self._listed(
                failures,
                lambda f: (
                    f"- {_code(f.test_name)} at {_code(_location(f.file, f.line))}"
                    + (f": {_code(f.message, 200)}" if f.message else "")
                ),
            )

        findings = sorted(
            results.security.findings if results.security else [],
            key=lambda f: _SEVERITY_ORDER[f.severity],
        )
        if findings:
            # LOW findings never decide anything. Folded away, they cannot bury the
            # HIGH or MEDIUM finding that does.
            serious = [f for f in findings if f.severity is not Severity.LOW]
            low = [f for f in findings if f.severity is Severity.LOW]
            lines += ["", f"### Security findings ({len(findings)})"]
            lines += self._listed(serious, _finding_line)
            if low:
                lines += [
                    "",
                    "<details>",
                    f"<summary>{len(low)} LOW finding(s), which do not affect the decision"
                    "</summary>",
                    "",
                    *self._listed(low, _finding_line),
                    "",
                    "</details>",
                ]

        notes = []
        if results.test is not None:
            minimum = self._policy.thresholds.min_coverage_pct
            notes.append(f"- Test coverage: {results.test.coverage_pct:g}% (minimum {minimum:g}%)")
        if results.security is not None:
            notes += [
                f"- Scan tool error: {_code(error, 200)}" for error in results.security.tool_errors
            ]
        if notes:
            lines += ["", "### Other checks", *notes]
        return "\n".join(lines)

    def _main_cause(
        self, decision: ReleaseDecision, results: PolicyInput, descriptions: dict[str, str]
    ) -> str | None:
        """One line naming what decided the run: the first matched rule (deny rules come
        first) and the first item that triggered it. Built from our own data, never from
        the explanation, and untrusted values stay in code spans."""
        if not decision.matched_rules:
            return None
        rule = decision.matched_rules[0]
        cause = None
        findings = sorted(
            results.security.findings if results.security else [],
            key=lambda f: _SEVERITY_ORDER[f.severity],
        )
        if rule == "build_failed" and results.build is not None:
            cause = "the Docker build failed" + (
                f": {_code(results.build.errors[0], 200)}" if results.build.errors else ""
            )
        elif rule == "test_failed" and results.test is not None:
            failures = results.test.failures
            if failures:
                cause = (
                    f"test {_code(failures[0].test_name)} failed at"
                    f" {_code(_location(failures[0].file, failures[0].line))}"
                )
            else:
                cause = f"{results.test.failed} test(s) failed"
        elif rule in ("high_finding", "medium_finding"):
            severity = Severity.HIGH if rule == "high_finding" else Severity.MEDIUM
            top = next((f for f in findings if f.severity is severity), None)
            if top is not None:
                cause = _finding_line(top).removeprefix("- ")
        elif rule == "low_coverage" and results.test is not None:
            minimum = self._policy.thresholds.min_coverage_pct
            cause = (
                f"test coverage is {results.test.coverage_pct:g}%, below the minimum of"
                f" {minimum:g}%"
            )
        if cause is None:
            cause = descriptions.get(rule) or _code(rule)
        others = len(decision.matched_rules) - 1
        if others:
            cause += f" (and {others} more rule{'s' if others > 1 else ''} below)"
        return cause

    def _listed(self, items: list, line) -> list[str]:
        shown = [line(item) for item in items[: self._max_items]]
        extra = len(items) - self._max_items
        return [*shown, f"- ... and {extra} more"] if extra > 0 else shown

    # ------------------------------------------------------------------ HTTP

    def _comment(self, run: PipelineRun, body: str) -> None:
        if run.pr_number is not None:
            self._post(f"issues/{run.pr_number}/comments", {"body": body})
        else:
            self._post(f"commits/{run.commit_sha}/comments", {"body": body})

    def _post(self, path: str, payload: dict) -> None:
        """Raises on failure. The orchestrator logs it and carries on: a failed
        notification never changes a decision or stops a rollback."""
        response = self._client.post(
            f"{self._api_url}/repos/{self._repo}/{path}",
            json=payload,
            headers=self._headers,
            timeout=self._timeout_s,
        )
        if response.status_code >= 300:
            # Our own message: it names the call and the status, and nothing from the
            # request, so the token cannot end up in a log (QA-PR-01).
            raise GitHubError(f"GitHub answered {response.status_code} for POST {path}")


class GitHubError(Exception):
    """GitHub refused a notification."""


def _finding_line(finding: Finding) -> str:
    where = finding.package or _location(finding.file, finding.line)
    text = (
        f"- **{finding.severity.value}** {finding.tool} {_code(finding.rule_id)} at {_code(where)}"
    )
    return f"{text}: {_code(finding.message, 200)}" if finding.message else text


def _location(file: str | None, line: int | None) -> str:
    if not file:
        return "unknown location"
    return f"{file}:{line}" if line is not None else file


def _plain(text: str) -> str:
    """Text for inside a code span: one line, and no backtick that could close the span."""
    return " ".join(str(text).replace("`", "'").split())


def _one_line(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _code(text: str, limit: int = 160) -> str:
    return f"`{_one_line(_plain(text), limit) or ' '}`"


def _code_list(items: tuple[str, ...]) -> str:
    return ", ".join(_code(item) for item in items) or "none"


_ZWSP = "​"  # zero-width space: invisible, but breaks what GitHub would link
_MARKDOWN_PUNCTUATION = frozenset(string.punctuation)


def _quote_block(text: str, limit: int) -> str:
    """Untrusted text as a plain, wrapped blockquote that renders exactly as written.

    Every ASCII punctuation character is backslash-escaped (CommonMark allows that for
    all of them), so no heading, list, emphasis, link, image, table or HTML can form.
    GitHub links @mentions, #references and URLs in the text left after escaping, so
    those get a zero-width space instead: after "@" and "#", inside "://" and after
    "www". Leading spaces are dropped, so no line becomes an indented code block.
    """
    text = str(text).strip()
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    text = text.replace("://", f":{_ZWSP}//")
    text = re.sub(r"(?i)\bwww\.", lambda m: m.group(0)[:3] + _ZWSP + ".", text)
    out = []
    for line in text.splitlines():
        escaped = []
        for char in line.strip():
            escaped.append(f"\\{char}" if char in _MARKDOWN_PUNCTUATION else char)
            if char in "@#":
                escaped.append(_ZWSP)
        out.append(f"> {''.join(escaped)}".rstrip())
    return "\n".join(out) or ">"


def _code_block(text: str, limit: int) -> str:
    text = str(text).replace("```", "'''").strip()
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return f"```text\n{text}\n```"
