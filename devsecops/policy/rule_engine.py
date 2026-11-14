"""Deterministic release rules: deny rules, then escalate rules, otherwise ALLOW (FR10-FR12).

No LLM is involved here. The decision this module returns already has a template reason,
so a run gets the same outcome and a usable explanation when Claude is off (QA-AV-01).
"""

import re
from dataclasses import dataclass, field
from functools import lru_cache

from devsecops.models import (
    AgentStatus,
    Finding,
    Outcome,
    PolicyInput,
    PolicySet,
    ReleaseDecision,
    Severity,
)

MAX_DETAILS_PER_RULE = 5


# --------------------------------------------------------------------------- policy lookups


def pip_audit_severity(
    policy: PolicySet, vuln_id: str, aliases: list[str] | tuple[str, ...] = ()
) -> Severity:
    """FR8: a pip-audit finding is HIGH unless its ID (or an alias) is a listed exception."""
    ids = {vuln_id.strip().upper(), *(alias.strip().upper() for alias in aliases)}
    for exception in policy.pip_audit_exceptions:
        if exception.id.upper() in ids:
            return Severity(exception.severity)
    return Severity.HIGH


@lru_cache(maxsize=256)
def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """``*`` matches within one path segment, ``**`` matches across segments."""
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


def _normalize_path(path: str) -> str:
    path = path.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def is_important_file(policy: PolicySet, path: str) -> bool:
    normalized = _normalize_path(path)
    return any(
        _glob_to_regex(_normalize_path(pattern)).fullmatch(normalized)
        for pattern in policy.important_files
    )


# --------------------------------------------------------------------------- engine


@dataclass
class _Match:
    rule_id: str
    details: list[str] = field(default_factory=list)


def _location(finding: Finding) -> str:
    if finding.file:
        return f"{finding.file}:{finding.line}" if finding.line is not None else finding.file
    return finding.package or "unknown location"


def _describe(finding: Finding) -> str:
    text = f"{finding.tool} {finding.rule_id} at {_location(finding)}"
    return f"{text}: {finding.message}" if finding.message else text


class RuleEngine:
    def __init__(self, policy: PolicySet) -> None:
        self._policy = policy
        self._descriptions = {rule.id: rule.description for rule in policy.rules}

    def effective_severity(self, finding: Finding) -> Severity:
        """Severity the rules use. pip-audit findings are re-derived from policy (FR8),
        whatever severity the scanner or an agent wrote on the finding."""
        if finding.tool == "pip-audit":
            return pip_audit_severity(self._policy, finding.rule_id, finding.aliases)
        return finding.severity

    def evaluate(self, results: PolicyInput) -> ReleaseDecision:
        deny = self._deny_matches(results)
        if deny:
            return self._decision(results.run_id, Outcome.DENY, deny)
        escalate = self._escalate_matches(results)
        if escalate:
            return self._decision(results.run_id, Outcome.ESCALATE, escalate)
        return self._decision(results.run_id, Outcome.ALLOW, [])

    # -- deny rules (FR5, FR11)

    def _deny_matches(self, results: PolicyInput) -> list[_Match]:
        matches: list[_Match] = []

        if results.build is not None and not results.build.success:
            matches.append(_Match("build_failed", list(results.build.errors)))

        if results.test is not None and (results.test.failed > 0 or results.test.failures):
            details = [
                f"{failure.test_name}"
                + (f" ({failure.file}:{failure.line})" if failure.file else "")
                + (f": {failure.message}" if failure.message else "")
                for failure in results.test.failures
            ] or [f"{results.test.failed} test(s) failed"]
            matches.append(_Match("test_failed", details))

        high = self._findings_with(results, Severity.HIGH)
        if high:
            matches.append(_Match("high_finding", [_describe(f) for f in high]))

        return matches

    # -- escalate rules (FR9, FR12)

    def _escalate_matches(self, results: PolicyInput) -> list[_Match]:
        matches: list[_Match] = []

        medium = self._findings_with(results, Severity.MEDIUM)
        if medium:
            matches.append(_Match("medium_finding", [_describe(f) for f in medium]))

        minimum = self._policy.thresholds.min_coverage_pct
        if results.test is not None and results.test.coverage_pct < minimum:
            matches.append(
                _Match(
                    "low_coverage",
                    [f"coverage is {results.test.coverage_pct:.1f}%, minimum is {minimum:g}%"],
                )
            )

        important = [p for p in results.changed_files if is_important_file(self._policy, p)]
        if important:
            matches.append(_Match("important_file_changed", important))

        errors = self._agent_errors(results)
        if errors:
            matches.append(_Match("agent_error", errors))

        if results.security is not None:
            injections = [f for f in results.security.findings if f.tool == "injection"]
            if results.security.injection_suspected or injections:
                matches.append(
                    _Match(
                        "prompt_injection",
                        [_describe(f) for f in injections]
                        or ["possible prompt injection in the change"],
                    )
                )

        return matches

    def _agent_errors(self, results: PolicyInput) -> list[str]:
        errors = [
            f"{result.agent} agent error"
            + (f": {'; '.join(result.errors)}" if result.errors else "")
            for result in results.agent_results
            if result.status is AgentStatus.ERROR
        ]
        if results.security is not None:
            errors += [f"scan tool error: {error}" for error in results.security.tool_errors]
        # Fail closed: a missing result is never treated as a clean result.
        if results.build is None:
            errors.append("build result is missing")
        if results.test is None:
            errors.append("test report is missing")
        if results.security is None:
            errors.append("security report is missing")
        return errors

    # -- helpers

    def _findings_with(self, results: PolicyInput, severity: Severity) -> list[Finding]:
        if results.security is None:
            return []
        # Injection findings have their own rule (prompt_injection), so they are not also
        # counted as a scanner finding.
        return [
            f
            for f in results.security.findings
            if f.tool != "injection" and self.effective_severity(f) is severity
        ]

    def _decision(self, run_id: str, outcome: Outcome, matches: list[_Match]) -> ReleaseDecision:
        return ReleaseDecision(
            run_id=run_id,
            outcome=outcome,
            matched_rules=tuple(match.rule_id for match in matches),
            reason=self._template_reason(outcome, matches),
            reason_source="template",
        )

    def _template_reason(self, outcome: Outcome, matches: list[_Match]) -> str:
        if outcome is Outcome.ALLOW:
            return "ALLOW: no deny or escalate rule matched."
        lines = [f"{outcome.value}: {len(matches)} rule(s) matched."]
        for match in matches:
            lines.append(f"- {match.rule_id}: {self._descriptions.get(match.rule_id, '')}".rstrip())
            for detail in match.details[:MAX_DETAILS_PER_RULE]:
                lines.append(f"    {detail}")
            extra = len(match.details) - MAX_DETAILS_PER_RULE
            if extra > 0:
                lines.append(f"    ... and {extra} more")
        return "\n".join(lines)
