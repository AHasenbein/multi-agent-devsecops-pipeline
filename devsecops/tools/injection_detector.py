"""Heuristic prompt-injection check over the lines a change adds (FR12, QA-SE-01).

A hit never decides anything by itself. It sets ``injection_suspected``, which the RuleEngine
turns into ESCALATE, so a person looks at the change. The patterns are narrow on purpose:
at least 9 of 10 safe changes must still be allowed.
"""

import re
import unicodedata
from collections.abc import Iterator

from devsecops.models import Finding, Severity

_SNIPPET = 120
_ZERO_WIDTH = re.compile("[​-‏⁠-⁤﻿­]")
_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = tuple(
    (rule_id, label, re.compile(pattern, re.IGNORECASE))
    for rule_id, label, pattern in (
        (
            "INJ001",
            "tells the reader to ignore its instructions",
            r"\b(ignore|disregard|forget|override)\b.{0,40}"
            r"\b(previous|prior|above|earlier|all|any|your|the)\b.{0,30}"
            r"\b(instructions?|rules?|prompts?|polic(?:y|ies)|guidelines?|directions?)\b",
        ),
        (
            "INJ002",
            "tries to give the reader a new role",
            r"\byou are now\b|\bfrom now on,? you\b|\bpretend (?:to be|you are)\b"
            r"|\bact as (?:an?|the) .{0,30}\b(?:assistant|reviewer|ai|model)\b",
        ),
        (
            "INJ003",
            "tries to steer the release decision",
            r"\b(?:approve|allow|accept|pass|whitelist)\b.{0,20}\bthis\b.{0,20}"
            r"\b(?:change|commit|pr|pull request|code|diff|merge|release|deployment)\b"
            r"|\b(?:mark|treat|classify|report|rate)\b.{0,30}\bas\b.{0,10}"
            r"\b(?:safe|secure|benign|low[- ]risk|approved)\b"
            r"|\b(?:outcome|decision|verdict)\b\s*(?:[:=]|is|should be)\s*[\"']?(?:allow|approve)"
            r"|\b(?:return|respond with|output|say|answer)\b.{0,15}\b(?-i:ALLOW)\b",
        ),
        (
            "INJ004",
            "addresses an AI reviewer directly",
            r"\b(?:dear|hey|attention|note to|message (?:to|for)|instructions? (?:to|for))\b.{0,15}"
            r"\b(?:ai|llm|claude|assistant|language model|reviewer bot|agent)\b"
            r"|\bas an ai\b"
            r"|\bai (?:reviewer|assistant|agent)s?\b.{0,20}\b(?:should|must|will)\b",
        ),
        (
            "INJ005",
            "contains chat or system-prompt markers",
            r"<\|(?:im_start|im_end|system|endoftext)\|>|\[/?INST\]"
            r"|</?(?:system|assistant|human)>"
            r"|\bsystem prompt\b",
        ),
        (
            "INJ006",
            "asks for findings or checks to be skipped",
            r"\bdo not (?:flag|report|mention|scan|block|deny|escalate)\b"
            r"|\bbypass\b.{0,20}\b(?:security|policy|review|scan)\b",
        ),
    )
)


def _normalize(text: str) -> str:
    """Undo the easy disguises: full-width letters, zero-width characters, odd spacing."""
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH.sub("", text)
    return " ".join(text.split())


def added_lines(diff: str) -> Iterator[tuple[str | None, int, str]]:
    """Yield ``(file, new_line_number, text)`` for each line a unified diff adds."""
    file: str | None = None
    line_no = 0
    old_left = new_left = 0
    for raw in diff.splitlines():
        if old_left > 0 or new_left > 0:  # inside a hunk: the first character is the marker
            if raw.startswith("+"):
                yield file, line_no, raw[1:]
                line_no += 1
                new_left -= 1
            elif raw.startswith("-"):
                old_left -= 1
            elif raw.startswith("\\"):
                pass  # "\ No newline at end of file"
            else:
                line_no += 1
                old_left -= 1
                new_left -= 1
            continue
        if raw.startswith("+++ "):
            path = raw[4:].split("\t")[0].strip().strip('"')
            file = None if path == "/dev/null" else path.removeprefix("b/")
            continue
        hunk = _HUNK.match(raw)
        if hunk:
            old_left = int(hunk.group(1) or 1)
            line_no = int(hunk.group(2))
            new_left = int(hunk.group(3) or 1)


class InjectionDetector:
    def scan_diff(self, diff: str) -> list[Finding]:
        findings: list[Finding] = []
        for file, line_no, text in added_lines(diff):
            findings += self.scan_text(text, file=file, line=line_no)
        return findings

    def scan_text(
        self, text: str, file: str | None = None, line: int | None = None
    ) -> list[Finding]:
        """Check free text such as a commit message or PR title. Each line is checked alone."""
        findings: list[Finding] = []
        for offset, raw in enumerate(text.splitlines() or [text]):
            normalized = _normalize(raw)
            if not normalized:
                continue
            for rule_id, label, pattern in _PATTERNS:
                match = pattern.search(normalized)
                if match:
                    findings.append(
                        Finding(
                            tool="injection",
                            rule_id=rule_id,
                            file=file,
                            line=(line + offset) if line is not None else None,
                            severity=Severity.MEDIUM,
                            message=f"{label}: {match.group(0)[:_SNIPPET]!r}",
                        )
                    )
        return findings
