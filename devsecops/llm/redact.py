"""Strips anything that looks like a secret from text before it leaves the host (QA-PR-01).

Everything from the evaluated change (finding messages, test failure messages, file names)
goes through ``redact()`` before it is put into a prompt. ``SECRET_PATTERNS`` is also what
``scripts/check_no_secrets.py`` searches logs and records for.
"""

import re
from typing import NamedTuple

REDACTED = "[REDACTED]"


class SecretPattern(NamedTuple):
    name: str
    pattern: re.Pattern[str]
    # Regex group that holds the secret. 0 = the whole match; for an assignment such as
    # ``password = "x"`` only the value is replaced, so the reason can still say what it was.
    group: int = 0


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "private_key_block",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
            re.DOTALL,
        ),
    ),
    SecretPattern("openrouter_key", re.compile(r"\bsk-or-[A-Za-z0-9_-]{16,}")),
    SecretPattern("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}")),
    SecretPattern("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    SecretPattern("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    SecretPattern("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    SecretPattern(
        "bearer_token", re.compile(r"\bBearer\s+([A-Za-z0-9._~+/=-]{8,})", re.IGNORECASE), 1
    ),
    SecretPattern(
        "secret_assignment",
        re.compile(
            # NAME[_SUFFIX] = value, e.g. password=..., DB_PASSWORD=..., SECRET_KEY: ...
            r"""\b(?:[A-Za-z0-9_]*_)?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)"""
            r"""(?:_[A-Za-z0-9]+)?["']?\s*[:=]\s*["']?"""
            # The value: 4+ characters with at least one letter (not a bare number), not an
            # earlier [REDACTED] (so redacting twice changes nothing), and not a call such
            # as share_token(note_id), which is code rather than a secret.
            r"""((?=[^\s"',;)}\]]*[A-Za-z])[^\s"',;(){}\]\[][^\s"',;(){}\]]{3,}(?![(\w]))""",
            re.IGNORECASE,
        ),
        1,
    ),
)


def redact(text: str) -> str:
    """Return ``text`` with every secret-looking part replaced by ``[REDACTED]``."""
    for secret in SECRET_PATTERNS:
        text = secret.pattern.sub(lambda m, g=secret.group: _replace(m, g), text)
    return text


def _replace(match: re.Match[str], group: int) -> str:
    if group == 0:
        return REDACTED
    if match.group(group) == REDACTED:
        return match.group(0)
    start, end = match.span(group)
    whole_start = match.start(0)
    whole = match.group(0)
    return whole[: start - whole_start] + REDACTED + whole[end - whole_start :]
