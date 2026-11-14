"""Loads and validates policy.yaml into a PolicySet.

The policy must come from a trusted host path, never from the commit being evaluated
(CLAUDE.md §11 item 3). Choosing that path is the caller's job (``config.py``).
"""

from pathlib import Path

import yaml
from pydantic import ValidationError

from devsecops.models import PolicySet


class PolicyError(Exception):
    """policy.yaml is missing, unreadable, or invalid. SetupValidator reports this (FR3)."""


def parse_policy(text: str, source: str = "policy.yaml") -> PolicySet:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"{source}: not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"{source}: expected a mapping at the top level")
    try:
        return PolicySet.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors()
        )
        raise PolicyError(f"{source}: invalid policy: {problems}") from exc


def load_policy(path: str | Path) -> PolicySet:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"{path}: cannot read policy file: {exc}") from exc
    return parse_policy(text, source=str(path))
