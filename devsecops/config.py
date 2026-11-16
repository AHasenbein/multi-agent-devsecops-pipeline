"""Host settings, read from the environment.

The pipeline code (this repo, public) and the app it evaluates (a separate private repo)
live apart, so nothing here may assume that the app sits next to the pipeline. Where the
app is, which GitHub repo it belongs to, and where the trusted policy lives all come from
these settings (CLAUDE.md §2 and §11 items 3 and 10).

    DEVSECOPS_APP_REPO     owner/name of the private app repo. Needed to talk to GitHub.
    DEVSECOPS_APP_DIR      the app's directory inside a checkout of that repo
                           (default "sample_app"; "." when the app is at the repo root)
    DEVSECOPS_APP_IMAGE    Docker image name for the app's builds (default "sample_app")
    DEVSECOPS_POLICY_PATH  the trusted policy.yaml (default: the one in this install)

Secrets (GITHUB_TOKEN, CONTROL_API_TOKEN, OPENROUTER_API_KEY) are not settings and are never
stored here. The code that needs one reads it from the environment at the point of use.
"""

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

DEFAULT_APP_DIR = "sample_app"
DEFAULT_APP_IMAGE = "sample_app"
DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "policy.yaml"

_REPO_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_IMAGE_NAME = re.compile(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*")


class ConfigError(ValueError):
    """A setting is malformed. The message names the variable, never a secret value."""


@dataclass(frozen=True)
class Settings:
    app_repo: str | None = None
    app_dir: str = DEFAULT_APP_DIR
    app_image: str = DEFAULT_APP_IMAGE
    policy_path: Path = DEFAULT_POLICY_PATH

    def require_app_repo(self) -> str:
        """The app repo's owner/name, for code that cannot work without it."""
        if self.app_repo is None:
            raise ConfigError("DEVSECOPS_APP_REPO is not set (expected owner/name)")
        return self.app_repo


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if environ is None else environ

    def value(name: str) -> str | None:
        return env.get(name, "").strip() or None

    app_repo = value("DEVSECOPS_APP_REPO")
    if app_repo is not None and not _REPO_NAME.fullmatch(app_repo):
        raise ConfigError("DEVSECOPS_APP_REPO must look like owner/name")

    app_image = value("DEVSECOPS_APP_IMAGE") or DEFAULT_APP_IMAGE
    if not _IMAGE_NAME.fullmatch(app_image):
        raise ConfigError("DEVSECOPS_APP_IMAGE must be a lowercase Docker image name, no tag")

    policy_path = value("DEVSECOPS_POLICY_PATH")
    return Settings(
        app_repo=app_repo,
        app_dir=_app_dir(value("DEVSECOPS_APP_DIR") or DEFAULT_APP_DIR),
        app_image=app_image,
        policy_path=Path(policy_path).expanduser() if policy_path else DEFAULT_POLICY_PATH,
    )


def _app_dir(raw: str) -> str:
    """A path inside the checkout. It must not be able to point outside of it."""
    path = PurePosixPath(raw.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise ConfigError("DEVSECOPS_APP_DIR must be a relative path inside the app checkout")
    return str(path)
