"""Host settings: where the app is and which repo it belongs to (CLAUDE.md §2, two repos)."""

from pathlib import Path

import pytest

from devsecops.config import DEFAULT_POLICY_PATH, ConfigError, Settings, load_settings
from devsecops.policy import load_policy


def test_defaults_match_this_repo_so_local_runs_need_no_setup():
    settings = load_settings({})
    assert settings == Settings()
    assert settings.app_repo is None
    assert settings.app_dir == "sample_app"
    assert settings.app_image == "sample_app"
    assert load_policy(settings.policy_path).reviewers  # the default policy file exists


def test_settings_come_from_the_environment():
    settings = load_settings(
        {
            "DEVSECOPS_APP_REPO": " someone/notes-app ",
            "DEVSECOPS_APP_DIR": "services/notes/",
            "DEVSECOPS_APP_IMAGE": "notes-app",
            "DEVSECOPS_POLICY_PATH": "/etc/devsecops/policy.yaml",
            "DEVSECOPS_STATE_DIR": "/var/lib/devsecops",
        }
    )
    assert settings.app_repo == "someone/notes-app"
    assert settings.app_dir == "services/notes"
    assert settings.app_image == "notes-app"
    assert settings.policy_path == Path("/etc/devsecops/policy.yaml")
    assert settings.state_dir == Path("/var/lib/devsecops")


def test_app_at_the_repo_root():
    assert load_settings({"DEVSECOPS_APP_DIR": "."}).app_dir == "."


def test_blank_values_fall_back_to_the_defaults():
    settings = load_settings({"DEVSECOPS_APP_REPO": "  ", "DEVSECOPS_POLICY_PATH": ""})
    assert settings.app_repo is None
    assert settings.policy_path == DEFAULT_POLICY_PATH


@pytest.mark.parametrize("app_dir", ["/srv/app", "../other-repo", "sample_app/../../etc"])
def test_app_dir_cannot_point_outside_the_checkout(app_dir):
    with pytest.raises(ConfigError, match="DEVSECOPS_APP_DIR"):
        load_settings({"DEVSECOPS_APP_DIR": app_dir})


@pytest.mark.parametrize("repo", ["notes-app", "https://github.com/someone/notes-app", "a/b/c"])
def test_app_repo_must_be_owner_slash_name(repo):
    with pytest.raises(ConfigError, match="DEVSECOPS_APP_REPO"):
        load_settings({"DEVSECOPS_APP_REPO": repo})


@pytest.mark.parametrize("image", ["Notes", "notes:latest", "notes app"])
def test_app_image_must_be_a_plain_image_name(image):
    with pytest.raises(ConfigError, match="DEVSECOPS_APP_IMAGE"):
        load_settings({"DEVSECOPS_APP_IMAGE": image})


def test_require_app_repo_names_the_variable_when_it_is_missing():
    with pytest.raises(ConfigError, match="DEVSECOPS_APP_REPO is not set"):
        Settings().require_app_repo()
    assert Settings(app_repo="someone/notes-app").require_app_repo() == "someone/notes-app"
