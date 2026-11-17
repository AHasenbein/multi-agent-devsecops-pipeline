"""GitWorkspaces: a private checkout of the evaluated commit, its diff and its changed
files (FR1, FR4, FR12; QA-PR-01). These tests use real git against a repo in tmp_path."""

import base64
import os
import subprocess

import pytest

from devsecops.tools import CommandResult, GitWorkspaces, WorkspaceError

IDENTITY = {
    "GIT_AUTHOR_NAME": "Dev",
    "GIT_AUTHOR_EMAIL": "dev@example.com",
    "GIT_COMMITTER_NAME": "Dev",
    "GIT_COMMITTER_EMAIL": "dev@example.com",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "PATH": os.environ["PATH"],
}


class Remote:
    """The 'app repo': a real git repository the workspaces fetch from."""

    def __init__(self, path):
        self.path = path
        path.mkdir()
        self.git("init", "-q", "-b", "main")

    def git(self, *args):
        done = subprocess.run(
            ["git", "-C", str(self.path), *args],
            env=IDENTITY,
            capture_output=True,
            text=True,
            check=True,
        )
        return done.stdout.strip()

    def commit(self, files, message="change"):
        for name, content in files.items():
            target = self.path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")


@pytest.fixture
def remote(tmp_path):
    return Remote(tmp_path / "app-repo")


@pytest.fixture
def workspaces(tmp_path, remote):
    return GitWorkspaces(tmp_path / "workspaces", str(remote.path))


def test_fr4_checks_out_the_commit_with_its_diff_and_changed_files(remote, workspaces):
    remote.commit({"sample_app/app/main.py": "print('one')\n"})
    sha = remote.commit({"sample_app/app/main.py": "print('two')\n"})

    checkout = workspaces.prepare("run-1", sha)

    assert (checkout.path / "sample_app/app/main.py").read_text() == "print('two')\n"
    assert checkout.changed_files == ["sample_app/app/main.py"]
    assert "-print('one')" in checkout.diff and "+print('two')" in checkout.diff


def test_fr12_base_sha_covers_every_commit_of_a_push_not_only_the_last(remote, workspaces):
    """A push of two commits: the important file changed in the first one must be seen."""
    before = remote.commit({"sample_app/app/main.py": "x = 1\n"})
    remote.commit({"sample_app/Dockerfile": "FROM python:3.12\n"})
    sha = remote.commit({"sample_app/app/main.py": "x = 2\n"})

    assert workspaces.prepare("run-1", sha).changed_files == ["sample_app/app/main.py"]
    assert workspaces.prepare("run-2", sha, base_sha=before).changed_files == [
        "sample_app/Dockerfile",
        "sample_app/app/main.py",
    ]


def test_pull_request_is_compared_with_where_it_branched_off(remote, workspaces):
    remote.commit({"README.md": "hello\n"})
    remote.git("checkout", "-q", "-b", "feature")
    head = remote.commit({"sample_app/app/main.py": "x = 1\n"})
    remote.git("checkout", "-q", "main")
    base = remote.commit({"policy.yaml": "version: 2\n"})  # main moved on meanwhile

    checkout = workspaces.prepare("run-1", head, base_sha=base)

    assert checkout.changed_files == ["sample_app/app/main.py"]  # not main's policy.yaml


def test_fr12_a_renamed_file_is_listed_under_both_names(remote, workspaces):
    remote.commit({"sample_app/Dockerfile": "FROM python:3.12\nRUN pip install fastapi\n"})
    remote.git("mv", "sample_app/Dockerfile", "sample_app/Dockerfile.old")
    sha = remote.commit({})

    assert workspaces.prepare("run-1", sha).changed_files == [
        "sample_app/Dockerfile",
        "sample_app/Dockerfile.old",
    ]


def test_first_commit_of_a_repo_is_compared_with_nothing(remote, workspaces):
    sha = remote.commit({"a.py": "a = 1\n", "b.py": "b = 1\n"})
    checkout = workspaces.prepare("run-1", sha)
    assert checkout.changed_files == ["a.py", "b.py"]
    assert "+a = 1" in checkout.diff


def test_all_zero_base_of_a_new_branch_falls_back_to_the_parent(remote, workspaces):
    remote.commit({"a.py": "a = 1\n"})
    sha = remote.commit({"b.py": "b = 1\n"})
    assert workspaces.prepare("run-1", sha, base_sha="0" * 40).changed_files == ["b.py"]


def test_unknown_commit_is_an_error_and_leaves_no_directory(remote, workspaces, tmp_path):
    remote.commit({"a.py": "a = 1\n"})
    with pytest.raises(WorkspaceError, match="was not found in the app repo"):
        workspaces.prepare("run-1", "f" * 40)
    assert not (tmp_path / "workspaces" / "run-1").exists()


@pytest.mark.parametrize("sha", ["HEAD", "main", "abc123", "--upload-pack=touch /tmp/x", ""])
def test_commit_must_be_a_full_commit_id(workspaces, sha):
    with pytest.raises(WorkspaceError, match="commit_sha"):
        workspaces.prepare("run-1", sha)


@pytest.mark.parametrize("run_id", ["../escape", "a/b", "", ".hidden"])
def test_run_id_cannot_point_outside_the_workspace_root(workspaces, run_id):
    with pytest.raises(WorkspaceError, match="run_id"):
        workspaces.prepare(run_id, "a" * 40)


def test_each_run_has_its_own_checkout_and_remove_deletes_it(remote, workspaces):
    sha = remote.commit({"a.py": "a = 1\n"})
    first = workspaces.prepare("run-1", sha)
    second = workspaces.prepare("run-2", sha)
    assert first.path != second.path
    with pytest.raises(WorkspaceError, match="already exists"):
        workspaces.prepare("run-1", sha)

    workspaces.remove("run-1")
    workspaces.remove("run-1")  # no error when it is already gone
    assert not first.path.exists() and second.path.exists()


def test_qa_pr_01_token_is_not_on_the_command_line_and_not_in_errors(tmp_path):
    token = "ghp_secret_token_value"
    encoded = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    seen = []

    def runner(args, *, cwd=None, timeout=None, env=None):
        seen.append((list(args), dict(env)))
        if args[3] == "init":
            return CommandResult(args=tuple(args), returncode=0)
        stderr = f"fatal: could not read from https://x:{token}@github.com ({encoded})"
        return CommandResult(args=tuple(args), returncode=128, stderr=stderr)

    workspaces = GitWorkspaces(
        tmp_path / "ws", "https://github.com/someone/app.git", token, runner=runner
    )
    with pytest.raises(WorkspaceError) as error:
        workspaces.prepare("run-1", "a" * 40)

    assert token not in str(error.value) and encoded not in str(error.value)
    for args, env in seen:
        assert not any(token in arg or encoded in arg for arg in args)
        # Sent to github.com only, and git never stops to ask for a password.
        assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraHeader"
        assert env["GIT_CONFIG_VALUE_0"] == f"Authorization: Basic {encoded}"
        assert env["GIT_TERMINAL_PROMPT"] == "0"
