"""DockerClient against a fake docker CLI (FR3, FR4, FR16, FR17, FR18)."""

import pytest

from devsecops.tools import CommandResult, DockerClient, DockerError, ToolError


class FakeDocker:
    """A tiny in-memory docker: tracks containers by name and records every command."""

    def __init__(self):
        self.containers: dict[str, dict] = {}
        self.commands: list[list[str]] = []
        self.fail: dict[str, str] = {}  # subcommand -> stderr
        self.build_result = CommandResult(args=(), returncode=0, stdout="Successfully built\n")
        self.next_id = 1

    def add(self, name, image="sample_app:old", status="running"):
        self.containers[name] = {"id": f"id{self.next_id}", "image": image, "status": status}
        self.next_id += 1

    def __call__(self, args, *, cwd=None, timeout=None, env=None):
        args = list(args)
        assert args[0] == "docker"
        self.commands.append(args[1:])
        sub = args[1]
        if sub in self.fail:
            return CommandResult(args=tuple(args), returncode=1, stderr=self.fail[sub])
        ok = CommandResult(args=tuple(args), returncode=0)
        missing = CommandResult(args=tuple(args), returncode=1, stderr="No such container")
        if sub == "info":
            return CommandResult(args=tuple(args), returncode=0, stdout="27.0.0\n")
        if sub == "build":
            return self.build_result
        if sub == "run":
            name, image = args[args.index("--name") + 1], args[-1]
            if name in self.containers:
                return CommandResult(args=tuple(args), returncode=125, stderr="name in use")
            self.add(name, image)
            return CommandResult(args=tuple(args), returncode=0, stdout="id\n")
        if sub == "inspect":
            c = self.containers.get(args[-1])
            if c is None:
                return missing
            line = f"{c['id']}|/{args[-1]}|{c['image']}|{c['status']}\n"
            return CommandResult(args=tuple(args), returncode=0, stdout=line)
        if sub in ("stop", "start"):
            if args[-1] not in self.containers:
                return missing
            self.containers[args[-1]]["status"] = "exited" if sub == "stop" else "running"
            return ok
        if sub == "rename":
            old, new = args[-2], args[-1]
            if old not in self.containers or new in self.containers:
                return missing
            self.containers[new] = self.containers.pop(old)
            return ok
        if sub == "rm":
            return ok if self.containers.pop(args[-1], None) else missing
        raise AssertionError(f"unexpected docker command: {args}")


@pytest.fixture
def docker():
    return FakeDocker()


@pytest.fixture
def client(docker):
    return DockerClient(runner=docker)


# ------------------------------------------------------------------ availability (FR3)


def test_fr3_is_available_when_the_daemon_answers(client):
    assert client.is_available()


def test_fr3_not_available_when_daemon_is_down_or_docker_is_missing(docker):
    docker.fail["info"] = "Cannot connect to the Docker daemon"
    assert not DockerClient(runner=docker).is_available()

    def no_docker(args, **kwargs):
        raise ToolError("docker: command not found")

    assert not DockerClient(runner=no_docker).is_available()


# ------------------------------------------------------------------ build (FR4)


def test_fr4_successful_build_returns_the_image_tag(client, docker):
    result = client.build("/ws/sample_app", "sample_app:abc123")
    assert result.success
    assert result.image_tag == "sample_app:abc123"
    assert result.errors == []
    assert docker.commands == [["build", "--tag", "sample_app:abc123", "/ws/sample_app"]]


def test_fr4_failed_build_is_a_result_with_the_errors_saved(client, docker):
    docker.build_result = CommandResult(
        args=(),
        returncode=1,
        stdout="#5 [2/4] COPY requirements.txt .\n",
        stderr=(
            '#5 ERROR: failed to compute cache key: "/requirements.txt": not found\n'
            "ERROR: failed to solve: failed to compute cache key\n"
        ),
    )
    result = client.build("/ws/sample_app", "sample_app:abc123")
    assert not result.success
    assert len(result.errors) == 2
    assert "requirements.txt" in result.errors[0]
    assert "failed to solve" in result.log_tail


def test_fr4_build_failure_without_error_lines_still_has_an_error(client, docker):
    docker.build_result = CommandResult(args=(), returncode=1, stderr="something broke\n")
    assert client.build(".", "t").errors == ["something broke"]
    docker.build_result = CommandResult(args=(), returncode=137)
    assert client.build(".", "t").errors == ["docker build failed with code 137"]


def test_fr4_build_timeout_is_a_failed_build(client, docker):
    docker.build_result = CommandResult(args=(), returncode=-1, timed_out=True)
    result = client.build(".", "t")
    assert not result.success
    assert "timed out" in result.errors[0]


# ------------------------------------------------------------------ containers (FR16)


def test_fr16_run_starts_a_detached_container_on_localhost_only(client, docker):
    container = client.run("sample_app:new", "sandbox-app", host_port=8080)
    assert container.name == "sandbox-app"
    assert container.image_tag == "sample_app:new"
    assert container.status == "running"
    run = docker.commands[0]
    assert run[run.index("--publish") + 1] == "127.0.0.1:8080:8080"
    assert "--detach" in run


def test_fr16_old_container_can_be_stopped_and_kept_under_a_new_name(client, docker):
    docker.add("sandbox-app", image="sample_app:old")
    client.stop("sandbox-app")
    client.rename("sandbox-app", "sandbox-app-previous")
    client.run("sample_app:new", "sandbox-app")

    kept = client.inspect("sandbox-app-previous")
    assert kept.image_tag == "sample_app:old"
    assert kept.status == "exited"
    assert client.inspect("sandbox-app").image_tag == "sample_app:new"


def test_inspect_returns_none_for_an_unknown_container(client):
    assert client.inspect("nope") is None


@pytest.mark.parametrize("method", ["stop", "start", "remove"])
def test_failed_container_command_raises_docker_error(client, method):
    with pytest.raises(DockerError, match="No such container"):
        getattr(client, method)("nope")


def test_run_failure_raises_docker_error(client, docker):
    docker.add("sandbox-app")
    with pytest.raises(DockerError, match="name in use"):
        client.run("sample_app:new", "sandbox-app")


# ------------------------------------------------------------------ rollback (FR17, FR18)


def test_fr17_rollback_brings_the_previous_container_back_under_the_live_name(client, docker):
    docker.add("sandbox-app-previous", image="sample_app:old", status="exited")
    docker.add("sandbox-app", image="sample_app:broken")

    restored = client.rollback("sandbox-app", "sandbox-app-previous")

    assert restored.name == "sandbox-app"
    assert restored.image_tag == "sample_app:old"
    assert restored.status == "running"
    assert "sandbox-app-previous" not in docker.containers


def test_fr17_rollback_works_when_the_new_container_is_already_gone(client, docker):
    docker.add("sandbox-app-previous", image="sample_app:old", status="exited")
    assert client.rollback("sandbox-app", "sandbox-app-previous").image_tag == "sample_app:old"


def test_fr18_rollback_without_a_previous_container_raises(client, docker):
    docker.add("sandbox-app", image="sample_app:broken")
    with pytest.raises(DockerError, match="no previous container"):
        client.rollback("sandbox-app", "sandbox-app-previous")
    assert "sandbox-app" in docker.containers  # the live container is left alone


def test_fr18_rollback_raises_when_the_old_container_will_not_start(client, docker):
    docker.add("sandbox-app-previous", image="sample_app:old", status="exited")
    docker.add("sandbox-app", image="sample_app:broken")
    docker.fail["start"] = "port is already allocated"
    with pytest.raises(DockerError, match="port is already allocated"):
        client.rollback("sandbox-app", "sandbox-app-previous")
