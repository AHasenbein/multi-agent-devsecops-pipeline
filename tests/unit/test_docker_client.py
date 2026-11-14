"""DockerClient against a fake docker CLI (FR3, FR4, FR16, FR17, FR18)."""

import pytest

from devsecops.tools import CommandResult, DockerClient, DockerError, ToolError

from ..fakes import FakeDocker


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
