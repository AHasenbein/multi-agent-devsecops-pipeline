"""Fakes shared by the unit tests."""

from devsecops.tools import CommandResult


class FakeDocker:
    """A tiny in-memory docker: tracks containers by name and records every command."""

    def __init__(self):
        self.containers: dict[str, dict] = {}
        self.commands: list[list[str]] = []
        self.fail: dict[str, str] = {}  # subcommand -> stderr
        self.build_result = CommandResult(args=(), returncode=0, stdout="Successfully built\n")
        self.next_id = 1
        self.run_status = "running"  # set to "exited" to fake a crash at startup

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
            self.add(name, image, self.run_status)
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
