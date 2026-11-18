"""scripts/check_no_secrets.py: is there a key in any log or record? (QA-PR-01)"""

import importlib.util
import sqlite3
import sys
from pathlib import Path

import pytest

from devsecops.models import Verdict
from devsecops.tools import ScanOutput

from ..fakes import FakeDocker
from .test_graph_paths import HIGH, MEDIUM, Checker, Pipeline, RecordingNotifier, World

REPO = Path(__file__).resolve().parents[2]
OPENROUTER = "sk-or-v1-" + "f00d" * 12
TOKEN_VALUE = "control-api-token-for-tests-only"


def load_script():
    spec = importlib.util.spec_from_file_location(
        "check_no_secrets", REPO / "scripts" / "check_no_secrets.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


script = load_script()


@pytest.fixture(autouse=True)
def no_real_secrets_in_env(monkeypatch):
    for name in script.SECRET_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def sqlite_file(path, rows):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE records (seq INTEGER, payload TEXT, blob BLOB)")
    conn.executemany("INSERT INTO records VALUES (?, ?, ?)", rows)
    conn.commit()
    conn.close()
    return path


def run(capsys, *paths):
    code = script.main([str(p) for p in paths])
    return code, capsys.readouterr()


def test_qa_pr_01_planted_keys_are_found_and_not_printed(tmp_path, capsys):
    db = sqlite_file(
        tmp_path / "evidence.db",
        [
            (1, '{"status": "ok"}', None),
            (2, f'{{"reason": "key {OPENROUTER}"}}', None),
            (3, "{}", b"\x80\x04 checkpoint Bearer abcdef123456 \xff"),
        ],
    )
    log = tmp_path / "control-api.log"
    log.write_text("started\nGET /runs 200\npassword=hunter2hunter2 in a debug line\n")

    code, out = run(capsys, db, log)

    assert code == 1
    assert f"{db}: table records, row 2, column payload: openrouter_key" in out.out
    assert f"{db}: table records, row 3, column blob: bearer_token" in out.out
    assert f"{log}: line 3: secret_assignment" in out.out
    assert "checked 2 files, 3 rows, 3 lines: 3 hits" in out.out
    everything = out.out + out.err
    assert OPENROUTER not in everything
    assert "abcdef123456" not in everything and "hunter2hunter2" not in everything


def test_qa_pr_01_exact_value_of_a_host_secret_is_found(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CONTROL_API_TOKEN", TOKEN_VALUE)
    log = tmp_path / "runner.log"
    log.write_text(f"curl -H X-Token:{TOKEN_VALUE} http://127.0.0.1:8000/runs\n")

    code, out = run(capsys, log)

    assert code == 1
    assert "line 1: value of CONTROL_API_TOKEN" in out.out
    assert TOKEN_VALUE not in out.out + out.err


def test_qa_pr_01_clean_files_pass(tmp_path, capsys):
    db = sqlite_file(tmp_path / "evidence.db", [(1, '{"reason": "token=[REDACTED]"}', b"\x00")])
    log = tmp_path / "control-api.log"
    log.write_text("started\nrun abc: DENY (test_failed)\n")

    code, out = run(capsys, db, log)

    assert code == 0
    assert out.out.strip().endswith("checked 2 files, 1 rows, 2 lines: 0 hits")


def test_a_directory_is_searched_and_a_missing_path_is_an_error(tmp_path, capsys):
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "a.log").write_text("fine\n")
    (tmp_path / "logs" / "b.log").write_text(f"oops {OPENROUTER}\n")

    code, out = run(capsys, tmp_path / "logs", tmp_path / "missing.db")

    assert code == 1  # a hit outranks the read error
    assert "b.log: line 1: openrouter_key" in out.out
    assert "missing.db: no such file" in out.err

    code, _ = run(capsys, tmp_path / "logs" / "a.log", tmp_path / "missing.db")
    assert code == 2  # nothing found, but not everything could be read


def test_qa_pr_01_real_pipeline_records_are_clean(tmp_path, capsys):
    """The evidence and checkpoint files of real runs (allowed, denied, escalated and
    approved) give no false alarm, so a hit in Phase 8 means a real problem."""
    world = World()
    pipeline = Pipeline(tmp_path, world, FakeDocker(), Checker(), RecordingNotifier())
    pipeline.start(sha="a" * 40)
    world.bandit = ScanOutput(findings=[HIGH])
    pipeline.start(sha="b" * 40)
    world.bandit = ScanOutput(findings=[MEDIUM])
    run_c, _ = pipeline.start(sha="c" * 40)
    pipeline.answer(run_c, Verdict.APPROVE)

    code, out = run(capsys, tmp_path / "evidence.db", tmp_path / "checkpoints.db")

    assert code == 0, out.out
    assert " 0 hits" in out.out
