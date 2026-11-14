"""Append-only, hash-chained evidence store (FR2, FR19) and QA-SC-01."""

import inspect
import json
import sqlite3
import threading

import pytest

from devsecops.evidence import EvidenceStore
from devsecops.evidence.store import GENESIS_HASH
from devsecops.models import EventType, Outcome, PipelineRun, ReleaseDecision


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "evidence.db"


@pytest.fixture
def store(db_path):
    return EvidenceStore(db_path)


def fill(store: EvidenceStore, run_id: str = "run-1") -> None:
    store.append(run_id, EventType.RUN_STARTED, {"commit_sha": "abc123", "author": "dev"})
    store.append(run_id, EventType.BUILD_RESULT, {"success": True})
    store.append(run_id, EventType.DECISION, {"outcome": "ALLOW"})
    store.append(run_id, EventType.RUN_FINISHED, {"status": "DEPLOYED"})


def tamper(db_path, *statements: str) -> None:
    """What a host admin could do: drop the triggers, edit rows, put the triggers back."""
    conn = sqlite3.connect(db_path)
    triggers = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'trigger'").fetchall()
    conn.execute("DROP TRIGGER evidence_no_update")
    conn.execute("DROP TRIGGER evidence_no_delete")
    for statement in statements:
        conn.execute(statement)
    for (sql,) in triggers:
        conn.execute(sql)
    conn.commit()
    conn.close()


# ------------------------------------------------------------------ append + read


def test_fr2_run_started_record_has_run_id_commit_author_and_start_time(store):
    run = PipelineRun(commit_sha="abc123", branch="main", author="dev", event="push")
    record = store.append(run.run_id, EventType.RUN_STARTED, run)

    payload = json.loads(record.payload_json)
    assert payload["run_id"] == run.run_id
    assert payload["commit_sha"] == "abc123"
    assert payload["author"] == "dev"
    assert payload["started_at"]
    assert record.created_at
    assert store.get_run(run.run_id) == [record]


def test_first_record_links_to_genesis_and_later_records_link_to_the_previous(store):
    fill(store)
    records = store.get_run("run-1")
    assert [r.seq for r in records] == [1, 2, 3, 4]
    assert records[0].prev_hash == GENESIS_HASH
    for previous, current in zip(records, records[1:], strict=False):
        assert current.prev_hash == previous.hash
    assert len({r.hash for r in records}) == 4


def test_accepts_pydantic_models_as_payload(store):
    decision = ReleaseDecision(run_id="run-1", outcome=Outcome.DENY, reason="nope")
    record = store.append("run-1", EventType.DECISION, decision)
    assert json.loads(record.payload_json)["outcome"] == "DENY"


def test_rejects_unknown_event_type_and_bad_payload(store):
    with pytest.raises(ValueError):
        store.append("run-1", "MADE_UP_EVENT", {})
    with pytest.raises(TypeError):
        store.append("run-1", EventType.DECISION, "not a mapping")
    with pytest.raises(ValueError):
        store.append("", EventType.DECISION, {})
    assert store.verify_chain().records_checked == 0


def test_get_run_returns_only_that_run_and_list_runs_summarizes(store):
    fill(store, "run-a")
    store.append("run-b", EventType.RUN_STARTED, {})
    store.append("run-a", EventType.HEALTH_CHECK, {"ok": True})

    assert [r.run_id for r in store.get_run("run-a")] == ["run-a"] * 5
    assert store.get_run("missing") == []

    runs = store.list_runs()
    assert [r.run_id for r in runs] == ["run-b", "run-a"]  # newest first
    assert runs[1].record_count == 5
    assert runs[1].last_event_type == "HEALTH_CHECK"
    assert runs[0].last_event_type == "RUN_STARTED"


def test_records_survive_reopening_the_database(db_path):
    fill(EvidenceStore(db_path))
    reopened = EvidenceStore(db_path)
    reopened.append("run-2", EventType.RUN_STARTED, {})
    assert len(reopened.get_run("run-1")) == 4
    assert reopened.verify_chain().ok
    assert reopened.verify_chain().records_checked == 5


def test_database_file_is_private_to_the_owner(store, db_path):
    assert (db_path.stat().st_mode & 0o777) == 0o600


# ------------------------------------------------------------------ append-only (FR19)


def test_fr19_store_has_no_update_or_delete_method():
    public = {name for name, _ in inspect.getmembers(EvidenceStore) if not name.startswith("_")}
    assert public == {"append", "get_run", "list_runs", "verify_chain"}


def test_fr19_sql_update_is_aborted_by_trigger(store, db_path):
    fill(store)
    conn = sqlite3.connect(db_path)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("UPDATE evidence SET payload_json = '{}' WHERE seq = 3")
    conn.close()
    assert store.verify_chain().ok


def test_fr19_sql_delete_is_aborted_by_trigger(store, db_path):
    fill(store)
    conn = sqlite3.connect(db_path)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM evidence WHERE seq = 3")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM evidence")
    conn.close()
    assert len(store.get_run("run-1")) == 4


# ------------------------------------------------------------------ tamper detection (FR19)


def test_fr19_intact_chain_verifies(store):
    assert store.verify_chain().ok  # empty store
    fill(store)
    result = store.verify_chain()
    assert result.ok
    assert result.records_checked == 4
    assert result.first_bad_seq is None


def test_fr19_edited_payload_is_detected(store, db_path):
    fill(store)
    tamper(db_path, """UPDATE evidence SET payload_json = '{"outcome":"ALLOW!"}' WHERE seq = 3""")
    result = store.verify_chain()
    assert not result.ok
    assert result.first_bad_seq == 3
    assert result.records_checked == 2


@pytest.mark.parametrize("column", ["run_id", "event_type", "created_at"])
def test_fr19_edited_metadata_is_detected(store, db_path, column):
    fill(store)
    tamper(db_path, f"UPDATE evidence SET {column} = 'RUN_FINISHED' WHERE seq = 2")
    result = store.verify_chain()
    assert not result.ok
    assert result.first_bad_seq == 2


def test_fr19_edit_with_recomputed_row_hash_is_detected_by_the_next_link(store, db_path):
    """Rewriting one row's hash to match its new contents breaks the following prev_hash."""
    from devsecops.evidence.store import compute_hash

    fill(store)
    row = store.get_run("run-1")[1]
    forged_payload = '{"success":false}'
    forged_hash = compute_hash(
        row.prev_hash, row.seq, row.run_id, row.event_type, forged_payload, row.created_at
    )
    tamper(
        db_path,
        f"UPDATE evidence SET payload_json = '{forged_payload}', hash = '{forged_hash}' "
        "WHERE seq = 2",
    )
    result = store.verify_chain()
    assert not result.ok
    assert result.first_bad_seq == 3
    assert "prev_hash" in result.error


def test_fr19_deleted_middle_row_is_detected(store, db_path):
    fill(store)
    tamper(db_path, "DELETE FROM evidence WHERE seq = 2")
    result = store.verify_chain()
    assert not result.ok
    assert result.first_bad_seq == 3
    assert "missing" in result.error


def test_fr19_deleted_last_row_is_detected(store, db_path):
    fill(store)
    tamper(db_path, "DELETE FROM evidence WHERE seq = 4")
    result = store.verify_chain()
    assert not result.ok
    assert "tail" in result.error


def test_fr19_removed_triggers_are_reported(store, db_path):
    fill(store)
    conn = sqlite3.connect(db_path)
    conn.execute("DROP TRIGGER evidence_no_delete")
    conn.commit()
    conn.close()
    result = store.verify_chain()
    assert not result.ok
    assert "evidence_no_delete" in result.error


# ------------------------------------------------------------------ concurrency (QA-SC-01)


def test_qa_sc_01_concurrent_runs_keep_one_valid_chain(db_path):
    """5 runs writing at once: every record is saved and the chain does not fork."""
    EvidenceStore(db_path)
    runs, per_run = 5, 20
    errors: list[BaseException] = []

    def worker(run_id: str) -> None:
        try:
            store = EvidenceStore(db_path)
            for i in range(per_run):
                store.append(run_id, EventType.HEALTH_CHECK, {"i": i})
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(f"run-{n}",)) for n in range(runs)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    store = EvidenceStore(db_path)
    result = store.verify_chain()
    assert result.ok, result.error
    assert result.records_checked == runs * per_run
    for n in range(runs):
        records = store.get_run(f"run-{n}")
        assert [json.loads(r.payload_json)["i"] for r in records] == list(range(per_run))
