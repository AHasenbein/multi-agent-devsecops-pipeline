"""Append-only, hash-chained evidence store on SQLite (FR19).

The public surface is ``append``, ``get_run``, ``list_runs`` and ``verify_chain``. There is
no update or delete. SQLite triggers abort UPDATE and DELETE as defense in depth, and every
row stores ``hash = sha256(prev_hash + canonical_json(row))`` so edits are detectable.

Limitation (CLAUDE.md §11 item 8): someone with write access to the database file can drop
the triggers and rebuild the whole chain. File permissions are the control for that.
"""

import hashlib
import json
import os
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from devsecops.models import EventType, RunRecord, utc_now

GENESIS_HASH = "0" * 64
_TABLE = "evidence"
_TRIGGERS = ("evidence_no_update", "evidence_no_delete")

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {_TABLE} (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS evidence_run_id ON {_TABLE} (run_id, seq);
CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON {_TABLE}
BEGIN
    SELECT RAISE(ABORT, 'evidence is append-only: UPDATE is not allowed');
END;
CREATE TRIGGER IF NOT EXISTS evidence_no_delete BEFORE DELETE ON {_TABLE}
BEGIN
    SELECT RAISE(ABORT, 'evidence is append-only: DELETE is not allowed');
END;
"""

_COLUMNS = "seq, run_id, event_type, payload_json, created_at, prev_hash, hash"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(
    prev_hash: str, seq: int, run_id: str, event_type: str, payload_json: str, created_at: str
) -> str:
    row = {
        "seq": seq,
        "run_id": run_id,
        "event_type": event_type,
        "payload_json": payload_json,
        "created_at": created_at,
    }
    return hashlib.sha256((prev_hash + canonical_json(row)).encode("utf-8")).hexdigest()


class ChainVerification(BaseModel):
    ok: bool
    records_checked: int
    first_bad_seq: int | None = None
    error: str | None = None


class RunIndexEntry(BaseModel):
    run_id: str
    started_at: str
    last_event_type: str
    last_event_at: str
    record_count: int


class EvidenceStore:
    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        is_new = not self._path.exists()
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
        if is_new:
            os.chmod(self._path, 0o600)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        # One short-lived connection per operation: safe across threads and processes.
        conn = sqlite3.connect(self._path, timeout=30, isolation_level=None)
        try:
            yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------------ write

    def append(
        self, run_id: str, event_type: EventType | str, payload: BaseModel | Mapping[str, Any]
    ) -> RunRecord:
        if not run_id:
            raise ValueError("run_id is required")
        event = EventType(event_type)
        if isinstance(payload, BaseModel):
            payload = payload.model_dump(mode="json")
        elif not isinstance(payload, Mapping):
            raise TypeError("payload must be a mapping or a Pydantic model")
        payload_json = canonical_json(payload)
        created_at = utc_now().isoformat()

        with self._connect() as conn:
            # IMMEDIATE takes the write lock first, so concurrent runs cannot fork the chain.
            conn.execute("BEGIN IMMEDIATE")
            try:
                last = conn.execute(
                    f"SELECT seq, hash FROM {_TABLE} ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                seq = (last[0] + 1) if last else 1
                prev_hash = last[1] if last else GENESIS_HASH
                row_hash = compute_hash(
                    prev_hash, seq, run_id, event.value, payload_json, created_at
                )
                conn.execute(
                    f"INSERT INTO {_TABLE} ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (seq, run_id, event.value, payload_json, created_at, prev_hash, row_hash),
                )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise

        return RunRecord(
            seq=seq,
            run_id=run_id,
            event_type=event,
            payload_json=payload_json,
            created_at=created_at,
            prev_hash=prev_hash,
            hash=row_hash,
        )

    # ------------------------------------------------------------------ read

    def get_run(self, run_id: str) -> list[RunRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {_COLUMNS} FROM {_TABLE} WHERE run_id = ? ORDER BY seq", (run_id,)
            ).fetchall()
        return [_to_record(row) for row in rows]

    def list_runs(self) -> list[RunIndexEntry]:
        """One entry per run, newest first."""
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT head.run_id, head.created_at, tail.event_type, tail.created_at, agg.n
                FROM (SELECT run_id, MIN(seq) AS lo, MAX(seq) AS hi, COUNT(*) AS n
                      FROM {_TABLE} GROUP BY run_id) AS agg
                JOIN {_TABLE} AS head ON head.seq = agg.lo
                JOIN {_TABLE} AS tail ON tail.seq = agg.hi
                ORDER BY agg.lo DESC
                """
            ).fetchall()
        return [
            RunIndexEntry(
                run_id=row[0],
                started_at=row[1],
                last_event_type=row[2],
                last_event_at=row[3],
                record_count=row[4],
            )
            for row in rows
        ]

    def verify_chain(self) -> ChainVerification:
        """Recompute every hash from the first row. Detects edited, removed and reordered rows."""
        with self._connect() as conn:
            rows = conn.execute(f"SELECT {_COLUMNS} FROM {_TABLE} ORDER BY seq").fetchall()
            high_water = conn.execute(
                "SELECT seq FROM sqlite_sequence WHERE name = ?", (_TABLE,)
            ).fetchone()
            triggers = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?",
                    (_TABLE,),
                )
            }

        prev_hash = GENESIS_HASH
        for index, (
            seq,
            run_id,
            event_type,
            payload_json,
            created_at,
            stored_prev,
            stored,
        ) in enumerate(rows, start=1):
            if seq != index:
                return _bad(index - 1, seq, f"expected seq {index}, found {seq}: a row is missing")
            if stored_prev != prev_hash:
                return _bad(index - 1, seq, "prev_hash does not match the previous row")
            if compute_hash(prev_hash, seq, run_id, event_type, payload_json, created_at) != stored:
                return _bad(index - 1, seq, "hash does not match the row contents")
            prev_hash = stored

        # AUTOINCREMENT remembers the highest seq ever written, which exposes a deleted tail.
        highest_ever = high_water[0] if high_water else 0
        if highest_ever != len(rows):
            return _bad(
                len(rows),
                len(rows) + 1,
                f"{highest_ever} row(s) were written but {len(rows)} remain: the tail was removed",
            )
        missing = sorted(set(_TRIGGERS) - triggers)
        if missing:
            return ChainVerification(
                ok=False,
                records_checked=len(rows),
                error=f"append-only trigger(s) missing: {', '.join(missing)}",
            )
        return ChainVerification(ok=True, records_checked=len(rows))


def _bad(checked: int, seq: int, error: str) -> ChainVerification:
    return ChainVerification(ok=False, records_checked=checked, first_bad_seq=seq, error=error)


def _to_record(row: tuple) -> RunRecord:
    return RunRecord(
        seq=row[0],
        run_id=row[1],
        event_type=row[2],
        payload_json=row[3],
        created_at=row[4],
        prev_hash=row[5],
        hash=row[6],
    )
