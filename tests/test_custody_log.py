from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from backend.db.custody_log import SqliteCustodyLog
from backend.db.interfaces import CustodyAppendError
from backend.models import CustodyEntry

CASE = "c" * 32


def _entry(index: int, case_id: str = CASE, **payload: object) -> CustodyEntry:
    # Hash fields are opaque placeholders: the log stores them, the core computes them.
    return CustodyEntry(
        case_id=case_id,
        index=index,
        timestamp=datetime(2026, 10, 20, 12, 0, index, tzinfo=timezone.utc),
        event_type="ingest" if index == 0 else "finding",
        detail=f"event {index}",
        prev_hash=f"prev-{index}",
        entry_hash=f"hash-{index}",
        payload=dict(payload),
    )


@pytest.fixture
def log(tmp_path: Path) -> SqliteCustodyLog:
    return SqliteCustodyLog(tmp_path / "nf.sqlite")


def test_entries_roundtrip_in_order(log: SqliteCustodyLog):
    written = [_entry(0, bytes_seen=1024), _entry(1, nested={"ports": [22, 80]})]
    for entry in written:
        log.append(entry)
    assert log.entries(CASE) == tuple(written)
    assert log.head(CASE) == written[-1]


def test_empty_log_has_no_head(log: SqliteCustodyLog):
    assert log.entries(CASE) == ()
    assert log.head(CASE) is None


def test_append_rejects_gap_and_duplicate_index(log: SqliteCustodyLog):
    with pytest.raises(CustodyAppendError, match="index 0"):
        log.append(_entry(1))
    log.append(_entry(0))
    with pytest.raises(CustodyAppendError, match="index 1"):
        log.append(_entry(0))
    assert len(log.entries(CASE)) == 1


def test_logs_are_independent_per_case(log: SqliteCustodyLog):
    log.append(_entry(0))
    log.append(_entry(0, case_id="d" * 32))
    assert len(log.entries(CASE)) == 1


def test_log_does_not_judge_hash_links(log: SqliteCustodyLog):
    """A broken prev_hash is stored as-is: exposing it is verification's job."""
    log.append(_entry(0))
    log.append(_entry(1))  # prev_hash "prev-1" != entry 0's "hash-0"
    assert log.head(CASE).prev_hash == "prev-1"


def test_database_rejects_update_and_delete_of_entries(tmp_path: Path):
    db_path = tmp_path / "nf.sqlite"
    SqliteCustodyLog(db_path).append(_entry(0))
    with sqlite3.connect(db_path) as connection:
        for statement in (
            "UPDATE custody_entries SET detail = 'rewritten'",
            "DELETE FROM custody_entries",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute(statement)
