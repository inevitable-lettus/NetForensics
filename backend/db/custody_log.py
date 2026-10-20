"""SQLite-backed append-only custody log.

Stores `CustodyEntry` values exactly as the core custody module built them. The
only rule enforced here is positional: an entry's index must be the next free slot
for its case, checked and inserted inside one write-locked transaction so two
concurrent writers cannot both claim the same slot. Hash linkage is deliberately
NOT checked here (see `CustodyLog` in `interfaces.py`).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from backend.db import sqlite_db
from backend.db.interfaces import CustodyAppendError, validate_case_id
from backend.models import CustodyEntry

_COLUMNS = "case_id, idx, timestamp, event_type, detail, prev_hash, entry_hash, payload_json"


class SqliteCustodyLog:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def append(self, entry: CustodyEntry) -> None:
        validate_case_id(entry.case_id)
        _require_json_round_trip(entry)
        with sqlite_db.connect(self.db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")  # take the write lock before reading
            try:
                self._check_next_index(connection, entry)
                connection.execute(
                    f"INSERT INTO custody_entries ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    _to_row(entry),
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def entries(self, case_id: str) -> tuple[CustodyEntry, ...]:
        validate_case_id(case_id)
        with sqlite_db.connect(self.db_path) as connection:
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM custody_entries WHERE case_id = ? ORDER BY idx",
                (case_id,),
            ).fetchall()
        return tuple(_from_row(row) for row in rows)

    def head(self, case_id: str) -> CustodyEntry | None:
        validate_case_id(case_id)
        with sqlite_db.connect(self.db_path) as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM custody_entries WHERE case_id = ?"
                " ORDER BY idx DESC LIMIT 1",
                (case_id,),
            ).fetchone()
        return _from_row(row) if row is not None else None

    @staticmethod
    def _check_next_index(connection: sqlite3.Connection, entry: CustodyEntry) -> None:
        (count,) = connection.execute(
            "SELECT COUNT(*) FROM custody_entries WHERE case_id = ?", (entry.case_id,)
        ).fetchone()
        if entry.index != count:
            raise CustodyAppendError(
                f"Case {entry.case_id} has {count} custody entries; "
                f"the next entry must have index {count}, got {entry.index}."
            )


def _require_json_round_trip(entry: CustodyEntry) -> None:
    """Refuse a payload that would read back different from what was given (tuple ->
    list, int key -> str key, NaN): its hash could never be re-verified from storage."""
    try:
        restored = json.loads(json.dumps(entry.payload, allow_nan=False))
    except (TypeError, ValueError) as error:
        raise CustodyAppendError(f"Payload is not JSON-storable: {error}") from error
    if restored != entry.payload:
        raise CustodyAppendError(
            "Payload would not read back identically from JSON (tuples, non-string keys "
            "or other non-JSON types); store lists, string keys and JSON scalars only."
        )


def _to_row(entry: CustodyEntry) -> tuple[object, ...]:
    return (
        entry.case_id,
        entry.index,
        entry.timestamp.isoformat(),
        entry.event_type,
        entry.detail,
        entry.prev_hash,
        entry.entry_hash,
        json.dumps(entry.payload),
    )


def _from_row(row: tuple[object, ...]) -> CustodyEntry:
    case_id, index, timestamp, event_type, detail, prev_hash, entry_hash, payload = row
    return CustodyEntry(
        case_id=str(case_id),
        index=int(index),
        timestamp=datetime.fromisoformat(str(timestamp)),
        event_type=str(event_type),
        detail=str(detail),
        prev_hash=str(prev_hash),
        entry_hash=str(entry_hash),
        payload=json.loads(str(payload)),
    )
