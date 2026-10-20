"""SQLite connection + schema for the case and custody tables.

Append-only is enforced *inside the database* by triggers that abort any UPDATE or
DELETE, so no code path (ours or a future one) can edit history by accident.

Honest limit: triggers guard against application mistakes, not against someone
with write access to the .sqlite file — they can drop a trigger or edit bytes
directly. Detecting *that* is the job of the hash chain and its anchoring (core
evidence layer), which is why storage never has to be trusted.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id     TEXT PRIMARY KEY,
    pcap_hash   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS cases_pcap_hash ON cases (pcap_hash);

CREATE TABLE IF NOT EXISTS custody_entries (
    case_id      TEXT    NOT NULL,
    idx          INTEGER NOT NULL CHECK (idx >= 0),
    timestamp    TEXT    NOT NULL,
    event_type   TEXT    NOT NULL,
    detail       TEXT    NOT NULL,
    prev_hash    TEXT    NOT NULL,
    entry_hash   TEXT    NOT NULL,
    payload_json TEXT    NOT NULL,
    PRIMARY KEY (case_id, idx)
);
"""

_APPEND_ONLY_TABLES = ("cases", "custody_entries")


def _append_only_triggers() -> str:
    statements = []
    for table in _APPEND_ONLY_TABLES:
        for action in ("UPDATE", "DELETE"):
            statements.append(
                f"CREATE TRIGGER IF NOT EXISTS {table}_no_{action.lower()} "
                f"BEFORE {action} ON {table} "
                f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END;"
            )
    return "\n".join(statements)


_initialized: set[Path] = set()


def _initialize(connection: sqlite3.Connection, db_path: Path) -> None:
    """Create tables and append-only triggers on first use of a database file.
    Lazy, so importing the API module never creates files as a side effect."""
    if db_path in _initialized:
        return
    connection.executescript(_SCHEMA + _append_only_triggers())
    _initialized.add(db_path)


@contextmanager
def connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    """One short-lived connection per operation (FastAPI runs sync routes on a
    thread pool, and sqlite3 connections must not cross threads). Autocommit
    mode, so callers open explicit transactions where they need atomicity."""
    db_path = db_path.resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path, isolation_level=None)
    try:
        _initialize(connection, db_path)
        yield connection
    finally:
        connection.close()
