"""SQLite connection + schema: cases, seals, findings and the custody log.

Append-only is enforced *inside the database* by triggers that abort any UPDATE or
DELETE, so no code path (ours or a future one) can edit history by accident. The one
permitted change is a seal's timestamp going PENDING -> GRANTED, once (TSA retry).

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
    case_id    TEXT PRIMARY KEY,
    flow_count INTEGER NOT NULL,
    created_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS seals (
    case_id            TEXT PRIMARY KEY REFERENCES cases (case_id),
    pcap_filename      TEXT    NOT NULL,
    pcap_size_bytes    INTEGER NOT NULL,
    hash_algorithm     TEXT    NOT NULL,
    pcap_hash          TEXT    NOT NULL,
    sha256_hash        TEXT    NOT NULL,
    received_at        TEXT    NOT NULL,
    timestamp_status   TEXT    NOT NULL CHECK (timestamp_status IN ('pending', 'granted')),
    rfc3161_token      BLOB,
    timestamp_gen_time TEXT,
    tsa_url            TEXT
);
CREATE INDEX IF NOT EXISTS seals_sha256 ON seals (sha256_hash);

CREATE TABLE IF NOT EXISTS findings (
    case_id              TEXT    NOT NULL REFERENCES cases (case_id),
    position             INTEGER NOT NULL CHECK (position >= 0),
    detector             TEXT    NOT NULL,
    what                 TEXT    NOT NULL,
    why                  TEXT    NOT NULL,
    supporting_data_json TEXT    NOT NULL,
    evidence             TEXT    NOT NULL,
    severity             TEXT    NOT NULL,
    PRIMARY KEY (case_id, position)
);

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

_FULLY_APPEND_ONLY = ("cases", "findings", "custody_entries")

# Primary key of every table. `INSERT OR REPLACE` / `REPLACE INTO` resolves a key
# conflict by deleting the old row WITHOUT firing DELETE triggers (SQLite only fires
# them with recursive_triggers on), so a BEFORE INSERT trigger refuses any insert
# whose key already exists — that closes the replace path on every table.
_PRIMARY_KEYS = {
    "cases": ("case_id",),
    "seals": ("case_id",),
    "findings": ("case_id", "position"),
    "custody_entries": ("case_id", "idx"),
}

# A seal may change exactly once: PENDING -> GRANTED, filling the three timestamp
# columns. Every other column must stay byte-identical (IS compares NULL-safely).
_SEAL_IMMUTABLE_COLUMNS = (
    "case_id", "pcap_filename", "pcap_size_bytes", "hash_algorithm",
    "pcap_hash", "sha256_hash", "received_at",
)
SEAL_UPDATE_REJECTED = "seal is immutable except one PENDING -> GRANTED timestamp"


def _no_overwrite_trigger(table: str, key: tuple[str, ...]) -> str:
    match = " AND ".join(f"{column} = NEW.{column}" for column in key)
    return (
        f"CREATE TRIGGER IF NOT EXISTS {table}_no_overwrite BEFORE INSERT ON {table} "
        f"WHEN EXISTS (SELECT 1 FROM {table} WHERE {match}) "
        f"BEGIN SELECT RAISE(ABORT, '{table} is append-only: row already exists'); END;"
    )


def _append_only_triggers() -> str:
    statements = [
        f"CREATE TRIGGER IF NOT EXISTS {table}_no_{action.lower()} "
        f"BEFORE {action} ON {table} "
        f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END;"
        for table in _FULLY_APPEND_ONLY
        for action in ("UPDATE", "DELETE")
    ]
    statements.append(
        "CREATE TRIGGER IF NOT EXISTS seals_no_delete BEFORE DELETE ON seals "
        "BEGIN SELECT RAISE(ABORT, 'seals is append-only'); END;"
    )
    statements.extend(_no_overwrite_trigger(table, key) for table, key in _PRIMARY_KEYS.items())
    unchanged = " AND ".join(f"NEW.{c} IS OLD.{c}" for c in _SEAL_IMMUTABLE_COLUMNS)
    statements.append(
        "CREATE TRIGGER IF NOT EXISTS seals_timestamp_once BEFORE UPDATE ON seals "
        "WHEN NOT (OLD.timestamp_status = 'pending' AND NEW.timestamp_status = 'granted'"
        " AND length(NEW.rfc3161_token) > 0 AND NEW.timestamp_gen_time IS NOT NULL"
        f" AND NEW.tsa_url IS NOT NULL AND {unchanged}) "
        f"BEGIN SELECT RAISE(ABORT, '{SEAL_UPDATE_REJECTED}'); END;"
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
        connection.execute("PRAGMA foreign_keys = ON")
        _initialize(connection, db_path)
        yield connection
    finally:
        connection.close()
