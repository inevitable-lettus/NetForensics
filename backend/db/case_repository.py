"""SQLite-backed, write-once case records (replaces the interim JSON-per-case store).

A case is three tables written in one transaction: `cases` (one row), `seals` (one
row, every `SealRecord` field) and `findings` (one row per finding, in pipeline
order). After that the only permitted change is `record_timestamp` — the seal's
single PENDING -> GRANTED transition, which a database trigger also enforces.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from backend.db import sqlite_db
from backend.db.case_rows import (
    FINDING_COLUMNS,
    SEAL_COLUMNS,
    finding_from_row,
    finding_to_row,
    seal_from_row,
    seal_to_row,
)
from backend.db.interfaces import (
    CaseExistsError,
    CaseNotFoundError,
    SealUpdateError,
    validate_case_id,
)
from backend.models import CaseRecord


class SqliteCaseRepository:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def save(self, record: CaseRecord) -> None:
        validate_case_id(record.case_id)
        with sqlite_db.connect(self.db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._insert_case(connection, record)
                connection.execute("COMMIT")
            except sqlite3.IntegrityError as error:
                connection.execute("ROLLBACK")
                raise CaseExistsError(record.case_id) from error
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def load(self, case_id: str) -> CaseRecord:
        validate_case_id(case_id)
        with sqlite_db.connect(self.db_path) as connection:
            case_row = connection.execute(
                "SELECT flow_count FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            if case_row is None:
                raise CaseNotFoundError(case_id)
            seal_row = connection.execute(
                f"SELECT {SEAL_COLUMNS} FROM seals WHERE case_id = ?", (case_id,)
            ).fetchone()
            finding_rows = connection.execute(
                f"SELECT {FINDING_COLUMNS} FROM findings WHERE case_id = ? ORDER BY position",
                (case_id,),
            ).fetchall()
        return CaseRecord(
            case_id=case_id,
            seal=seal_from_row(seal_row),
            findings=tuple(finding_from_row(row) for row in finding_rows),
            flow_count=case_row[0],
        )

    def record_timestamp(
        self, case_id: str, token: bytes, gen_time: datetime, tsa_url: str
    ) -> None:
        """Store a TSA token for a PENDING seal. Validating the token is the core
        timestamp module's job; this only persists it, once."""
        validate_case_id(case_id)
        if not token:
            raise SealUpdateError(f"Case {case_id}: an empty token is not a timestamp.")
        with sqlite_db.connect(self.db_path) as connection:
            try:
                cursor = connection.execute(
                    "UPDATE seals SET timestamp_status = 'granted', rfc3161_token = ?,"
                    " timestamp_gen_time = ?, tsa_url = ? WHERE case_id = ?",
                    (token, gen_time.isoformat(), tsa_url, case_id),
                )
            except sqlite3.IntegrityError as error:
                raise SealUpdateError(f"Case {case_id}: {error}") from error
        if cursor.rowcount == 0:
            raise CaseNotFoundError(case_id)

    def pending_timestamp_case_ids(self) -> tuple[str, ...]:
        """Cases whose seal still waits for a TSA token, oldest first."""
        with sqlite_db.connect(self.db_path) as connection:
            rows = connection.execute(
                "SELECT seals.case_id FROM seals JOIN cases USING (case_id)"
                " WHERE timestamp_status = 'pending' ORDER BY cases.created_at, case_id"
            ).fetchall()
        return tuple(row[0] for row in rows)

    @staticmethod
    def _insert_case(connection: sqlite3.Connection, record: CaseRecord) -> None:
        connection.execute(
            "INSERT INTO cases (case_id, flow_count, created_at) VALUES (?, ?, ?)",
            (record.case_id, record.flow_count, datetime.now(timezone.utc).isoformat()),
        )
        connection.execute(
            f"INSERT INTO seals ({SEAL_COLUMNS}) VALUES ({', '.join('?' * 11)})",
            seal_to_row(record.case_id, record.seal),
        )
        connection.executemany(
            f"INSERT INTO findings ({FINDING_COLUMNS}) VALUES ({', '.join('?' * 8)})",
            [
                finding_to_row(record.case_id, position, finding)
                for position, finding in enumerate(record.findings)
            ],
        )
