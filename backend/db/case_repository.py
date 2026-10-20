"""SQLite-backed, write-once case records (replaces the interim JSON-per-case store).

The full `CaseRecord` is stored as JSON through the one serialization path the API
also uses, so the stored and on-wire shapes cannot drift. `pcap_hash` is copied
into its own column so cases can be looked up by evidence digest.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from backend.db import sqlite_db
from backend.db.interfaces import CaseExistsError, CaseNotFoundError, validate_case_id
from backend.db.serialization import case_from_dict, to_jsonable
from backend.models import CaseRecord


class SqliteCaseRepository:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def save(self, record: CaseRecord) -> None:
        validate_case_id(record.case_id)
        row = (
            record.case_id,
            record.seal.pcap_hash,
            datetime.now(timezone.utc).isoformat(),
            json.dumps(to_jsonable(record)),
        )
        with sqlite_db.connect(self.db_path) as connection:
            try:
                connection.execute(
                    "INSERT INTO cases (case_id, pcap_hash, created_at, record_json)"
                    " VALUES (?, ?, ?, ?)",
                    row,
                )
            except sqlite3.IntegrityError as error:
                raise CaseExistsError(record.case_id) from error

    def load(self, case_id: str) -> CaseRecord:
        validate_case_id(case_id)
        with sqlite_db.connect(self.db_path) as connection:
            row = connection.execute(
                "SELECT record_json FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()
        if row is None:
            raise CaseNotFoundError(case_id)
        return case_from_dict(json.loads(row[0]))
