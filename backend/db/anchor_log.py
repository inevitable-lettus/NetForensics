"""SQLite-backed append-only store of chain-head anchors (see `AnchorLog`). Stores
`ChainAnchor` values exactly as `backend/evidence/anchor.py` built them; it never
checks a token or a hash — verification does that."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from backend.db import sqlite_db
from backend.db.interfaces import validate_case_id
from backend.models import ChainAnchor, TimestampStatus

_COLUMNS = ("case_id, head_index, head_hash, anchored_at, timestamp_status, rfc3161_token,"
            " timestamp_gen_time, tsa_url")


class SqliteAnchorLog:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def append(self, anchor: ChainAnchor) -> None:
        validate_case_id(anchor.case_id)
        gen_time = anchor.timestamp_gen_time
        with sqlite_db.connect(self.db_path) as connection:
            connection.execute(
                f"INSERT INTO chain_anchors ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (anchor.case_id, anchor.head_index, anchor.head_hash,
                 anchor.anchored_at.isoformat(), anchor.timestamp_status.value,
                 anchor.rfc3161_token, gen_time.isoformat() if gen_time else None,
                 anchor.tsa_url),
            )

    def anchors(self, case_id: str) -> tuple[ChainAnchor, ...]:
        validate_case_id(case_id)
        with sqlite_db.connect(self.db_path) as connection:
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM chain_anchors WHERE case_id = ? ORDER BY head_index",
                (case_id,),
            ).fetchall()
        return tuple(_from_row(row) for row in rows)


def _from_row(row: tuple[object, ...]) -> ChainAnchor:
    case_id, index, head_hash, anchored_at, status, token, gen_time, tsa_url = row
    return ChainAnchor(
        case_id=str(case_id),
        head_index=int(index),
        head_hash=str(head_hash),
        anchored_at=datetime.fromisoformat(str(anchored_at)),
        timestamp_status=TimestampStatus(status),
        rfc3161_token=bytes(token) if token is not None else None,
        timestamp_gen_time=datetime.fromisoformat(str(gen_time)) if gen_time else None,
        tsa_url=str(tsa_url) if tsa_url is not None else None,
    )
