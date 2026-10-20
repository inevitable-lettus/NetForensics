from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from backend.db.case_repository import SqliteCaseRepository
from backend.db.interfaces import CaseExistsError, CaseNotFoundError
from backend.pipeline import analyze_pcap
from tests.fixtures.packets import syn_frame, write_timed_pcap


def _record(tmp_path: Path, case_id: str = "a" * 32):
    packets = [
        (1_700_000_000.0 + i * 60, syn_frame("10.0.0.5", "203.0.113.7", 40000 + i, 443))
        for i in range(12)
    ]
    return analyze_pcap(case_id, str(write_timed_pcap(tmp_path / "b.pcap", packets)))


def test_save_load_roundtrip_preserves_record(tmp_path: Path):
    repo = SqliteCaseRepository(tmp_path / "nf.sqlite")
    record = _record(tmp_path)
    repo.save(record)
    assert repo.load(record.case_id) == record


def test_case_records_are_write_once(tmp_path: Path):
    repo = SqliteCaseRepository(tmp_path / "nf.sqlite")
    record = _record(tmp_path)
    repo.save(record)
    with pytest.raises(CaseExistsError):
        repo.save(record)


def test_database_rejects_update_and_delete_of_cases(tmp_path: Path):
    db_path = tmp_path / "nf.sqlite"
    SqliteCaseRepository(db_path).save(_record(tmp_path))
    with sqlite3.connect(db_path) as connection:
        for statement in ("UPDATE cases SET record_json = '{}'", "DELETE FROM cases"):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute(statement)


def test_unknown_and_malformed_ids_not_found(tmp_path: Path):
    repo = SqliteCaseRepository(tmp_path / "nf.sqlite")
    for bad in ("b" * 32, "../etc", "A" * 32, ""):
        with pytest.raises(CaseNotFoundError):
            repo.load(bad)


def test_opening_repository_creates_no_files(tmp_path: Path):
    repo = SqliteCaseRepository(tmp_path / "sub" / "nf.sqlite")
    assert repo and not (tmp_path / "sub").exists()
