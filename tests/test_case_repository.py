from __future__ import annotations

import dataclasses
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from backend.db.case_repository import SqliteCaseRepository
from backend.db.interfaces import CaseExistsError, CaseNotFoundError, SealUpdateError
from backend.models import CaseRecord, TimestampStatus
from backend.pipeline import analyze_pcap
from tests.fixtures.packets import syn_frame, write_timed_pcap

GEN_TIME = datetime(2026, 10, 20, 12, 0, 5, tzinfo=timezone.utc)
TSA = "https://freetsa.org/tsr"


def _record(tmp_path: Path, case_id: str = "a" * 32) -> CaseRecord:
    packets = [
        (1_700_000_000.0 + i * 60, syn_frame("10.0.0.5", "203.0.113.7", 40000 + i, 443))
        for i in range(12)
    ]
    return analyze_pcap(case_id, str(write_timed_pcap(tmp_path / "b.pcap", packets)))


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "nf.sqlite"


def test_save_load_roundtrip_preserves_record(tmp_path: Path, db_path: Path):
    repo = SqliteCaseRepository(db_path)
    record = _record(tmp_path)
    assert record.findings, "fixture should produce at least one finding"
    repo.save(record)
    assert repo.load(record.case_id) == record


def test_roundtrip_preserves_granted_seal_token_bytes(tmp_path: Path, db_path: Path):
    record = _record(tmp_path)
    granted = dataclasses.replace(
        record.seal,
        timestamp_status=TimestampStatus.GRANTED,
        rfc3161_token=bytes(range(256)),
        timestamp_gen_time=GEN_TIME,
        tsa_url=TSA,
    )
    record = dataclasses.replace(record, seal=granted)
    repo = SqliteCaseRepository(db_path)
    repo.save(record)
    assert repo.load(record.case_id) == record


def test_case_records_are_write_once(tmp_path: Path, db_path: Path):
    repo = SqliteCaseRepository(db_path)
    record = _record(tmp_path)
    repo.save(record)
    with pytest.raises(CaseExistsError):
        repo.save(record)
    assert repo.load(record.case_id) == record


def test_pending_seal_can_be_granted_exactly_once(tmp_path: Path, db_path: Path):
    repo = SqliteCaseRepository(db_path)
    record = _record(tmp_path)
    repo.save(record)
    repo.record_timestamp(record.case_id, b"\x30\x82token", GEN_TIME, TSA)
    seal = repo.load(record.case_id).seal
    assert seal.timestamp_status is TimestampStatus.GRANTED
    assert (seal.rfc3161_token, seal.timestamp_gen_time, seal.tsa_url) == (
        b"\x30\x82token", GEN_TIME, TSA,
    )
    with pytest.raises(SealUpdateError, match="PENDING -> GRANTED"):
        repo.record_timestamp(record.case_id, b"second", GEN_TIME, TSA)


def test_record_timestamp_on_unknown_case_not_found(db_path: Path):
    with pytest.raises(CaseNotFoundError):
        SqliteCaseRepository(db_path).record_timestamp("b" * 32, b"t", GEN_TIME, TSA)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE seals SET pcap_hash = 'forged'",
        "UPDATE seals SET sha256_hash = 'forged', timestamp_status = 'granted',"
        " rfc3161_token = x'00', timestamp_gen_time = 't', tsa_url = 'u'",
        "UPDATE seals SET timestamp_status = 'granted'",  # no token
        "UPDATE seals SET timestamp_status = 'granted', rfc3161_token = NULL,"
        " timestamp_gen_time = 't', tsa_url = 'u'",  # NULL token: length() is NULL
        "UPDATE seals SET timestamp_status = 'granted', rfc3161_token = x'',"
        " timestamp_gen_time = 't', tsa_url = 'u'",  # empty token
        "DELETE FROM seals",
        "UPDATE cases SET flow_count = 0",
        "DELETE FROM cases",
        "UPDATE findings SET evidence = 'rewritten'",
        "DELETE FROM findings",
    ],
)
def test_database_rejects_direct_edits(tmp_path: Path, db_path: Path, statement: str):
    SqliteCaseRepository(db_path).save(_record(tmp_path))
    with sqlite3.connect(db_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only|immutable"):
            connection.execute(statement)


def test_unknown_and_malformed_ids_not_found(db_path: Path):
    repo = SqliteCaseRepository(db_path)
    for bad in ("b" * 32, "../etc", "A" * 32, ""):
        with pytest.raises(CaseNotFoundError):
            repo.load(bad)


def test_opening_repository_creates_no_files(tmp_path: Path):
    SqliteCaseRepository(tmp_path / "sub" / "nf.sqlite")
    assert not (tmp_path / "sub").exists()


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT OR REPLACE INTO cases (case_id, flow_count, created_at)"
        " VALUES ('{c}', 0, 'forged')",
        "REPLACE INTO seals SELECT case_id, pcap_filename, pcap_size_bytes, hash_algorithm,"
        " 'forged', sha256_hash, received_at, timestamp_status, rfc3161_token,"
        " timestamp_gen_time, tsa_url FROM seals",
        "INSERT OR REPLACE INTO findings SELECT case_id, position, detector, what, why,"
        " supporting_data_json, 'rewritten', severity FROM findings",
    ],
    ids=["cases", "seals", "findings"],
)
def test_insert_or_replace_cannot_overwrite_rows(tmp_path: Path, db_path: Path, statement: str):
    record = _record(tmp_path)
    repo = SqliteCaseRepository(db_path)
    repo.save(record)
    with sqlite3.connect(db_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="row already exists"):
            connection.execute(statement.format(c=record.case_id))
    assert repo.load(record.case_id) == record


def test_empty_token_is_not_a_timestamp(tmp_path: Path, db_path: Path):
    repo = SqliteCaseRepository(db_path)
    record = _record(tmp_path)
    repo.save(record)
    with pytest.raises(SealUpdateError, match="empty token"):
        repo.record_timestamp(record.case_id, b"", GEN_TIME, TSA)
    with sqlite3.connect(db_path) as connection:  # the trigger refuses it too
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE seals SET timestamp_status = 'granted', rfc3161_token = x'',"
                " timestamp_gen_time = 't', tsa_url = 'u'"
            )
