from __future__ import annotations

from pathlib import Path

import pytest

from backend.db.case_store import CaseNotFoundError, CaseStore
from backend.pipeline import analyze_pcap
from tests.fixtures.packets import syn_frame, write_timed_pcap


def _record(tmp_path: Path):
    packets = [
        (1_700_000_000.0 + i * 60, syn_frame("10.0.0.5", "203.0.113.7", 40000 + i, 443))
        for i in range(12)
    ]
    return analyze_pcap("a" * 32, str(write_timed_pcap(tmp_path / "b.pcap", packets)))


def test_save_load_roundtrip_preserves_record(tmp_path: Path):
    store = CaseStore(tmp_path / "store")
    record = _record(tmp_path)
    store.write_upload(record.case_id, "b.pcap", iter([b"x", b""]).__next__, 10)
    store.save(record)
    assert store.load(record.case_id) == record


def test_traversal_ids_rejected(tmp_path: Path):
    store = CaseStore(tmp_path)
    for bad in ("../etc", "a" * 31, "A" * 32, ""):
        with pytest.raises(CaseNotFoundError):
            store.case_dir(bad)


def test_unknown_case_not_found(tmp_path: Path):
    with pytest.raises(CaseNotFoundError):
        CaseStore(tmp_path).load("b" * 32)


def test_upload_over_limit_raises(tmp_path: Path):
    chunks = iter([b"x" * 6, b"x" * 6, b""])
    with pytest.raises(ValueError, match="limit"):
        CaseStore(tmp_path).write_upload("c" * 32, "b.pcap", chunks.__next__, 10)


def test_upload_filename_cannot_escape_case_dir(tmp_path: Path):
    store = CaseStore(tmp_path)
    path = store.write_upload("d" * 32, "../../evil.pcap", iter([b"x", b""]).__next__, 10)
    assert path.parent == store.case_dir("d" * 32)


def test_discard_removes_case_dir(tmp_path: Path):
    store = CaseStore(tmp_path)
    store.write_upload("e" * 32, "b.pcap", iter([b"x", b""]).__next__, 10)
    store.discard("e" * 32)
    assert not store.case_dir("e" * 32).exists()
