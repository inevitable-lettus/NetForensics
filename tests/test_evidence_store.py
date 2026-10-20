from __future__ import annotations

import stat
from pathlib import Path

import pytest

from backend.db.evidence_store import ContentAddressedEvidenceStore, EvidenceNotFoundError
from backend.db.interfaces import CaseNotFoundError

CASE = "e" * 32
DIGEST = "ab" + "0" * 62


def _chunks(*parts: bytes):
    return iter([*parts, b""]).__next__


def test_commit_moves_upload_to_read_only_content_address(tmp_path: Path):
    store = ContentAddressedEvidenceStore(tmp_path)
    staged = store.stage_upload(CASE, "b.pcap", _chunks(b"pcap-bytes"), 100)
    stored = store.commit(staged, DIGEST)
    assert stored == tmp_path / "objects" / "ab" / DIGEST
    assert stored.read_bytes() == b"pcap-bytes"
    assert not stat.S_IMODE(stored.stat().st_mode) & 0o222
    assert store.path_for(DIGEST) == stored
    assert not staged.parent.exists()


def test_duplicate_evidence_keeps_single_object(tmp_path: Path):
    store = ContentAddressedEvidenceStore(tmp_path)
    store.commit(store.stage_upload(CASE, "b.pcap", _chunks(b"x"), 10), DIGEST)
    other = "f" * 32
    store.commit(store.stage_upload(other, "b.pcap", _chunks(b"x"), 10), DIGEST)
    assert list((tmp_path / "objects" / "ab").iterdir()) == [store.path_for(DIGEST)]
    assert not (tmp_path / "staging" / other).exists()


def test_upload_over_limit_raises_and_discard_cleans_up(tmp_path: Path):
    store = ContentAddressedEvidenceStore(tmp_path)
    with pytest.raises(ValueError, match="limit"):
        store.stage_upload(CASE, "b.pcap", _chunks(b"x" * 6, b"x" * 6), 10)
    store.discard_staged(CASE)
    assert not (tmp_path / "staging" / CASE).exists()


def test_upload_filename_cannot_escape_staging(tmp_path: Path):
    store = ContentAddressedEvidenceStore(tmp_path)
    path = store.stage_upload(CASE, "../../evil.pcap", _chunks(b"x"), 10)
    assert path == tmp_path / "staging" / CASE / "evil.pcap"


def test_bad_case_ids_and_digests_rejected(tmp_path: Path):
    store = ContentAddressedEvidenceStore(tmp_path)
    with pytest.raises(CaseNotFoundError):
        store.stage_upload("../x", "b.pcap", _chunks(b"x"), 10)
    for bad in ("../" + "0" * 61, "AB" + "0" * 62, "0" * 63):
        with pytest.raises(ValueError):
            store.path_for(bad)


def test_commit_refuses_files_outside_staging(tmp_path: Path):
    store = ContentAddressedEvidenceStore(tmp_path / "store")
    outside = tmp_path / "loose.pcap"
    outside.write_bytes(b"x")
    with pytest.raises(ValueError, match="not a staged upload"):
        store.commit(outside, DIGEST)


def test_missing_evidence_not_found(tmp_path: Path):
    with pytest.raises(EvidenceNotFoundError):
        ContentAddressedEvidenceStore(tmp_path).path_for(DIGEST)
