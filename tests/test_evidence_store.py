from __future__ import annotations

import hashlib
import stat
from pathlib import Path

import pytest

from backend.db.evidence_store import ContentAddressedEvidenceStore, EvidenceNotFoundError
from backend.db.interfaces import CaseNotFoundError, EvidenceMismatchError
from backend.evidence.seal import hash_file

CASE = "e" * 32
DATA = b"pcap-bytes"
DIGEST = hashlib.sha256(DATA).hexdigest()


def _chunks(*parts: bytes):
    return iter([*parts, b""]).__next__


def _stage(store: ContentAddressedEvidenceStore, case_id: str = CASE, data: bytes = DATA):
    return store.stage_upload(case_id, "b.pcap", _chunks(data), 100)


def test_commit_moves_upload_to_read_only_content_address(tmp_path: Path):
    store = ContentAddressedEvidenceStore(tmp_path)
    staged = _stage(store)
    stored = store.commit(staged, DIGEST)
    assert stored == tmp_path / "blobs" / DIGEST
    assert stored.read_bytes() == DATA
    assert not stat.S_IMODE(stored.stat().st_mode) & 0o222
    assert store.path_for(DIGEST) == stored
    assert not staged.parent.exists()


def test_same_bytes_twice_keep_one_blob(tmp_path: Path):
    store = ContentAddressedEvidenceStore(tmp_path)
    store.commit(_stage(store), DIGEST)
    other = "f" * 32
    store.commit(_stage(store, other), DIGEST)
    assert list((tmp_path / "blobs").iterdir()) == [store.path_for(DIGEST)]
    assert not (tmp_path / "staging" / other).exists()


def test_commit_refuses_bytes_that_do_not_match_their_name(tmp_path: Path):
    store = ContentAddressedEvidenceStore(tmp_path)
    staged = _stage(store, data=b"different bytes")
    with pytest.raises(EvidenceMismatchError, match="claimed"):
        store.commit(staged, DIGEST)
    assert not (tmp_path / "blobs" / DIGEST).exists()
    assert not staged.parent.exists()


def test_tampered_blob_is_detectable_by_rehashing(tmp_path: Path):
    store = ContentAddressedEvidenceStore(tmp_path)
    stored = store.commit(_stage(store), DIGEST)
    stored.chmod(0o644)
    stored.write_bytes(b"Pcap-bytes")  # one byte flipped
    assert hash_file(str(store.path_for(DIGEST))).sha256_hex != DIGEST


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
    outside.write_bytes(DATA)
    with pytest.raises(ValueError, match="not a staged upload"):
        store.commit(outside, DIGEST)
    assert outside.exists()


def test_missing_evidence_not_found(tmp_path: Path):
    with pytest.raises(EvidenceNotFoundError):
        ContentAddressedEvidenceStore(tmp_path).path_for(DIGEST)
