"""Tests for stage 1 seal - the evidence bag must hash deterministically
and change completely if a single byte is altered."""

from __future__ import annotations

from pathlib import Path

from backend.evidence.seal import hash_file, seal_pcap
from backend.models import TimestampStatus
from tests.fixtures.pcap_builder import write_minimal_pcap

# FIPS 180-2 published test vector: SHA-256("abc").
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_seal_is_deterministic(tmp_pcap: Path) -> None:
    write_minimal_pcap(tmp_pcap, [b"\x01\x02\x03\x04"])

    first = seal_pcap(str(tmp_pcap))
    second = seal_pcap(str(tmp_pcap))

    assert first.pcap_hash == second.pcap_hash
    assert first.sha256_hash == second.sha256_hash


def test_seal_changes_on_single_byte_flip(tmp_path: Path) -> None:
    original_path = tmp_path / "original.pcap"
    tampered_path = tmp_path / "tampered.pcap"
    write_minimal_pcap(original_path, [b"\x01\x02\x03\x04"])

    tampered_bytes = bytearray(original_path.read_bytes())
    tampered_bytes[-1] ^= 0xFF
    tampered_path.write_bytes(tampered_bytes)

    original_seal = seal_pcap(str(original_path))
    tampered_seal = seal_pcap(str(tampered_path))

    assert original_seal.pcap_hash != tampered_seal.pcap_hash
    assert original_seal.sha256_hash != tampered_seal.sha256_hash


def test_sha256_matches_published_vector(tmp_path: Path) -> None:
    path = tmp_path / "abc.bin"
    path.write_bytes(b"abc")

    assert hash_file(str(path)).sha256_hex == SHA256_ABC


def test_chunk_size_does_not_change_digests(tmp_path: Path) -> None:
    path = tmp_path / "data.bin"
    path.write_bytes(bytes(range(256)) * 10)  # 2560 bytes, not a multiple of 3

    tiny_chunks = hash_file(str(path), chunk_bytes=3)
    one_chunk = hash_file(str(path), chunk_bytes=1 << 20)

    assert tiny_chunks == one_chunk


def test_size_matches_bytes_hashed(tmp_path: Path) -> None:
    path = tmp_path / "data.bin"
    path.write_bytes(b"x" * 1234)

    assert hash_file(str(path), chunk_bytes=100).size_bytes == 1234


def test_new_seal_is_pending_and_utc(tmp_pcap: Path) -> None:
    write_minimal_pcap(tmp_pcap, [b"\x01"])

    seal = seal_pcap(str(tmp_pcap))

    assert seal.timestamp_status is TimestampStatus.PENDING
    assert seal.rfc3161_token is None
    assert seal.received_at.utcoffset() is not None
    assert seal.received_at.utcoffset().total_seconds() == 0
    assert seal.pcap_filename == "evidence.pcap"
