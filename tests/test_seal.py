"""Tests for stage 1 seal - the evidence bag must hash deterministically
and change completely if a single byte is altered."""

from __future__ import annotations

from pathlib import Path

from backend.evidence.seal import seal_pcap
from tests.fixtures.pcap_builder import write_minimal_pcap


def test_seal_is_deterministic(tmp_pcap: Path) -> None:
    write_minimal_pcap(tmp_pcap, [b"\x01\x02\x03\x04"])

    first = seal_pcap(str(tmp_pcap))
    second = seal_pcap(str(tmp_pcap))

    assert first.pcap_hash == second.pcap_hash


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
