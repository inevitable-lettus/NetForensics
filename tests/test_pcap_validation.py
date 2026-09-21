from __future__ import annotations

from pathlib import Path

import pytest

from backend.ingest.pcap_validation import InvalidCaptureError, validate_pcap_file
from tests.fixtures.pcap_builder import write_minimal_pcap


def test_valid_pcap_passes(tmp_path: Path):
    validate_pcap_file(write_minimal_pcap(tmp_path / "ok.pcap", []))


def test_pcapng_rejected_with_specific_message(tmp_path: Path):
    path = tmp_path / "x.pcapng"
    path.write_bytes(bytes.fromhex("0a0d0d0a") + b"\x00" * 40)
    with pytest.raises(InvalidCaptureError, match="pcapng"):
        validate_pcap_file(path)


def test_garbage_rejected(tmp_path: Path):
    path = tmp_path / "x.pcap"
    path.write_bytes(b"not a capture at all, just text" * 2)
    with pytest.raises(InvalidCaptureError, match="not a libpcap"):
        validate_pcap_file(path)


def test_truncated_header_rejected(tmp_path: Path):
    path = tmp_path / "x.pcap"
    path.write_bytes(bytes.fromhex("d4c3b2a1") + b"\x00" * 4)
    with pytest.raises(InvalidCaptureError):
        validate_pcap_file(path)
