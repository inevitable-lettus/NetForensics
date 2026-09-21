from __future__ import annotations

from pathlib import Path

from backend.evidence.seal import hash_file
from backend.models import Severity
from backend.pipeline import analyze_pcap
from tests.fixtures.packets import syn_frame, write_timed_pcap

BASE = 1_700_000_000.0


def _beacon_packets(count: int = 12, interval: float = 60.0) -> list[tuple[float, bytes]]:
    return [
        (BASE + i * interval, syn_frame("10.0.0.5", "203.0.113.7", 40000 + i, 443))
        for i in range(count)
    ]


def _scan_packets(ports: int = 120) -> list[tuple[float, bytes]]:
    return [
        (BASE + i * 0.01, syn_frame("10.0.0.66", "10.0.0.9", 50000, 1000 + i))
        for i in range(ports)
    ]


def test_beacon_capture_yields_c2_finding_with_evidence(tmp_path: Path):
    pcap = write_timed_pcap(tmp_path / "beacon.pcap", _beacon_packets())
    record = analyze_pcap("c" * 32, str(pcap))
    (finding,) = [f for f in record.findings if f.detector == "c2_beacon"]
    assert finding.what == "10.0.0.5 -> 203.0.113.7"
    assert "coefficient of variation" in finding.evidence
    assert record.flow_count == 12


def test_scan_capture_yields_port_scan_finding(tmp_path: Path):
    pcap = write_timed_pcap(tmp_path / "scan.pcap", _scan_packets())
    record = analyze_pcap("c" * 32, str(pcap))
    (finding,) = [f for f in record.findings if f.detector == "port_scan"]
    assert finding.supporting_data["max_distinct_ports"] == 120


def test_findings_sorted_most_severe_first(tmp_path: Path):
    pcap = write_timed_pcap(tmp_path / "both.pcap", _beacon_packets() + _scan_packets())
    severities = [f.severity for f in analyze_pcap("c" * 32, str(pcap)).findings]
    order = [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    assert severities == sorted(severities, key=order.index)


def test_benign_capture_has_no_findings(tmp_path: Path):
    pcap = write_timed_pcap(tmp_path / "quiet.pcap", _beacon_packets(count=3))
    assert analyze_pcap("c" * 32, str(pcap)).findings == ()


def test_seal_matches_the_file_analysed(tmp_path: Path):
    pcap = write_timed_pcap(tmp_path / "beacon.pcap", _beacon_packets())
    record = analyze_pcap("c" * 32, str(pcap))
    digests = hash_file(str(pcap))
    assert record.seal.pcap_hash == digests.blake3_hex
    assert record.seal.sha256_hash == digests.sha256_hex
    assert record.seal.pcap_filename == "beacon.pcap"
