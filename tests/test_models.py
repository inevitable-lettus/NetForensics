"""Contract tests for the shared data models. These prove the scaffold's shapes
import and behave; the algorithmic logic that fills them comes in later phases."""

from __future__ import annotations

from datetime import datetime

from backend.models import (
    CustodyEntry,
    DnsFeatures,
    Features,
    Finding,
    SealRecord,
    Severity,
)
from tests.fixtures.pcap_builder import dns_flow, make_flow


def test_flow_five_tuple() -> None:
    flow = make_flow(src_ip="1.2.3.4", dst_ip="5.6.7.8", src_port=1234, dst_port=53)
    assert flow.five_tuple == ("1.2.3.4", "5.6.7.8", 1234, 53, "udp")


def test_dns_flow_carries_features() -> None:
    flow = dns_flow("evil.com", ["a3f9kd02", "x7"], entropy=4.2, query_count=300)
    assert isinstance(flow.features, Features)
    assert isinstance(flow.features.dns, DnsFeatures)
    assert flow.features.dns.parent_domain == "evil.com"
    assert flow.features.dns.max_subdomain_entropy == 4.2


def test_finding_carries_explainability_contract() -> None:
    finding = Finding(
        detector="dns_exfil",
        what="subdomain a3f9kd02.evil.com",
        why="high-entropy encoded data tunneled over DNS",
        supporting_data={"entropy": 4.2, "benign_baseline": 2.5},
        evidence="Subdomain a3f9kd02 has entropy 4.2 (benign ~2.5).",
        severity=Severity.HIGH,
    )
    # WHAT / WHY / SUPPORTING DATA all present, no confidence score field.
    assert finding.what and finding.why and finding.supporting_data
    assert "confidence" not in finding.supporting_data
    assert not hasattr(finding, "confidence")


def test_seal_record_records_hash_and_time() -> None:
    seal = SealRecord(
        pcap_filename="evidence.pcap",
        pcap_size_bytes=1024,
        hash_algorithm="blake3",
        pcap_hash="deadbeef",
        received_at=datetime(2026, 6, 25, 10, 0, 0),
    )
    assert seal.hash_algorithm == "blake3"
    assert seal.rfc3161_token is None  # offline fallback path is representable


def test_custody_entry_chains_to_prior() -> None:
    genesis = CustodyEntry(
        index=0,
        timestamp=datetime(2026, 6, 25, 10, 0, 0),
        event_type="ingest",
        detail="sealed evidence.pcap",
        prev_hash="",
        entry_hash="h0",
    )
    nxt = CustodyEntry(
        index=1,
        timestamp=datetime(2026, 6, 25, 10, 0, 1),
        event_type="parse",
        detail="extracted 12 flows",
        prev_hash=genesis.entry_hash,
        entry_hash="h1",
    )
    assert nxt.prev_hash == genesis.entry_hash
