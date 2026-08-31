from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.config import CONFIG
from backend.detectors.port_scan import (
    PortScanDetector,
    _group_by_src,
    _max_fanout_in_window,
)
from backend.models import Features, Flow, Severity


def _flow(
    src_ip: str, dst_ip: str, dst_port: int, offset_secs: float, protocol: str = "tcp"
) -> Flow:
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=offset_secs)
    return Flow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=44000,
        dst_port=dst_port,
        protocol=protocol,
        start_time=ts,
        end_time=ts,
        features=Features(packet_count=1, byte_count=100),
    )


def test_groups_by_src_ip_only():
    flows = [
        _flow("10.0.0.5", "203.0.113.9", 80, 0),
        _flow("10.0.0.5", "198.51.100.2", 443, 1),
        _flow("10.0.0.6", "203.0.113.9", 80, 0),
    ]
    groups = _group_by_src(flows)
    assert set(groups.keys()) == {"10.0.0.5", "10.0.0.6"}
    assert len(groups["10.0.0.5"]) == 2


def test_group_by_src_empty_input():
    assert _group_by_src([]) == {}


def test_max_fanout_hand_worked_example():
    # Five connections to the same host, 3s apart, each a new port. Window=10s.
    # At t=12 the flow from t=0 (3s+9s=12s gap) falls outside the window and
    # is evicted, so the port count peaks at 4 (not 5) just before eviction.
    flows = [_flow("10.0.0.5", "203.0.113.9", 100 + i, i * 3) for i in range(5)]
    max_ports, max_hosts = _max_fanout_in_window(flows, window_secs=10)
    assert (max_ports, max_hosts) == (4, 1)


def test_detector_fires_medium_on_vertical_scan():
    # 105 distinct ports to one host, all within a 10s window -> ports axis only.
    flows = [
        _flow("10.0.0.5", "203.0.113.9", 1000 + i, i * 0.05) for i in range(105)
    ]
    findings = PortScanDetector(CONFIG).run(flows)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector == "port_scan"
    assert finding.what == "Source 10.0.0.5"
    assert finding.severity == Severity.MEDIUM
    assert finding.supporting_data["max_distinct_ports"] == 105
    assert finding.supporting_data["max_distinct_hosts"] == 1


def test_detector_fires_medium_on_horizontal_scan():
    # 12 distinct hosts on one port, all within a 10s window -> hosts axis only.
    flows = [
        _flow("10.0.0.5", f"203.0.113.{i}", 80, i * 0.2) for i in range(12)
    ]
    findings = PortScanDetector(CONFIG).run(flows)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.MEDIUM
    assert finding.supporting_data["max_distinct_hosts"] == 12
    assert finding.supporting_data["max_distinct_ports"] == 1


def test_detector_fires_high_when_both_axes_corroborate():
    # 105 distinct ports spread over only 12 distinct hosts, all in-window ->
    # both axes exceed their threshold.
    flows = [
        _flow("10.0.0.5", f"203.0.113.{i % 12}", 1000 + i, i * 0.05)
        for i in range(105)
    ]
    findings = PortScanDetector(CONFIG).run(flows)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_detector_does_not_fire_on_normal_traffic():
    flows = [
        _flow("10.0.0.5", "203.0.113.9", 443, 0),
        _flow("10.0.0.5", "203.0.113.9", 443, 1),
        _flow("10.0.0.5", "198.51.100.2", 80, 2),
    ]
    findings = PortScanDetector(CONFIG).run(flows)
    assert findings == []


def test_detector_ignores_fanout_spread_outside_the_window():
    # 150 distinct ports to one host, but 20s apart each -> never more than
    # one flow inside any 10s window. Proves the sliding window is enforced,
    # not a naive whole-capture distinct-port count.
    flows = [_flow("10.0.0.5", "203.0.113.9", 1000 + i, i * 20) for i in range(150)]
    findings = PortScanDetector(CONFIG).run(flows)
    assert findings == []


def test_detector_evaluates_sources_independently():
    scanner = [
        _flow("10.0.0.5", "203.0.113.9", 1000 + i, i * 0.05) for i in range(105)
    ]
    normal = [
        _flow("10.0.0.7", "203.0.113.9", 443, 0),
        _flow("10.0.0.7", "198.51.100.2", 80, 1),
    ]
    findings = PortScanDetector(CONFIG).run(scanner + normal)
    assert len(findings) == 1
    assert findings[0].what == "Source 10.0.0.5"
