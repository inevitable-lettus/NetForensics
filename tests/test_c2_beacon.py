from __future__ import annotations

import math
from datetime import datetime, timezone

from backend.config import Allowlists, CONFIG, Config
from backend.detectors.c2_beacon import (
    C2BeaconDetector,
    _coefficient_of_variation,
    _group_by_src_dst,
    _inter_arrival_times,
)
from backend.models import Features, Flow, Severity


def _flow(src_ip: str, dst_ip: str, offset_secs: float, dst_port: int = 443) -> Flow:
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ts = ts.fromtimestamp(ts.timestamp() + offset_secs, tz=timezone.utc)
    return Flow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=44000,
        dst_port=dst_port,
        protocol="tcp",
        start_time=ts,
        end_time=ts,
        features=Features(packet_count=1, byte_count=100),
    )


def test_groups_by_src_dst_pair():
    flows = [
        _flow("10.0.0.5", "203.0.113.9", 0),
        _flow("10.0.0.5", "203.0.113.9", 60),
        _flow("10.0.0.5", "198.51.100.2", 0),
        _flow("10.0.0.6", "203.0.113.9", 0),
    ]
    groups = _group_by_src_dst(flows)
    assert set(groups.keys()) == {
        ("10.0.0.5", "203.0.113.9"),
        ("10.0.0.5", "198.51.100.2"),
        ("10.0.0.6", "203.0.113.9"),
    }
    assert len(groups[("10.0.0.5", "203.0.113.9")]) == 2


def test_ignores_destination_port_when_grouping():
    # Same src/dst IPs, different dst_port — must land in the same group.
    a = _flow("10.0.0.5", "203.0.113.9", 0, dst_port=443)
    b = _flow("10.0.0.5", "203.0.113.9", 60, dst_port=8443)
    groups = _group_by_src_dst([a, b])
    assert len(groups[("10.0.0.5", "203.0.113.9")]) == 2


def test_empty_input_returns_empty_dict():
    assert _group_by_src_dst([]) == {}


def test_inter_arrival_times_sorts_before_diffing():
    # Deliberately out of chronological order.
    flows = [
        _flow("10.0.0.5", "203.0.113.9", 60),
        _flow("10.0.0.5", "203.0.113.9", 0),
        _flow("10.0.0.5", "203.0.113.9", 121),
    ]
    assert _inter_arrival_times(flows) == [60.0, 61.0]


def test_inter_arrival_times_needs_at_least_two_flows():
    assert _inter_arrival_times([]) == []
    assert _inter_arrival_times([_flow("10.0.0.5", "203.0.113.9", 0)]) == []


def test_coefficient_of_variation_regular_beacon():
    # Ten connections ~60s apart with small jitter — the worked example.
    offsets = [0, 60, 121, 179, 241, 301, 362, 419, 481, 541]
    flows = [_flow("10.0.0.5", "203.0.113.9", off) for off in offsets]
    iats = _inter_arrival_times(flows)
    cv = _coefficient_of_variation(iats)
    assert cv is not None
    assert math.isclose(cv, 0.0281, abs_tol=0.001)


def test_coefficient_of_variation_irregular_human_traffic():
    # Bursty, human-like gaps — CV should sit well above the 0.1 beacon cutoff.
    iats = [5.0, 120.0, 300.0, 45.0, 600.0, 12.0, 90.0]
    cv = _coefficient_of_variation(iats)
    assert cv is not None
    assert cv > 1.0


def test_coefficient_of_variation_needs_at_least_two_gaps():
    assert _coefficient_of_variation([]) is None
    assert _coefficient_of_variation([60.0]) is None


def test_coefficient_of_variation_zero_mean_is_not_meaningful():
    assert _coefficient_of_variation([0.0, 0.0, 0.0]) is None


def test_detector_fires_on_regular_beacon():
    offsets = [0, 60, 121, 179, 241, 301, 362, 419, 481, 541]
    flows = [_flow("10.0.0.5", "203.0.113.9", off) for off in offsets]
    findings = C2BeaconDetector(CONFIG).run(flows)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector == "c2_beacon"
    assert finding.what == "10.0.0.5 -> 203.0.113.9"
    assert finding.severity == Severity.MEDIUM
    assert finding.supporting_data["connection_count"] == 10


def test_detector_does_not_fire_on_irregular_human_traffic():
    gaps = [5, 120, 300, 45, 600, 12, 90, 200, 15, 88]
    offsets = [0]
    for gap in gaps:
        offsets.append(offsets[-1] + gap)
    flows = [_flow("10.0.0.5", "203.0.113.9", off) for off in offsets]
    findings = C2BeaconDetector(CONFIG).run(flows)
    assert findings == []


def test_detector_requires_min_connections():
    # Perfectly regular, but only 5 connections — below min_connections=10.
    offsets = [0, 60, 120, 180, 240]
    flows = [_flow("10.0.0.5", "203.0.113.9", off) for off in offsets]
    findings = C2BeaconDetector(CONFIG).run(flows)
    assert findings == []


def test_detector_suppresses_allowlisted_destination():
    offsets = [0, 60, 121, 179, 241, 301, 362, 419, 481, 541]
    flows = [_flow("10.0.0.5", "203.0.113.9", off) for off in offsets]
    cfg = Config(allowlists=Allowlists(beacon_dst_ips=("203.0.113.9",)))
    findings = C2BeaconDetector(cfg).run(flows)
    assert findings == []


def test_detector_evaluates_groups_independently():
    beacon_offsets = [0, 60, 121, 179, 241, 301, 362, 419, 481, 541]
    human_offsets = [0]
    for gap in [5, 120, 300, 45, 600, 12, 90, 200, 15, 88]:
        human_offsets.append(human_offsets[-1] + gap)
    flows = [_flow("10.0.0.5", "203.0.113.9", off) for off in beacon_offsets]
    flows += [_flow("10.0.0.5", "198.51.100.2", off) for off in human_offsets]
    findings = C2BeaconDetector(CONFIG).run(flows)
    assert len(findings) == 1
    assert findings[0].what == "10.0.0.5 -> 203.0.113.9"
