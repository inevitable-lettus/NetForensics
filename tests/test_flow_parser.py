from __future__ import annotations

from pathlib import Path

from backend.parse.flow_parser import parse_flows
from tests.fixtures.packets import syn_frame, tcp_frame, udp_frame, write_timed_pcap

BASE = 1_700_000_000.0


def test_both_directions_fold_into_one_initiator_oriented_flow(tmp_path: Path):
    pcap = write_timed_pcap(
        tmp_path / "a.pcap",
        [
            (BASE, syn_frame("10.0.0.5", "10.0.0.9", 40000, 443)),
            (BASE + 0.1, tcp_frame("10.0.0.9", "10.0.0.5", 443, 40000)),
            (BASE + 0.2, tcp_frame("10.0.0.5", "10.0.0.9", 40000, 443)),
        ],
    )
    (flow,) = parse_flows(str(pcap))
    assert (flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port) == (
        "10.0.0.5", "10.0.0.9", 40000, 443,
    )
    assert flow.protocol == "tcp"
    assert flow.features.packet_count == 3
    assert (flow.end_time - flow.start_time).total_seconds() == 0.2


def test_server_reply_never_becomes_its_own_flow(tmp_path: Path):
    """Otherwise a scanned host would look like a scanner (src of many flows)."""
    pcap = write_timed_pcap(
        tmp_path / "a.pcap",
        [
            (BASE, syn_frame("10.0.0.5", "10.0.0.9", 40000, 80)),
            (BASE + 0.1, tcp_frame("10.0.0.9", "10.0.0.5", 80, 40000)),
        ],
    )
    assert {f.src_ip for f in parse_flows(str(pcap))} == {"10.0.0.5"}


def test_new_syn_on_same_five_tuple_starts_a_new_flow(tmp_path: Path):
    pcap = write_timed_pcap(
        tmp_path / "a.pcap",
        [
            (BASE, syn_frame("10.0.0.5", "10.0.0.9", 40000, 443)),
            (BASE + 1, tcp_frame("10.0.0.5", "10.0.0.9", 40000, 443)),
            (BASE + 60, syn_frame("10.0.0.5", "10.0.0.9", 40000, 443)),
        ],
    )
    flows = parse_flows(str(pcap))
    assert [f.features.packet_count for f in flows] == [2, 1]
    assert flows[1].start_time > flows[0].end_time


def test_udp_and_tcp_on_same_ports_are_distinct_flows(tmp_path: Path):
    pcap = write_timed_pcap(
        tmp_path / "a.pcap",
        [
            (BASE, udp_frame("10.0.0.5", "10.0.0.9", 5000, 53)),
            (BASE + 1, syn_frame("10.0.0.5", "10.0.0.9", 5000, 53)),
        ],
    )
    assert {f.protocol for f in parse_flows(str(pcap))} == {"udp", "tcp"}


def test_non_ip_and_garbage_frames_are_skipped(tmp_path: Path):
    pcap = write_timed_pcap(
        tmp_path / "a.pcap",
        [(BASE, b"\x00\x01\x02"), (BASE + 1, udp_frame("10.0.0.5", "10.0.0.9", 1, 2))],
    )
    assert len(parse_flows(str(pcap))) == 1


def test_flows_are_ordered_by_start_time(tmp_path: Path):
    pcap = write_timed_pcap(
        tmp_path / "a.pcap",
        [
            (BASE, udp_frame("10.0.0.5", "10.0.0.9", 1, 2)),
            (BASE + 5, udp_frame("10.0.0.6", "10.0.0.9", 1, 2)),
        ],
    )
    starts = [f.start_time for f in parse_flows(str(pcap))]
    assert starts == sorted(starts)
