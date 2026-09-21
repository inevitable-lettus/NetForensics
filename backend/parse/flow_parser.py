"""Stage 2 (generic path) — dpkt bulk parse of a pcap into one `Flow` per
connection, for the beaconing and port-scan detectors.

Ethernet/IPv4 TCP and UDP only for v1 (no IPv6, no TCP reassembly — scope is
fixed). A flow is bidirectional: both directions of a conversation fold into one
`Flow`, oriented so `src_ip` is whoever spoke first (the initiator). Orienting
matters — if server replies became their own flows, a scanned host would look
like a scanner itself.

Known limitation: a UDP conversation that reuses one 5-tuple stays one flow
(no idle timeout); TCP splits into a new flow when a fresh SYN reappears.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone

import dpkt

from backend.models import Features, Flow

_FlowKey = tuple[tuple[str, int], tuple[str, int], str]


@dataclass(frozen=True)
class _Packet:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size_bytes: int
    opens_connection: bool  # TCP SYN without ACK — the first packet of a handshake


@dataclass
class _OpenFlow:
    """Mutable accumulator while a flow is still receiving packets."""

    first: _Packet
    last_timestamp: datetime
    packet_count: int = 0
    byte_count: int = 0

    def add(self, packet: _Packet) -> None:
        self.last_timestamp = max(self.last_timestamp, packet.timestamp)
        self.packet_count += 1
        self.byte_count += packet.size_bytes


def _decode_packet(ts: float, buf: bytes) -> _Packet | None:
    """One raw frame -> `_Packet`, or None if it is not Ethernet/IPv4 TCP/UDP.
    Undecodable frames are skipped, not raised (bulk-parse noise)."""
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except dpkt.dpkt.UnpackError:
        return None
    ip = eth.data
    if not isinstance(ip, dpkt.ip.IP):
        return None
    segment = ip.data
    if isinstance(segment, dpkt.tcp.TCP):
        protocol = "tcp"
        opens = bool(segment.flags & dpkt.tcp.TH_SYN) and not segment.flags & dpkt.tcp.TH_ACK
    elif isinstance(segment, dpkt.udp.UDP):
        protocol, opens = "udp", False
    else:
        return None
    return _Packet(
        timestamp=datetime.fromtimestamp(ts, tz=timezone.utc),
        src_ip=socket.inet_ntoa(ip.src),
        dst_ip=socket.inet_ntoa(ip.dst),
        src_port=segment.sport,
        dst_port=segment.dport,
        protocol=protocol,
        size_bytes=len(buf),
        opens_connection=opens,
    )


def _iter_packets(pcap_path: str) -> Iterator[_Packet]:
    """Single pass over the capture — dpkt reads the file once."""
    with open(pcap_path, "rb") as fh:
        for ts, buf in dpkt.pcap.Reader(fh):
            packet = _decode_packet(ts, buf)
            if packet is not None:
                yield packet


def _flow_key(packet: _Packet) -> _FlowKey:
    """Direction-independent key: both directions of a conversation share it."""
    endpoints = sorted([(packet.src_ip, packet.src_port), (packet.dst_ip, packet.dst_port)])
    return endpoints[0], endpoints[1], packet.protocol


def _begin(packet: _Packet) -> _OpenFlow:
    open_flow = _OpenFlow(first=packet, last_timestamp=packet.timestamp)
    open_flow.add(packet)
    return open_flow


def _to_flow(open_flow: _OpenFlow) -> Flow:
    first = open_flow.first
    return Flow(
        src_ip=first.src_ip,
        dst_ip=first.dst_ip,
        src_port=first.src_port,
        dst_port=first.dst_port,
        protocol=first.protocol,
        start_time=first.timestamp,
        end_time=open_flow.last_timestamp,
        features=Features(
            packet_count=open_flow.packet_count, byte_count=open_flow.byte_count
        ),
    )


def parse_flows(pcap_path: str) -> list[Flow]:
    """Bulk-parse a pcap into connection `Flow`s, ordered by start time, ready for
    `C2BeaconDetector.run` and `PortScanDetector.run`."""
    open_flows: dict[_FlowKey, _OpenFlow] = {}
    finished: list[Flow] = []
    for packet in _iter_packets(pcap_path):
        key = _flow_key(packet)
        current = open_flows.get(key)
        if current is not None and packet.opens_connection:
            finished.append(_to_flow(current))
            current = None
        if current is None:
            open_flows[key] = _begin(packet)
        else:
            current.add(packet)
    finished.extend(_to_flow(open_flow) for open_flow in open_flows.values())
    return sorted(finished, key=lambda flow: flow.start_time)
