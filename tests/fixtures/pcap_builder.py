"""Dependency-free builders for tiny crafted test inputs.

Two kinds of fixtures:
  * `write_minimal_pcap` — emits a real libpcap-format file (global header +
    packet records). Used to exercise Stage 1 (seal/hash) and Stage 2 (parse)
    without pulling in scapy/dpkt at fixture-build time.
  * `make_flow` / `synthetic_flows` — build `Flow` objects directly, so detector
    tests can craft exactly the feature shape they need.
"""

from __future__ import annotations

import struct
from datetime import datetime, timedelta
from pathlib import Path

from backend.models import DnsFeatures, Features, Flow, TlsFeatures

# libpcap global header: magic, version 2.4, no tz/sigfigs, 65535 snaplen,
# linktype 1 = Ethernet.
_PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def write_minimal_pcap(path: Path, packets: list[bytes]) -> Path:
    """Write a valid libpcap file containing `packets` (each raw link-layer bytes).

    A capture with zero packets is still a structurally valid pcap — useful for
    the seal/hash path, which never inspects packet contents.
    """
    with path.open("wb") as fh:
        fh.write(_PCAP_GLOBAL_HEADER)
        base = 1_700_000_000  # fixed epoch so fixtures hash deterministically
        for i, pkt in enumerate(packets):
            rec = struct.pack("<IIII", base + i, 0, len(pkt), len(pkt))
            fh.write(rec)
            fh.write(pkt)
    return path


def make_flow(
    *,
    src_ip: str = "10.0.0.5",
    dst_ip: str = "10.0.0.6",
    src_port: int = 5353,
    dst_port: int = 53,
    protocol: str = "udp",
    features: Features | None = None,
) -> Flow:
    """Build a single Flow with sensible defaults; override only what a test needs."""
    start = datetime(2026, 1, 1, 12, 0, 0)
    return Flow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        start_time=start,
        end_time=start + timedelta(seconds=1),
        features=features or Features(packet_count=1, byte_count=64),
    )


def dns_flow(parent: str, subdomains: list[str], entropy: float, query_count: int) -> Flow:
    """A UDP/53 flow carrying DNS features — for the DNS-exfil detector test."""
    feats = Features(
        packet_count=query_count,
        byte_count=query_count * 80,
        dns=DnsFeatures(
            parent_domain=parent,
            subdomains=tuple(subdomains),
            query_count=query_count,
            max_subdomain_entropy=entropy,
            max_subdomain_length=max((len(s) for s in subdomains), default=0),
        ),
    )
    return make_flow(dst_port=53, protocol="udp", features=feats)


def tls_flow(ja3: str, server_name: str | None = None) -> Flow:
    """A TCP/443 flow carrying a JA3 fingerprint — for the malicious-TLS test."""
    feats = Features(
        packet_count=10,
        byte_count=4096,
        tls=TlsFeatures(ja3=ja3, ja3_string=None, server_name=server_name),
    )
    return make_flow(src_port=44321, dst_port=443, protocol="tcp", features=feats)
