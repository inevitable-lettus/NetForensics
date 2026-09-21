"""dpkt-built raw Ethernet frames for parser / pipeline tests. Separate from
`pcap_builder` because that module is deliberately dependency-free."""

from __future__ import annotations

import struct
from pathlib import Path

import dpkt

_PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def _ip(address: str) -> bytes:
    return bytes(int(octet) for octet in address.split("."))


def _frame(src_ip: str, dst_ip: str, proto: int, transport: bytes) -> bytes:
    ip = dpkt.ip.IP(src=_ip(src_ip), dst=_ip(dst_ip), p=proto, data=transport)
    ip.len = len(bytes(ip))
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00" * 6, dst=b"\x11" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=bytes(ip)
    )
    return bytes(eth)


def tcp_frame(
    src_ip: str, dst_ip: str, sport: int, dport: int, flags: int = dpkt.tcp.TH_ACK
) -> bytes:
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags)
    return _frame(src_ip, dst_ip, dpkt.ip.IP_PROTO_TCP, bytes(tcp))


def syn_frame(src_ip: str, dst_ip: str, sport: int, dport: int) -> bytes:
    return tcp_frame(src_ip, dst_ip, sport, dport, flags=dpkt.tcp.TH_SYN)


def udp_frame(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes = b"") -> bytes:
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = len(bytes(udp))
    return _frame(src_ip, dst_ip, dpkt.ip.IP_PROTO_UDP, bytes(udp))


def write_timed_pcap(path: Path, packets: list[tuple[float, bytes]]) -> Path:
    """Write a libpcap file where each packet carries its own epoch timestamp —
    needed for timing-based detectors (beaconing, scan windows)."""
    with path.open("wb") as fh:
        fh.write(_PCAP_GLOBAL_HEADER)
        for ts, pkt in packets:
            seconds = int(ts)
            micros = int(round((ts - seconds) * 1_000_000))
            fh.write(struct.pack("<IIII", seconds, micros, len(pkt), len(pkt)))
            fh.write(pkt)
    return path
