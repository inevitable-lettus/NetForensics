"""Stage 2 (DNS path) — dpkt bulk parse of a pcap into `Flow`+`DnsFeatures`,
grouped by (src_ip, parent_domain) so the DNS-exfil detector sees accumulated
query volume per host-per-parent, not one fragment per request/response pair.

UDP/53 only for v1 — DNS tunneling/exfil is overwhelmingly UDP; TCP/53 (zone
transfers, oversized responses) is out of scope for this detector.
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone

import dpkt

from backend.models import DnsFeatures, Features, Flow
from backend.parse.entropy import shannon_entropy


_DNS_HEADER_LEN = 12
_QUESTION_TAIL_LEN = 4  # QTYPE + QCLASS after each name


def _questions_lossless(payload: bytes) -> list[str]:
    """Read question names straight from the DNS wire format, decoding label bytes with
    backslash escapes instead of failing. Fallback for names dpkt rejects because a
    label is not valid UTF-8 (e.g. iodine's Latin-1 padding): the label is kept, with
    each bad byte shown as \\xNN, so the detector still measures it.

    Questions only, uncompressed only: a compression pointer or a truncated packet ends
    the read and returns the names parsed so far."""
    if len(payload) < _DNS_HEADER_LEN:
        return []
    question_count = struct.unpack("!H", payload[4:6])[0]
    names: list[str] = []
    offset = _DNS_HEADER_LEN
    for _ in range(question_count):
        labels: list[bytes] = []
        while True:
            if offset >= len(payload):
                return names
            length = payload[offset]
            offset += 1
            if length == 0:
                break
            if length & 0xC0:
                return names
            labels.append(payload[offset : offset + length])
            offset += length
        names.append(b".".join(labels).decode("utf-8", errors="backslashreplace"))
        offset += _QUESTION_TAIL_LEN
    return names


def _query_names(payload: bytes) -> list[str]:
    """Question names in one DNS payload; [] when it is not parseable DNS at all."""
    try:
        return [question.name for question in dpkt.dns.DNS(payload).qd]
    except UnicodeDecodeError:
        return _questions_lossless(payload)
    except dpkt.dpkt.UnpackError:
        return []


def _iter_dns_queries(pcap_path: str) -> Iterator[tuple[datetime, str, str, str]]:
    """Yield (timestamp, src_ip, dst_ip, query_name) for every DNS query packet
    (UDP dst port 53) in the capture. Single pass — dpkt reads the pcap once;
    malformed or non-DNS packets are skipped, not raised (bulk-parse noise, not a
    boundary validation failure)."""
    with open(pcap_path, "rb") as fh:
        for ts, buf in dpkt.pcap.Reader(fh):
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except dpkt.dpkt.UnpackError:
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            udp = ip.data
            if not isinstance(udp, dpkt.udp.UDP) or udp.dport != 53:
                continue
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            timestamp = datetime.fromtimestamp(ts, tz=timezone.utc)
            for name in _query_names(udp.data):
                yield timestamp, src_ip, dst_ip, name


def _split_domain(name: str) -> tuple[str, str]:
    """Split a DNS query name into (parent_domain, subdomain).

    Naive last-two-labels heuristic — "a8f3.evil.example.com" -> ("example.com",
    "a8f3.evil"). Known limitation: wrong on multi-part TLDs like "foo.co.uk"
    (gives parent "co.uk"). No public-suffix-list dependency for this phase —
    scope discipline over correctness on an edge case; revisit if real captures
    show it matters.
    """
    name = name.rstrip(".").lower()
    labels = name.split(".")
    if len(labels) <= 2:
        return name, ""
    parent = ".".join(labels[-2:])
    subdomain = ".".join(labels[:-2])
    return parent, subdomain


def _group_dns_queries(
    records: Iterable[tuple[datetime, str, str, str]],
) -> dict[tuple[str, str], list[tuple[datetime, str, str]]]:
    """Bucket (timestamp, src_ip, dst_ip, query_name) records by (src_ip,
    parent_domain) — the unit the DNS-exfil detector reasons about: one host's
    query behavior against one parent domain."""
    groups: dict[tuple[str, str], list[tuple[datetime, str, str]]] = {}
    for timestamp, src_ip, dst_ip, qname in records:
        parent, subdomain = _split_domain(qname)
        groups.setdefault((src_ip, parent), []).append((timestamp, dst_ip, subdomain))
    return groups


def _build_dns_flow(
    src_ip: str, parent: str, entries: list[tuple[datetime, str, str]]
) -> Flow:
    """Turn one (src_ip, parent_domain) group into a `Flow`.

    Known modeling compromise: a "flow" here aggregates many real UDP
    query/response pairs, not one 5-tuple connection, so `src_port` is a
    sentinel (0) and `dst_ip` is taken from the first query in the group —
    neither is read by the DNS-exfil detector.
    """
    timestamps = [ts for ts, _, _ in entries]
    dst_ip = entries[0][1]
    subdomains = tuple(sub for _, _, sub in entries if sub)  # drop apex queries ("")
    dns = DnsFeatures(
        parent_domain=parent,
        subdomains=subdomains,
        query_count=len(entries),
        max_subdomain_entropy=max((shannon_entropy(s) for s in subdomains), default=0.0),
        max_subdomain_length=max((len(s) for s in subdomains), default=0),
    )
    return Flow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=0,
        dst_port=53,
        protocol="udp",
        start_time=min(timestamps),
        end_time=max(timestamps),
        features=Features(packet_count=len(entries), byte_count=0, dns=dns),
    )


def parse_dns_flows(pcap_path: str) -> list[Flow]:
    """Bulk-parse a pcap's DNS traffic into one `Flow` per (src_ip,
    parent_domain), ready for `DnsExfilDetector.run`."""
    groups = _group_dns_queries(_iter_dns_queries(pcap_path))
    return [_build_dns_flow(src_ip, parent, entries) for (src_ip, parent), entries in groups.items()]
