"""Stage 2 (DNS path) — dpkt bulk parse of a pcap into `Flow`+`DnsFeatures`,
grouped by (src_ip, parent_domain) so the DNS-exfil detector sees accumulated
query volume per host-per-parent, not one fragment per request/response pair.

UDP/53 only for v1 — DNS tunneling/exfil is overwhelmingly UDP; TCP/53 (zone
transfers, oversized responses) is out of scope for this detector.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from datetime import datetime, timezone

import dpkt


def _iter_dns_queries(pcap_path: str) -> Iterator[tuple[datetime, str, str]]:
    """Yield (timestamp, src_ip, query_name) for every DNS query packet (UDP dst
    port 53) in the capture. Single pass — dpkt reads the pcap once; malformed
    or non-DNS packets are skipped, not raised (bulk-parse noise, not a boundary
    validation failure)."""
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
            try:
                dns = dpkt.dns.DNS(udp.data)
            except dpkt.dpkt.UnpackError:
                continue
            src_ip = socket.inet_ntoa(ip.src)
            timestamp = datetime.fromtimestamp(ts, tz=timezone.utc)
            for question in dns.qd:
                yield timestamp, src_ip, question.name


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
