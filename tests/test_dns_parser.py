from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import dpkt

from backend.parse.dns_parser import (
    _build_dns_flow,
    _group_dns_queries,
    _iter_dns_queries,
    _split_domain,
    parse_dns_flows,
)
from tests.fixtures.pcap_builder import write_minimal_pcap


def _dns_query_packet(qname: str, *, src_ip: str = "10.0.0.5", dst_ip: str = "8.8.8.8") -> bytes:
    """Craft a raw Ethernet frame carrying one UDP/53 DNS query for `qname`."""
    dns = dpkt.dns.DNS(op=dpkt.dns.DNS_QUERY, rd=1)
    dns.qd = [dpkt.dns.DNS.Q(name=qname, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN)]

    udp = dpkt.udp.UDP(sport=33333, dport=53, data=bytes(dns))
    udp.ulen = len(bytes(udp))

    ip = dpkt.ip.IP(
        src=bytes(int(o) for o in src_ip.split(".")),
        dst=bytes(int(o) for o in dst_ip.split(".")),
        p=dpkt.ip.IP_PROTO_UDP,
        data=bytes(udp),
    )
    ip.len = len(bytes(ip))

    eth = dpkt.ethernet.Ethernet(
        src=b"\x00" * 6, dst=b"\x11" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=bytes(ip)
    )
    return bytes(eth)


def test_split_domain_basic():
    assert _split_domain("a8f3k2.evil.example.com") == ("example.com", "a8f3k2.evil")


def test_split_domain_bare_apex():
    assert _split_domain("example.com") == ("example.com", "")


def test_split_domain_single_label():
    assert _split_domain("localhost") == ("localhost", "")


def test_split_domain_trailing_dot_and_case():
    assert _split_domain("A8F3.Evil.Example.Com.") == ("example.com", "a8f3.evil")


def test_split_domain_known_limitation_multi_part_tld():
    # Documented limitation: naive heuristic gives "co.uk", not "foo.co.uk".
    assert _split_domain("bar.foo.co.uk") == ("co.uk", "bar.foo")


def test_iter_dns_queries_extracts_query(tmp_pcap: Path):
    write_minimal_pcap(
        tmp_pcap,
        [_dns_query_packet("evil.example.com", src_ip="10.0.0.5", dst_ip="8.8.8.8")],
    )
    results = list(_iter_dns_queries(str(tmp_pcap)))
    assert len(results) == 1
    _, src_ip, dst_ip, qname = results[0]
    assert src_ip == "10.0.0.5"
    assert dst_ip == "8.8.8.8"
    assert qname == "evil.example.com"


def test_iter_dns_queries_skips_non_dns_udp(tmp_pcap: Path):
    # UDP but not port 53 and not valid DNS payload — must not crash the pass.
    junk = dpkt.ethernet.Ethernet(
        src=b"\x00" * 6,
        dst=b"\x11" * 6,
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=bytes(
            dpkt.ip.IP(
                src=bytes([10, 0, 0, 5]),
                dst=bytes([8, 8, 8, 8]),
                p=dpkt.ip.IP_PROTO_UDP,
                data=bytes(dpkt.udp.UDP(sport=1234, dport=9999, data=b"not dns")),
            )
        ),
    )
    write_minimal_pcap(tmp_pcap, [bytes(junk)])
    assert list(_iter_dns_queries(str(tmp_pcap))) == []


def test_iter_dns_queries_multiple_packets(tmp_pcap: Path):
    packets = [
        _dns_query_packet("a.evil.com", src_ip="10.0.0.5"),
        _dns_query_packet("b.evil.com", src_ip="10.0.0.6"),
    ]
    write_minimal_pcap(tmp_pcap, packets)
    results = list(_iter_dns_queries(str(tmp_pcap)))
    assert [(r[1], r[3]) for r in results] == [
        ("10.0.0.5", "a.evil.com"),
        ("10.0.0.6", "b.evil.com"),
    ]


def test_group_dns_queries_buckets_by_src_and_parent():
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    records = [
        (t0, "10.0.0.5", "8.8.8.8", "a1.evil.com"),
        (t0, "10.0.0.5", "8.8.8.8", "a2.evil.com"),
        (t0, "10.0.0.5", "8.8.8.8", "b.benign.com"),
        (t0, "10.0.0.6", "8.8.8.8", "c1.evil.com"),
    ]
    groups = _group_dns_queries(records)
    assert set(groups.keys()) == {
        ("10.0.0.5", "evil.com"),
        ("10.0.0.5", "benign.com"),
        ("10.0.0.6", "evil.com"),
    }
    assert len(groups[("10.0.0.5", "evil.com")]) == 2


def test_build_dns_flow_computes_entropy_and_length_from_subdomains():
    t0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 1, 1, 0, 0, 5, tzinfo=timezone.utc)
    entries = [(t0, "8.8.8.8", "ab"), (t1, "8.8.8.8", "abcd")]
    flow = _build_dns_flow("10.0.0.5", "evil.com", entries)
    assert flow.src_ip == "10.0.0.5"
    assert flow.dst_ip == "8.8.8.8"
    assert flow.start_time == t0
    assert flow.end_time == t1
    assert flow.features.dns.parent_domain == "evil.com"
    assert flow.features.dns.query_count == 2
    assert flow.features.dns.max_subdomain_length == 4
    assert flow.features.dns.subdomains == ("ab", "abcd")


def test_build_dns_flow_apex_only_queries_have_zero_entropy_and_length():
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    entries = [(t0, "8.8.8.8", "")]
    flow = _build_dns_flow("10.0.0.5", "example.com", entries)
    assert flow.features.dns.query_count == 1
    assert flow.features.dns.max_subdomain_entropy == 0.0
    assert flow.features.dns.max_subdomain_length == 0
    assert flow.features.dns.subdomains == ()


def test_parse_dns_flows_end_to_end(tmp_pcap: Path):
    packets = [
        _dns_query_packet("a8f3k2z9.evil.com", src_ip="10.0.0.5"),
        _dns_query_packet("b7c1m4x2.evil.com", src_ip="10.0.0.5"),
        _dns_query_packet("mail.benign.com", src_ip="10.0.0.6"),
    ]
    write_minimal_pcap(tmp_pcap, packets)
    flows = parse_dns_flows(str(tmp_pcap))
    assert len(flows) == 2
    evil_flow = next(f for f in flows if f.features.dns.parent_domain == "evil.com")
    assert evil_flow.src_ip == "10.0.0.5"
    assert evil_flow.features.dns.query_count == 2
