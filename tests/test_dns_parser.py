from __future__ import annotations

import math
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import dpkt

from backend.detectors.dns_exfil import DnsExfilDetector
from backend.parse.dns_parser import (
    _query_names,
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


def _non_utf8_query_packet(src_ip: str = "10.0.0.5") -> bytes:
    """dpkt cannot build a non-UTF-8 name, so craft the frame with a placeholder byte
    and swap in 0xE4 (Latin-1 'ä') — the byte that crashed the iodine capture."""
    frame = _dns_query_packet("jXgermeister.t1.evil.com", src_ip=src_ip)
    assert frame.count(b"X") == 1
    return frame.replace(b"X", b"\xe4")


def test_query_names_keeps_non_utf8_label_with_escape():
    frame = _non_utf8_query_packet()
    payload = dpkt.ethernet.Ethernet(frame).data.data.data
    # The bad byte is kept as a lone surrogate, so the raw bytes can be recovered exactly.
    (name,) = _query_names(payload)
    assert name == "j\udce4germeister.t1.evil.com"
    assert name.encode("utf-8", "surrogateescape") == b"j\xe4germeister.t1.evil.com"


def test_query_names_ignores_payload_that_is_not_dns():
    assert _query_names(b"\x00\x01") == []


def test_parse_dns_flows_survives_non_utf8_label(tmp_pcap: Path):
    write_minimal_pcap(
        tmp_pcap, [_non_utf8_query_packet(), _dns_query_packet("a8f3.evil.com")]
    )
    (flow,) = parse_dns_flows(str(tmp_pcap))
    assert flow.features.dns.parent_domain == "evil.com"
    assert flow.features.dns.query_count == 2
    assert "j\\xe4germeister.t1" in flow.features.dns.subdomains


# Issue #32: entropy and length are measured on the raw label bytes, not on the
# four-character \\xNN escapes shown for them.
_DENSE_LABEL = bytes(range(0x80, 0xA0))  # 32 distinct bytes; none is valid UTF-8 on its own


def _dense_binary_packet() -> bytes:
    frame = _dns_query_packet("q" * 32 + ".evil.com")
    assert frame.count(b"q" * 32) == 1
    return frame.replace(b"q" * 32, _DENSE_LABEL)


def test_non_text_label_is_measured_on_raw_bytes(tmp_pcap: Path):
    write_minimal_pcap(tmp_pcap, [_dense_binary_packet()])
    (flow,) = parse_dns_flows(str(tmp_pcap))
    dns = flow.features.dns
    assert dns.max_subdomain_length == 32  # not 128 escaped characters
    assert math.isclose(dns.max_subdomain_entropy, 5.0)  # log2(32); escaped text scores about 3.1
    assert dns.subdomains == (_DENSE_LABEL.decode("utf-8", "backslashreplace"),)
    assert dns.longest_subdomain == dns.subdomains[0]  # evidence still prints escapes


def test_dense_binary_tunnel_label_is_detected(tmp_pcap: Path, config):
    # Escaped, this label scored about 3.1 bits and slipped under the 4.2 cutoff.
    write_minimal_pcap(tmp_pcap, [_dense_binary_packet()])
    findings = DnsExfilDetector(config).run(parse_dns_flows(str(tmp_pcap)))
    assert len(findings) == 1
    assert "subdomain length 32 chars" in findings[0].evidence  # raw bytes, not 128 escaped characters
    assert "x80" in findings[0].evidence  # the label is named with its escapes, as before


def test_plain_text_labels_measure_the_same_as_before(tmp_pcap: Path):
    write_minimal_pcap(tmp_pcap, [_dns_query_packet("abcd.evil.com")])
    (flow,) = parse_dns_flows(str(tmp_pcap))
    assert flow.features.dns.max_subdomain_length == 4
    assert math.isclose(flow.features.dns.max_subdomain_entropy, 2.0)


def test_bad_byte_in_the_parent_domain_stays_storable(tmp_pcap: Path, config):
    # The parent (last two labels) holds a non-UTF-8 byte too. It must reach the flow,
    # the finding and SQLite as printable text, not as a lone surrogate.
    frame = _dense_binary_packet()
    assert frame.count(b"\x03com") == 1
    write_minimal_pcap(tmp_pcap, [frame.replace(b"\x03com", b"\x03c\xe4m")])
    (flow,) = parse_dns_flows(str(tmp_pcap))
    assert flow.features.dns.parent_domain == "evil.c\\xe4m"
    (finding,) = DnsExfilDetector(config).run([flow])
    finding.what.encode("utf-8")  # raises on a lone surrogate
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE t (what TEXT)")
        db.execute("INSERT INTO t VALUES (?)", (finding.what,))
