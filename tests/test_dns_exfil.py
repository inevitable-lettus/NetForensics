from __future__ import annotations

from datetime import datetime, timedelta

from backend.detectors.dns_exfil import DnsExfilDetector, _is_allowlisted, _query_rate
from backend.models import DnsFeatures, Features, Flow
from tests.fixtures.pcap_builder import dns_flow

_START = datetime(2026, 1, 1, 12, 0, 0)


def _flow_with_duration(seconds: float, query_count: int) -> Flow:
    dns = DnsFeatures(
        parent_domain="evil.example.com",
        subdomains=("a",),
        query_count=query_count,
        max_subdomain_entropy=4.5,
        max_subdomain_length=1,
    )
    return Flow(
        src_ip="10.0.0.5",
        dst_ip="10.0.0.6",
        src_port=5353,
        dst_port=53,
        protocol="udp",
        start_time=_START,
        end_time=_START + timedelta(seconds=seconds),
        features=Features(packet_count=query_count, byte_count=64, dns=dns),
    )


def test_allowlist_exact_match():
    assert _is_allowlisted("cloudfront.net", ("cloudfront.net",))


def test_allowlist_subdomain_match():
    assert _is_allowlisted("d3ab1c.cloudfront.net", ("cloudfront.net",))


def test_allowlist_rejects_suffix_collision():
    assert not _is_allowlisted("evilcloudfront.net", ("cloudfront.net",))


def test_allowlist_no_match():
    assert not _is_allowlisted("evil.example.com", ("cloudfront.net",))


def test_allowlist_trailing_dot_and_case():
    assert _is_allowlisted("D3AB1C.CloudFront.Net.", ("cloudfront.net",))


def test_query_rate_normalizes_to_window():
    flow = _flow_with_duration(seconds=20, query_count=100)
    dns = flow.features.dns
    rate = _query_rate(dns, flow, window_secs=60)
    assert rate == 300.0  # 100/20s = 5 qps * 60s window


def test_query_rate_zero_duration_falls_back_to_raw_count():
    flow = _flow_with_duration(seconds=0, query_count=300)
    dns = flow.features.dns
    rate = _query_rate(dns, flow, window_secs=60)
    assert rate == 300.0


def test_fires_on_high_entropy_tunnel(config):
    flow = dns_flow(
        parent="evil.example.com",
        subdomains=["a8f3k2j9d0s7f6g5h4j3k2l1m0n9b8v7c6x5z4"],
        entropy=4.6,
        query_count=300,
    )
    findings = DnsExfilDetector(config).run([flow])
    assert len(findings) == 1
    assert "4.6" in findings[0].evidence
    assert "2.5" in findings[0].evidence


def test_silent_on_benign_dns(config):
    flow = dns_flow("google.com", ["www"], entropy=1.5, query_count=3)
    assert DnsExfilDetector(config).run([flow]) == []


def test_allowlisted_cdn_suppressed(config):
    flow = dns_flow(
        "d3ab1c.cloudfront.net",
        ["d3ab1c9f8e7d6c5b4a3f2e1d0c9b8a7f6e5"],
        entropy=4.8,
        query_count=400,
    )
    assert DnsExfilDetector(config).run([flow]) == []
