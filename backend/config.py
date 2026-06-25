"""Single source of truth for thresholds, baselines, and allowlists (CLAUDE.md:
one source of truth — no magic numbers scattered across detectors).

Values marked PROPOSED are starting points to tune against real captures
(Phase 4). Values from the solution proposal (DNS entropy baselines) are kept
as-is. Detectors import these constants; they never hard-code numbers.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Detector thresholds
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DnsExfilConfig:
    benign_entropy_baseline: float = 2.5    # benign subdomains sit near here
    entropy_threshold: float = 4.2          # encoded data reaches ~4.2+
    subdomain_length_threshold: int = 30    # PROPOSED — long subdomains signal tunneling
    query_rate_threshold: int = 50          # PROPOSED — queries to one parent per 60s window
    query_rate_window_secs: int = 60


@dataclass(frozen=True)
class C2BeaconConfig:
    min_connections: int = 10               # PROPOSED — need enough samples to call regularity
    max_coefficient_of_variation: float = 0.1  # PROPOSED — CV below this = robotic regularity


@dataclass(frozen=True)
class PortScanConfig:
    distinct_ports_threshold: int = 100     # PROPOSED — fan-out cutoff for one source
    distinct_hosts_threshold: int = 10      # PROPOSED
    window_secs: int = 10                   # PROPOSED — time window for fan-out


@dataclass(frozen=True)
class TlsClientConfig:
    sslbl_cache_path: str = "sample-pcaps/sslbl_ja3.cache"  # local cache of abuse.ch feed


# --------------------------------------------------------------------------- #
# False-positive allowlists (logic.md: human stays in the loop, but suppress noise)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Allowlists:
    # Legitimately high-entropy parent domains (CDNs / cloud) — suppress DNS-exfil FPs.
    dns_parent_domains: tuple[str, ...] = (
        "cloudfront.net",
        "akamaihd.net",
        "googleusercontent.com",
        "amazonaws.com",
    )
    # Legitimately regular timing (heartbeats / keep-alives) — suppress beacon FPs.
    beacon_dst_ips: tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# Evidence-integrity layer
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class EvidenceConfig:
    hash_algorithm: str = "blake3"
    # RFC 3161 TSA + offline fallback (open risk #1 — must not hard-fail on demo wifi).
    tsa_url: str = "https://freetsa.org/tsr"
    tsa_timeout_secs: int = 5
    allow_offline_fallback: bool = True


# --------------------------------------------------------------------------- #
# Top-level config aggregate
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Config:
    dns_exfil: DnsExfilConfig = field(default_factory=DnsExfilConfig)
    c2_beacon: C2BeaconConfig = field(default_factory=C2BeaconConfig)
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    tls_client: TlsClientConfig = field(default_factory=TlsClientConfig)
    allowlists: Allowlists = field(default_factory=Allowlists)
    evidence: EvidenceConfig = field(default_factory=EvidenceConfig)


# Default singleton — import this. Construct a fresh Config(...) in tests to override.
CONFIG = Config()
