"""Shared data models — the single source of truth for shapes that flow through the
pipeline. Defined once here and reused everywhere (CLAUDE.md DRY rule).

Stages produce and consume these in one direction:
    pcap -> SealRecord -> [Flow + Features] -> Finding -> CustodyEntry -> PDF

No stage reaches backwards; no model carries hidden state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# --------------------------------------------------------------------------- #
# Stage 2 — Parse to Flows
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DnsFeatures:
    """Plaintext-DNS fields extracted for the DNS-exfil detector."""

    parent_domain: str
    subdomains: tuple[str, ...]
    query_count: int
    max_subdomain_entropy: float
    max_subdomain_length: int


@dataclass(frozen=True)
class TlsFeatures:
    """TLS handshake parameters for the malicious-TLS-client detector."""

    ja3: str | None
    ja3_string: str | None
    server_name: str | None


@dataclass(frozen=True)
class Features:
    """Per-flow extracted features. Protocol-specific sub-features are optional —
    only populated when the flow carries that protocol."""

    packet_count: int
    byte_count: int
    inter_arrival_times: tuple[float, ...] = ()
    dns: DnsFeatures | None = None
    tls: TlsFeatures | None = None


@dataclass(frozen=True)
class Flow:
    """One connection flow (a 5-tuple aggregate), with its extracted features.

    A flow is the unit detectors consume — they never re-read raw packets
    (CLAUDE.md: single-pass over large captures).
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "tcp" | "udp" | ...
    start_time: datetime
    end_time: datetime
    features: Features

    @property
    def five_tuple(self) -> tuple[str, str, int, int, str]:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)


# --------------------------------------------------------------------------- #
# Stage 3 — Findings (the explainability contract)
# --------------------------------------------------------------------------- #


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Finding:
    """A detector result. Carries the full explainability contract (logic.md):
    WHAT was flagged, WHY it is suspicious, and the SUPPORTING DATA (measured
    number vs. benign baseline). No confidence scores — Hard Rule 1.

    `evidence` is the single human-readable line a magistrate can follow; it is
    derived from the structured fields, not a free-floating claim.
    """

    detector: str            # detector that emitted this (e.g. "dns_exfil")
    what: str                # entity flagged: domain / host-pair / src IP / fingerprint
    why: str                 # plain-language reason
    supporting_data: dict[str, object]  # measured values + baselines they exceed
    evidence: str            # courtroom-ready sentence
    severity: Severity = Severity.MEDIUM


# --------------------------------------------------------------------------- #
# Stages 1 & 4 — Evidence-integrity layer (the differentiator)
# --------------------------------------------------------------------------- #


class TimestampStatus(str, Enum):
    GRANTED = "granted"   # TSA returned a token binding the SHA-256 to its clock
    PENDING = "pending"   # TSA unreachable at ingest — retried later, never faked


@dataclass(frozen=True)
class SealRecord:
    """The digital evidence-bag seal, created in Stage 1 BEFORE any analysis.

    Establishes "this is the exact evidence, unaltered, as received at this time."
    Two digests over the same bytes: BLAKE3 (primary, fast) and SHA-256 (the digest
    the RFC 3161 TSA timestamps, and the one openssl / courts already recognise).
    `rfc3161_token` is the DER-encoded timestamp token, or None while PENDING.
    `timestamp_gen_time` is the TSA's clock, not ours — compare with `received_at`.
    """

    pcap_filename: str
    pcap_size_bytes: int
    hash_algorithm: str       # "blake3"
    pcap_hash: str            # BLAKE3 hex digest of the entire pcap
    sha256_hash: str          # SHA-256 hex digest of the same bytes
    received_at: datetime
    timestamp_status: TimestampStatus = TimestampStatus.PENDING
    rfc3161_token: bytes | None = None
    timestamp_gen_time: datetime | None = None
    tsa_url: str | None = None


@dataclass(frozen=True)
class CustodyEntry:
    """One link in the append-only, hash-chained chain of custody (Stage 4).

    Each entry references the prior entry's hash, so no entry can be altered or
    removed without breaking every later link. Genuine tamper-evidence, not
    cosmetic (Hard Rule 3). Entry 0's prev_hash is bound to the seal, so a chain
    cannot be transplanted onto different evidence.
    """

    case_id: str              # the sealed evidence this chain belongs to
    index: int                # 0-based position in the chain
    timestamp: datetime
    event_type: str           # "ingest" | "parse" | "finding" | "report" | "verify" | ...
    detail: str               # human-readable description of the event
    prev_hash: str            # entry_hash of the previous entry (seal-derived for genesis)
    entry_hash: str           # hash over ALL fields above AND payload — nothing unhashed
    payload: dict[str, object] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Verification results — the explainability contract, applied to integrity
# --------------------------------------------------------------------------- #


class Verdict(str, Enum):
    INTACT = "intact"            # every check passed
    ALTERED = "altered"          # at least one check failed — custody broken
    INCOMPLETE = "incomplete"    # nothing failed, but a timestamp is still PENDING


@dataclass(frozen=True)
class CheckResult:
    """One integrity check. `evidence` is the sentence a magistrate reads —
    the measured value vs. the sealed value, never a bare pass/fail.
    `passed` is None when the check could not run yet (e.g. PENDING token)."""

    name: str
    passed: bool | None
    evidence: str


@dataclass(frozen=True)
class VerificationReport:
    verdict: Verdict
    checks: tuple[CheckResult, ...]
