"""Row <-> model mapping for the `cases`, `seals` and `findings` tables. Kept apart
from the repository so the SQL there stays readable. Datetimes are stored as
ISO-8601 text and the RFC 3161 token as a raw BLOB."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from backend.models import Finding, SealRecord, Severity, TimestampStatus

SEAL_COLUMNS = (
    "case_id, pcap_filename, pcap_size_bytes, hash_algorithm, pcap_hash, sha256_hash,"
    " received_at, timestamp_status, rfc3161_token, timestamp_gen_time, tsa_url"
)
FINDING_COLUMNS = (
    "case_id, position, detector, what, why, supporting_data_json, evidence, severity"
)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _from_iso(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value is not None else None


def seal_to_row(case_id: str, seal: SealRecord) -> tuple[Any, ...]:
    return (
        case_id,
        seal.pcap_filename,
        seal.pcap_size_bytes,
        seal.hash_algorithm,
        seal.pcap_hash,
        seal.sha256_hash,
        seal.received_at.isoformat(),
        seal.timestamp_status.value,
        seal.rfc3161_token,
        _iso(seal.timestamp_gen_time),
        seal.tsa_url,
    )


def seal_from_row(row: tuple[Any, ...]) -> SealRecord:
    _case_id, filename, size, algorithm, pcap_hash, sha256, received, status, token, gen, tsa = row
    return SealRecord(
        pcap_filename=filename,
        pcap_size_bytes=size,
        hash_algorithm=algorithm,
        pcap_hash=pcap_hash,
        sha256_hash=sha256,
        received_at=datetime.fromisoformat(received),
        timestamp_status=TimestampStatus(status),
        rfc3161_token=bytes(token) if token is not None else None,
        timestamp_gen_time=_from_iso(gen),
        tsa_url=tsa,
    )


def finding_to_row(case_id: str, position: int, finding: Finding) -> tuple[Any, ...]:
    return (
        case_id,
        position,
        finding.detector,
        finding.what,
        finding.why,
        json.dumps(finding.supporting_data),
        finding.evidence,
        finding.severity.value,
    )


def finding_from_row(row: tuple[Any, ...]) -> Finding:
    _case_id, _position, detector, what, why, supporting, evidence, severity = row
    return Finding(
        detector=detector,
        what=what,
        why=why,
        supporting_data=json.loads(supporting),
        evidence=evidence,
        severity=Severity(severity),
    )
