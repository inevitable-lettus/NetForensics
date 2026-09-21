"""Model <-> JSON-safe dict conversion. One place, used by both the case store and
the API, so the on-disk and on-wire shapes cannot drift apart."""

from __future__ import annotations

import base64
import dataclasses
from datetime import datetime
from enum import Enum
from typing import Any

from backend.models import CaseRecord, Finding, SealRecord, Severity, TimestampStatus


def to_jsonable(value: Any) -> Any:
    """Recursively convert models to plain JSON types. Enums -> value, datetimes ->
    ISO-8601, bytes -> base64 (the RFC 3161 token), dataclasses -> dicts."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    return value


def _optional_datetime(raw: str | None) -> datetime | None:
    return datetime.fromisoformat(raw) if raw is not None else None


def seal_from_dict(raw: dict[str, Any]) -> SealRecord:
    token = raw["rfc3161_token"]
    return SealRecord(
        pcap_filename=raw["pcap_filename"],
        pcap_size_bytes=raw["pcap_size_bytes"],
        hash_algorithm=raw["hash_algorithm"],
        pcap_hash=raw["pcap_hash"],
        sha256_hash=raw["sha256_hash"],
        received_at=datetime.fromisoformat(raw["received_at"]),
        timestamp_status=TimestampStatus(raw["timestamp_status"]),
        rfc3161_token=base64.b64decode(token) if token is not None else None,
        timestamp_gen_time=_optional_datetime(raw["timestamp_gen_time"]),
        tsa_url=raw["tsa_url"],
    )


def finding_from_dict(raw: dict[str, Any]) -> Finding:
    return Finding(
        detector=raw["detector"],
        what=raw["what"],
        why=raw["why"],
        supporting_data=raw["supporting_data"],
        evidence=raw["evidence"],
        severity=Severity(raw["severity"]),
    )


def case_from_dict(raw: dict[str, Any]) -> CaseRecord:
    return CaseRecord(
        case_id=raw["case_id"],
        seal=seal_from_dict(raw["seal"]),
        findings=tuple(finding_from_dict(f) for f in raw["findings"]),
        flow_count=raw["flow_count"],
    )
