"""Case intake — the one path a pcap takes from "offered" to "stored case", shared by
the API and the CLI so both seal, store and timestamp evidence the same way.

    stage_and_validate : stream the bytes into staging, check it is a real capture
    seal_and_store     : seal + analyse, commit the blob, save the case, open its
                         custody chain and anchor it, one TSA try
    append_custody     : chain events onto a case, then anchor the new head

Interface concerns (HTTP status codes, CLI exit codes, printing) stay with the
callers; this module only raises the typed errors they translate.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path

from backend.config import Config
from backend.db.interfaces import CaseRepository
from backend.db.storage import Storage
from backend.evidence.anchor import anchor_event, take_anchor
from backend.evidence.custody import CustodyEvent, build_entry
from backend.evidence.tsa_client import Timestamper, retry_pending
from backend.ingest.pcap_validation import validate_pcap_file
from backend.models import CaseRecord, SealRecord
from backend.pipeline import analyze_pcap

logger = logging.getLogger(__name__)


def stage_and_validate(
    storage: Storage, case_id: str, filename: str, read_chunk: Callable[[], bytes],
    config: Config,
) -> Path:
    """Stage an upload and refuse it unless it is a capture. Raises `ValueError` when
    it is over the size limit, or `InvalidCaptureError` (a `ValueError`) when it is
    not a pcap. A refused or interrupted upload never leaves staged bytes behind."""
    try:
        staged = storage.evidence.stage_upload(
            case_id, filename, read_chunk, config.ingest.max_upload_bytes
        )
        validate_pcap_file(staged)
    except BaseException:
        storage.evidence.discard_staged(case_id)
        raise
    return staged


def seal_and_store(
    storage: Storage, case_id: str, staged: Path, config: Config,
    timestamper: Timestamper | None = None,
) -> CaseRecord:
    """Seal and analyse the staged capture, move it to its content address, save the
    case and, if a timestamper is wired in, make one timestamp attempt. The seal is
    taken on the staged bytes; the commit is a hard link, so they never change.
    Raises `StoredEvidenceCorruptError` if identical evidence is already stored but
    no longer matches its hash."""
    try:
        record = analyze_pcap(case_id, str(staged), config)
    except BaseException:
        storage.evidence.discard_staged(case_id)
        raise
    storage.evidence.commit(staged, record.seal.sha256_hash)
    storage.cases.save(record)
    append_custody(storage, record.seal, _intake_events(record), timestamper, config)
    if timestamper is None:
        return record
    return _try_timestamp_once(storage.cases, case_id, timestamper, config)


def _try_timestamp_once(
    cases: CaseRepository, case_id: str, timestamper: Timestamper, config: Config
) -> CaseRecord:
    """One attempt at intake so a caller never waits through backoff. Any failure
    leaves the seal PENDING for `retry_all_pending`; it never fails the intake."""
    try:
        retry_pending(case_id, cases, timestamper, config, attempts=1)
    except Exception:  # noqa: BLE001 — the case is already safely stored as PENDING
        logger.exception("Timestamping case %s failed; seal left PENDING.", case_id)
    return cases.load(case_id)


def append_custody(
    storage: Storage, seal: SealRecord, events: Sequence[CustodyEvent],
    timestamper: Timestamper | None, config: Config,
) -> None:
    """Chain `events` after the stored head, then anchor the new head (one TSA try;
    PENDING if it fails) and record the anchor as a custody event of its own."""
    case_id = events[0].case_id
    head = storage.custody.head(case_id)
    for event in events:
        head = build_entry(seal, head, event, datetime.now(timezone.utc))
        storage.custody.append(head)
    anchor = take_anchor(head, datetime.now(timezone.utc), timestamper, config.evidence.tsa_url)
    storage.anchors.append(anchor)
    storage.custody.append(build_entry(seal, head, anchor_event(anchor), datetime.now(timezone.utc)))


def _intake_events(record: CaseRecord) -> list[CustodyEvent]:
    seal = record.seal
    return [
        CustodyEvent(record.case_id, "ingest",
                     f"Received and sealed {seal.pcap_filename} ({seal.pcap_size_bytes} bytes).",
                     {"pcap_hash": seal.pcap_hash, "sha256_hash": seal.sha256_hash,
                      "pcap_size_bytes": seal.pcap_size_bytes}),
        CustodyEvent(record.case_id, "analyze",
                     f"Analysed: {record.flow_count} flows, {len(record.findings)} findings.",
                     {"flow_count": record.flow_count,
                      "findings": [{"detector": f.detector, "severity": f.severity.value,
                                    "what": f.what} for f in record.findings]}),
    ]
