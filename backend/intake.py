"""Case intake — the one path a pcap takes from "offered" to "stored case", shared by
the API and the CLI so both seal, store and timestamp evidence the same way.

    stage_and_validate : stream the bytes into staging, check it is a real capture
    seal_and_store     : seal + analyse, commit the blob, save the case, one TSA try

Interface concerns (HTTP status codes, CLI exit codes, printing) stay with the
callers; this module only raises the typed errors they translate.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from backend.config import Config
from backend.db.interfaces import CaseRepository
from backend.db.storage import Storage
from backend.evidence.tsa_client import Timestamper, retry_pending
from backend.ingest.pcap_validation import validate_pcap_file
from backend.models import CaseRecord
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
