"""FastAPI routes: upload a pcap, read a case, verify it, run the tamper test, download
its PDF. HTTP concerns only — intake is `backend.intake` and verification is
`backend.case_verification`, both shared with the CLI.

Run from the repo root:  uvicorn backend.api.app:app --reload
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any, TypeVar

from fastapi import APIRouter, FastAPI, File, HTTPException, Response, UploadFile

from backend.case_verification import record_verification, tamper_test, verify_stored
from backend.config import CONFIG, Config
from backend.db.evidence_store import EvidenceNotFoundError, StoredEvidenceCorruptError
from backend.db.interfaces import CaseNotFoundError, CaseRepository
from backend.db.serialization import to_jsonable
from backend.db.storage import Storage
from backend.evidence.timestamp import TokenVerifier, make_timestamper
from backend.evidence.tsa_client import Timestamper
from backend.ingest.pcap_validation import InvalidCaptureError
from backend.intake import seal_and_store, stage_and_validate
from backend.models import CaseRecord, ChainAnchor
from backend.report.pdf import build_case_pdf

T = TypeVar("T")


def create_app(
    storage: Storage | None = None,
    config: Config = CONFIG,
    timestamper: Timestamper | None = None,
    verify_token: TokenVerifier | None = None,
) -> FastAPI:
    """`timestamper` is the RFC 3161 hook (`timestamp.make_timestamper`, #11); the
    module-level `app` wires the real one. Without one, or when the TSA is
    unreachable, cases are stored with a PENDING seal and retried later.
    `verify_token` replaces the pinned-certificate token check (tests only)."""
    storage = storage or Storage.open(config.evidence)
    router = APIRouter(prefix="/api")

    @router.post("/cases", status_code=201)
    def create_case(file: UploadFile = File(...)) -> dict[str, Any]:
        case_id = uuid.uuid4().hex
        try:
            staged = stage_and_validate(
                storage,
                case_id,
                file.filename or "upload.pcap",
                lambda: file.file.read(config.ingest.upload_chunk_bytes),
                config,
            )
        except ValueError as error:  # oversize, or InvalidCaptureError (a ValueError)
            status = 400 if isinstance(error, InvalidCaptureError) else 413
            raise HTTPException(status_code=status, detail=str(error)) from error
        try:
            record = seal_and_store(storage, case_id, staged, config, timestamper)
        except StoredEvidenceCorruptError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return to_jsonable(record)

    @router.get("/cases/{case_id}")
    def get_case(case_id: str) -> dict[str, Any]:
        return to_jsonable(_load_or_404(storage.cases, case_id))

    @router.post("/cases/{case_id}/verify")
    def verify(case_id: str) -> dict[str, Any]:
        """Re-hash and re-check the case. Recorded in its custody chain (and the head
        re-anchored) unless ALTERED, which is left exactly as found."""
        report = _or_404(lambda: verify_stored(storage, case_id, config, verify_token))
        anchor = record_verification(storage, case_id, report, timestamper, config)
        return to_jsonable(report) | {"recorded": anchor is not None,
                                      "anchor": _anchor_json(anchor)}

    @router.post("/cases/{case_id}/tamper-test")
    def run_tamper_test(case_id: str) -> dict[str, Any]:
        """Demo: verify a throwaway copy, flip one bit of it, verify again. The stored
        case, its file and its custody chain are never changed."""
        try:
            result = _or_404(lambda: tamper_test(storage, case_id, config, verify_token))
        except EvidenceNotFoundError as error:
            raise HTTPException(status_code=409, detail="The stored evidence file is missing; "
                                "verify the case to see the full report.") from error
        return to_jsonable(result)

    @router.get("/cases/{case_id}/report.pdf")
    def get_report(case_id: str) -> Response:
        pdf = build_case_pdf(_load_or_404(storage.cases, case_id))
        return Response(
            pdf,
            media_type="application/pdf",
            headers={"Content-Disposition": f'inline; filename="case-{case_id}.pdf"'},
        )

    app = FastAPI(title="NetForensics")
    app.include_router(router)
    return app


def _load_or_404(cases: CaseRepository, case_id: str) -> CaseRecord:
    return _or_404(lambda: cases.load(case_id))


def _or_404(run: Callable[[], T]) -> T:
    try:
        return run()
    except CaseNotFoundError as error:
        raise HTTPException(status_code=404, detail="Case not found.") from error


def _anchor_json(anchor: ChainAnchor | None) -> dict[str, Any] | None:
    """The anchor a holder should keep a copy of; the token itself stays server-side."""
    if anchor is None:
        return None
    return {"head_index": anchor.head_index, "head_hash": anchor.head_hash,
            "timestamp_status": anchor.timestamp_status.value,
            "timestamp_gen_time": to_jsonable(anchor.timestamp_gen_time)}


app = create_app(timestamper=make_timestamper(CONFIG))
