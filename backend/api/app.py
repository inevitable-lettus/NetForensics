"""FastAPI routes: upload a pcap, read a case, download its PDF. HTTP concerns only
— intake (seal, analyse, store, timestamp) is `backend.intake`, shared with the CLI.

Run from the repo root:  uvicorn backend.api.app:app --reload
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, FastAPI, File, HTTPException, Response, UploadFile

from backend.config import CONFIG, Config
from backend.db.evidence_store import StoredEvidenceCorruptError
from backend.db.interfaces import CaseNotFoundError, CaseRepository
from backend.db.serialization import to_jsonable
from backend.db.storage import Storage
from backend.evidence.timestamp import make_timestamper
from backend.evidence.tsa_client import Timestamper
from backend.ingest.pcap_validation import InvalidCaptureError
from backend.intake import seal_and_store, stage_and_validate
from backend.models import CaseRecord
from backend.report.pdf import build_case_pdf


def create_app(
    storage: Storage | None = None,
    config: Config = CONFIG,
    timestamper: Timestamper | None = None,
) -> FastAPI:
    """`timestamper` is the RFC 3161 hook (`timestamp.make_timestamper`, #11); the
    module-level `app` wires the real one. Without one, or when the TSA is
    unreachable, cases are stored with a PENDING seal and retried later."""
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
    try:
        return cases.load(case_id)
    except CaseNotFoundError as error:
        raise HTTPException(status_code=404, detail="Case not found.") from error


app = create_app(timestamper=make_timestamper(CONFIG))
