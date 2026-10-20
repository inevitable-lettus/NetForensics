"""FastAPI routes: upload a pcap, read a case, download its PDF. HTTP concerns only
— all analysis is delegated to `backend.pipeline`, persistence to `Storage`.

Run from the repo root:  uvicorn backend.api.app:app --reload
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, File, HTTPException, Response, UploadFile

from backend.config import CONFIG, Config
from backend.db.interfaces import CaseNotFoundError, CaseRepository
from backend.db.serialization import to_jsonable
from backend.db.storage import Storage
from backend.ingest.pcap_validation import InvalidCaptureError, validate_pcap_file
from backend.models import CaseRecord
from backend.pipeline import analyze_pcap
from backend.report.pdf import build_case_pdf


def create_app(storage: Storage | None = None, config: Config = CONFIG) -> FastAPI:
    storage = storage or Storage.open(config.evidence)
    router = APIRouter(prefix="/api")

    @router.post("/cases", status_code=201)
    def create_case(file: UploadFile = File(...)) -> dict[str, Any]:
        case_id = uuid.uuid4().hex
        try:
            staged = storage.evidence.stage_upload(
                case_id,
                file.filename or "upload.pcap",
                lambda: file.file.read(config.ingest.upload_chunk_bytes),
                config.ingest.max_upload_bytes,
            )
            validate_pcap_file(staged)
        except ValueError as error:  # oversize, or InvalidCaptureError (a ValueError)
            storage.evidence.discard_staged(case_id)
            status = 400 if isinstance(error, InvalidCaptureError) else 413
            raise HTTPException(status_code=status, detail=str(error)) from error
        record = _analyze_and_commit(storage, case_id, staged, config)
        storage.cases.save(record)
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


def _analyze_and_commit(
    storage: Storage, case_id: str, staged: Path, config: Config
) -> CaseRecord:
    """Seal + analyse the staged upload, then move it to its content address. The
    seal is taken on the staged bytes; the commit is a rename, so they never change."""
    try:
        record = analyze_pcap(case_id, str(staged), config)
    except Exception:
        storage.evidence.discard_staged(case_id)
        raise
    storage.evidence.commit(staged, record.seal.pcap_hash)
    return record


def _load_or_404(cases: CaseRepository, case_id: str) -> CaseRecord:
    try:
        return cases.load(case_id)
    except CaseNotFoundError as error:
        raise HTTPException(status_code=404, detail="Case not found.") from error


app = create_app()
