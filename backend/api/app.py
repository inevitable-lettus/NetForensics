"""FastAPI routes: upload a pcap, read a case, download its PDF. HTTP concerns only
— all analysis is delegated to `backend.pipeline`, persistence to `CaseStore`.

Run from the repo root:  uvicorn backend.api.app:app --reload
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, File, HTTPException, Response, UploadFile

from backend.config import CONFIG, Config
from backend.db.case_store import CaseNotFoundError, CaseStore
from backend.db.serialization import to_jsonable
from backend.ingest.pcap_validation import InvalidCaptureError, validate_pcap_file
from backend.pipeline import analyze_pcap
from backend.report.pdf import build_case_pdf


def create_app(store: CaseStore | None = None, config: Config = CONFIG) -> FastAPI:
    store = store or CaseStore(Path(config.evidence.evidence_store_dir) / "cases")
    router = APIRouter(prefix="/api")

    @router.post("/cases", status_code=201)
    def create_case(file: UploadFile = File(...)) -> dict[str, Any]:
        case_id = store.new_case_id()
        try:
            pcap_path = store.write_upload(
                case_id,
                file.filename or "upload.pcap",
                lambda: file.file.read(config.ingest.upload_chunk_bytes),
                config.ingest.max_upload_bytes,
            )
            validate_pcap_file(pcap_path)
        except ValueError as error:  # oversize, or InvalidCaptureError (a ValueError)
            store.discard(case_id)
            status = 400 if isinstance(error, InvalidCaptureError) else 413
            raise HTTPException(status_code=status, detail=str(error)) from error
        record = analyze_pcap(case_id, str(pcap_path), config)
        store.save(record)
        return to_jsonable(record)

    @router.get("/cases/{case_id}")
    def get_case(case_id: str) -> dict[str, Any]:
        return to_jsonable(_load_or_404(store, case_id))

    @router.get("/cases/{case_id}/report.pdf")
    def get_report(case_id: str) -> Response:
        pdf = build_case_pdf(_load_or_404(store, case_id))
        return Response(
            pdf,
            media_type="application/pdf",
            headers={"Content-Disposition": f'inline; filename="case-{case_id}.pdf"'},
        )

    app = FastAPI(title="NetForensics")
    app.include_router(router)
    return app


def _load_or_404(store: CaseStore, case_id: str):
    try:
        return store.load(case_id)
    except CaseNotFoundError as error:
        raise HTTPException(status_code=404, detail="Case not found.") from error


app = create_app()
