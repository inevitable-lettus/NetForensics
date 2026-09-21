"""Interim case persistence: one directory per case holding the uploaded pcap and a
`case.json` with the results. Phase 3 step 6 replaces this with the append-only
SQLite store and content-addressed evidence store; the `CaseStore` interface is
what callers depend on, so that swap stays local.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Callable
from pathlib import Path

from backend.db.serialization import case_from_dict, to_jsonable
from backend.models import CaseRecord

_CASE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_CASE_FILE = "case.json"


class CaseNotFoundError(LookupError):
    """No case exists under the requested id."""


class CaseStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    @staticmethod
    def new_case_id() -> str:
        return uuid.uuid4().hex

    def case_dir(self, case_id: str) -> Path:
        """Directory for a case. The id is validated against a strict pattern, so a
        crafted id ("../x") can never escape the store root."""
        if not _CASE_ID_PATTERN.fullmatch(case_id):
            raise CaseNotFoundError(case_id)
        return self.root / case_id

    def write_upload(
        self, case_id: str, filename: str, read_chunk: Callable[[], bytes], max_bytes: int
    ) -> Path:
        """Stream an upload into the case directory. Raises `ValueError` if it
        exceeds `max_bytes`; the caller cleans up via `discard`."""
        directory = self.case_dir(case_id)
        directory.mkdir(parents=True, exist_ok=False)
        destination = directory / Path(filename).name
        written = 0
        with destination.open("wb") as out:
            while chunk := read_chunk():
                written += len(chunk)
                if written > max_bytes:
                    raise ValueError(f"Upload exceeds the {max_bytes}-byte limit.")
                out.write(chunk)
        return destination

    def save(self, record: CaseRecord) -> None:
        path = self.case_dir(record.case_id) / _CASE_FILE
        path.write_text(json.dumps(to_jsonable(record), indent=2), encoding="utf-8")

    def load(self, case_id: str) -> CaseRecord:
        path = self.case_dir(case_id) / _CASE_FILE
        if not path.is_file():
            raise CaseNotFoundError(case_id)
        return case_from_dict(json.loads(path.read_text(encoding="utf-8")))

    def discard(self, case_id: str) -> None:
        """Remove a case that never completed (failed validation / oversize)."""
        directory = self.case_dir(case_id)
        if directory.is_dir():
            for child in directory.iterdir():
                child.unlink()
            directory.rmdir()
