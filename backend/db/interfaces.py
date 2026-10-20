"""Storage contracts the rest of the system depends on (Phase 3 step 6).

Callers — the API, the CLI and the core evidence layer (custody chain, verify) —
program against these Protocols, never against SQLite or the filesystem directly.
The storage layer only *persists*: it never computes a custody hash, never decides
whether a chain is valid and never re-hashes evidence. Those are core-logic jobs
(`backend/evidence/`); keeping them out of here is what lets the core plug in
without touching storage, and lets storage be swapped without touching the core.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from backend.models import CaseRecord, CustodyEntry

_CASE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")


class CaseNotFoundError(LookupError):
    """No case exists under the requested id."""


class CaseExistsError(ValueError):
    """A case with this id was already saved — case records are write-once."""


class CustodyAppendError(ValueError):
    """An entry was rejected because it would not extend the stored log by
    exactly one position (gap, duplicate index, or a race with another writer)."""


def validate_case_id(case_id: str) -> str:
    """Case ids are 32 lowercase hex chars (uuid4().hex). Anything else is treated
    as "not found", so a crafted id ("../x") never reaches a path or a query."""
    if not _CASE_ID_PATTERN.fullmatch(case_id):
        raise CaseNotFoundError(case_id)
    return case_id


class CaseRepository(Protocol):
    """Write-once store of analysis results. No update, no delete."""

    def save(self, record: CaseRecord) -> None: ...

    def load(self, case_id: str) -> CaseRecord: ...


class CustodyLog(Protocol):
    """Append-only persistence for custody entries, one ordered log per case.

    `append` only checks *position* (the entry's index is the next free slot). It
    does not check `prev_hash` / `entry_hash` — linking and verifying the chain is
    the core custody module's job, and a log that silently refused a broken link
    would hide exactly the tampering verification exists to expose.
    """

    def append(self, entry: CustodyEntry) -> None: ...

    def entries(self, case_id: str) -> tuple[CustodyEntry, ...]: ...

    def head(self, case_id: str) -> CustodyEntry | None: ...


class EvidenceStore(Protocol):
    """Content-addressed, write-once store for evidence files (the pcaps).

    An upload is first streamed into a per-case staging area; once sealed, it is
    committed under its BLAKE3 digest. The digest is supplied by the caller (from
    the seal) — the store does not re-hash, so verification stays in the core.
    """

    def stage_upload(
        self, case_id: str, filename: str, read_chunk: Callable[[], bytes], max_bytes: int
    ) -> Path: ...

    def commit(self, staged_path: Path, blake3_hex: str) -> Path: ...

    def discard_staged(self, case_id: str) -> None: ...

    def path_for(self, blake3_hex: str) -> Path: ...
