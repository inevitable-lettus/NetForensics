"""Storage contracts the rest of the system depends on (Phase 3 step 6).

Callers — the API, the CLI and the core evidence layer (custody chain, verify) —
program against these Protocols, never against SQLite or the filesystem directly.
The storage layer only *persists*: it never computes a custody hash, never decides
whether a chain is valid and never issues an integrity verdict (the evidence store
re-hashes on write only to refuse mislabelled bytes). Those are core-logic jobs
(`backend/evidence/`); keeping them out of here is what lets the core plug in
without touching storage, and lets storage be swapped without touching the core.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Protocol

from backend.models import CaseRecord, CustodyEntry

_CASE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")


class CaseNotFoundError(LookupError):
    """No case exists under the requested id."""


class CaseExistsError(ValueError):
    """A case with this id was already saved — case records are write-once."""


class SealUpdateError(ValueError):
    """A seal change other than its single PENDING -> GRANTED timestamp."""


class EvidenceMismatchError(ValueError):
    """Bytes offered to the evidence store do not hash to the name they claim."""


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
    """Write-once store of analysis results. No delete; the only update is a
    PENDING seal receiving its RFC 3161 token, once."""

    def save(self, record: CaseRecord) -> None: ...

    def load(self, case_id: str) -> CaseRecord: ...

    def record_timestamp(
        self, case_id: str, token: bytes, gen_time: datetime, tsa_url: str
    ) -> None: ...


class CustodyLog(Protocol):
    """Append-only persistence for custody entries, one ordered log per case.

    `append` only checks *position* (the entry's index is the next free slot). It
    does not check `prev_hash` / `entry_hash` — linking and verifying the chain is
    the core custody module's job, and a log that silently refused a broken link
    would hide exactly the tampering verification exists to expose. `payload` must
    be JSON-native (str/int/float/bool/None, lists, dicts) and round-trips exactly.
    """

    def append(self, entry: CustodyEntry) -> None: ...

    def entries(self, case_id: str) -> tuple[CustodyEntry, ...]: ...

    def head(self, case_id: str) -> CustodyEntry | None: ...


class EvidenceStore(Protocol):
    """Content-addressed, write-once store for evidence files (the pcaps).

    An upload is first streamed into a per-case staging area; once sealed, it is
    committed under its SHA-256 digest. `commit` re-hashes the bytes (through the
    one shared `hash_file`) and refuses them if they do not match the claimed name.
    """

    def stage_upload(
        self, case_id: str, filename: str, read_chunk: Callable[[], bytes], max_bytes: int
    ) -> Path: ...

    def commit(self, staged_path: Path, sha256_hex: str) -> Path: ...

    def discard_staged(self, case_id: str) -> None: ...

    def path_for(self, sha256_hex: str) -> Path: ...
