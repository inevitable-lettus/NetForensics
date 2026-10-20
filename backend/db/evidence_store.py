"""Content-addressed, write-once evidence store for uploaded pcaps.

Layout under the store root:
    staging/<case_id>/<filename>     upload in progress (not yet sealed)
    objects/<aa>/<blake3 hex>        committed evidence, read-only (0o444)

Committing is a rename on the same filesystem, so the sealed bytes are moved, never
rewritten. Identical evidence uploaded twice maps to one object (same digest).
"""

from __future__ import annotations

import os
import re
import shutil
from collections.abc import Callable
from pathlib import Path

from backend.db.interfaces import validate_case_id

_BLAKE3_HEX = re.compile(r"^[0-9a-f]{64}$")
_READ_ONLY = 0o444


class EvidenceNotFoundError(LookupError):
    """No committed evidence exists under the requested digest."""


class ContentAddressedEvidenceStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.staging = root / "staging"
        self.objects = root / "objects"

    def stage_upload(
        self, case_id: str, filename: str, read_chunk: Callable[[], bytes], max_bytes: int
    ) -> Path:
        """Stream an upload into staging. Raises `ValueError` if it exceeds
        `max_bytes`; the caller cleans up via `discard_staged`. The filename is
        reduced to its basename so it cannot escape the staging directory."""
        directory = self.staging / validate_case_id(case_id)
        directory.mkdir(parents=True, exist_ok=False)
        destination = directory / (Path(filename).name or "upload.pcap")
        written = 0
        with destination.open("wb") as out:
            while chunk := read_chunk():
                written += len(chunk)
                if written > max_bytes:
                    raise ValueError(f"Upload exceeds the {max_bytes}-byte limit.")
                out.write(chunk)
        return destination

    def commit(self, staged_path: Path, blake3_hex: str) -> Path:
        """Move a sealed upload to its content address and make it read-only. If the
        same evidence is already stored, the staged copy is dropped. The staging
        directory is removed either way."""
        if not staged_path.resolve().is_relative_to(self.staging.resolve()):
            raise ValueError(f"{staged_path} is not a staged upload.")
        destination = self._object_path(blake3_hex)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            staged_path.unlink()
        else:
            os.replace(staged_path, destination)
            destination.chmod(_READ_ONLY)
        staged_path.parent.rmdir()
        return destination

    def discard_staged(self, case_id: str) -> None:
        """Remove an upload that never got sealed (failed validation / oversize)."""
        shutil.rmtree(self.staging / validate_case_id(case_id), ignore_errors=True)

    def path_for(self, blake3_hex: str) -> Path:
        path = self._object_path(blake3_hex)
        if not path.is_file():
            raise EvidenceNotFoundError(blake3_hex)
        return path

    def _object_path(self, blake3_hex: str) -> Path:
        if not _BLAKE3_HEX.fullmatch(blake3_hex):
            raise ValueError(f"Not a BLAKE3 hex digest: {blake3_hex!r}")
        return self.objects / blake3_hex[:2] / blake3_hex
