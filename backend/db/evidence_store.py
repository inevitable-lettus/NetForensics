"""Content-addressed, write-once evidence store for uploaded pcaps.

Layout under the store root:
    staging/<case_id>/<filename>     upload in progress (not yet sealed)
    blobs/<sha256 hex>               committed evidence, read-only (0o444)

Committing re-hashes the staged file with the shared `hash_file` and refuses it if
the SHA-256 does not match the name it is being stored under. It is then hard-linked
into place on the same filesystem, so the sealed bytes are never rewritten. Identical
evidence uploaded twice maps to one blob, and an existing blob is never overwritten.
SHA-256 names the blob because it is the digest the RFC 3161 token covers, so a
blob can be checked against its timestamp with stock tools (`openssl ts -verify`).
"""

from __future__ import annotations

import os
import re
import shutil
from collections.abc import Callable
from pathlib import Path

from backend.db.interfaces import EvidenceMismatchError, validate_case_id
from backend.evidence.seal import hash_file

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_READ_ONLY = 0o444


class EvidenceNotFoundError(LookupError):
    """No committed evidence exists under the requested digest."""


class ContentAddressedEvidenceStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.staging = root / "staging"
        self.blobs = root / "blobs"

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

    def commit(self, staged_path: Path, sha256_hex: str) -> Path:
        """Move a sealed upload to its content address and make it read-only. If the
        same evidence is already stored, the staged copy is dropped. The staging
        directory is removed either way, including when the bytes are refused."""
        if not staged_path.resolve().is_relative_to(self.staging.resolve()):
            raise ValueError(f"{staged_path} is not a staged upload.")
        destination = self._blob_path(sha256_hex)
        try:
            actual = hash_file(str(staged_path)).sha256_hex
            if actual != sha256_hex:
                raise EvidenceMismatchError(
                    f"Staged bytes hash to SHA-256 {actual}, not the claimed {sha256_hex}."
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            self._link_once(staged_path, destination)
        finally:
            shutil.rmtree(staged_path.parent, ignore_errors=True)
        return destination

    @staticmethod
    def _link_once(staged_path: Path, destination: Path) -> None:
        """Hard-link the staged file into place. `os.link` refuses an existing
        target atomically, so two concurrent commits of the same evidence can never
        overwrite a stored blob; the loser simply keeps the existing one."""
        try:
            os.link(staged_path, destination)
        except FileExistsError:
            return
        destination.chmod(_READ_ONLY)

    def discard_staged(self, case_id: str) -> None:
        """Remove an upload that never got sealed (failed validation / oversize)."""
        shutil.rmtree(self.staging / validate_case_id(case_id), ignore_errors=True)

    def path_for(self, sha256_hex: str) -> Path:
        path = self._blob_path(sha256_hex)
        if not path.is_file():
            raise EvidenceNotFoundError(sha256_hex)
        return path

    def _blob_path(self, sha256_hex: str) -> Path:
        if not _SHA256_HEX.fullmatch(sha256_hex):
            raise ValueError(f"Not a SHA-256 hex digest: {sha256_hex!r}")
        return self.blobs / sha256_hex
