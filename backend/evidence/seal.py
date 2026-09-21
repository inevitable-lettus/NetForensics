"""Stage 1 — seal a pcap the moment it arrives, before any analysis touches it.

Two digests over the same bytes in one streaming pass: BLAKE3 (primary) and
SHA-256 (what the RFC 3161 TSA timestamps, and what openssl / courts recognise).
Sealing stays pure hashing — timestamping is a separate step, so an offline TSA
can never block or corrupt the seal.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timezone

import blake3

from backend.config import CONFIG
from backend.models import SealRecord


@dataclass(frozen=True)
class FileDigests:
    """Both digests plus the exact byte count they cover. Shared by sealing and
    verification so there is ONE hashing code path, not two that could drift."""

    blake3_hex: str
    sha256_hex: str
    size_bytes: int


def hash_file(path: str, chunk_bytes: int | None = None) -> FileDigests:
    """Stream the file once, feeding every chunk to both hashers. Memory stays
    flat regardless of capture size (incremental update == one-shot digest)."""
    chunk_bytes = chunk_bytes or CONFIG.evidence.hash_chunk_bytes
    blake3_hasher = blake3.blake3()
    sha256_hasher = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while chunk := f.read(chunk_bytes):
            blake3_hasher.update(chunk)
            sha256_hasher.update(chunk)
            size += len(chunk)
    return FileDigests(blake3_hasher.hexdigest(), sha256_hasher.hexdigest(), size)


def seal_pcap(path: str) -> SealRecord:
    """Hash the pcap at `path` and return its SealRecord (timestamp PENDING).

    `received_at` is taken before hashing: custody begins when handling begins,
    not when a multi-GB hash finishes. Always UTC — local time is ambiguous.
    """
    received_at = datetime.now(timezone.utc)
    digests = hash_file(path)
    return SealRecord(
        pcap_filename=os.path.basename(path),
        pcap_size_bytes=digests.size_bytes,
        hash_algorithm=CONFIG.evidence.hash_algorithm,
        pcap_hash=digests.blake3_hex,
        sha256_hash=digests.sha256_hex,
        received_at=received_at,
    )
