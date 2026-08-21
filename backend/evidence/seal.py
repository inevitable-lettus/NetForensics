"""Stage 1 — seal a pcap the moment it arrives, before any analysis touches it."""

from __future__ import annotations
from datetime import datetime, timezone
import blake3
from backend.models import SealRecord
import os

def seal_pcap(path: str) -> SealRecord:
    """Hash the pcap at `path` and return its SealRecord.

    Steps:
    1. Read the file's raw bytes
    2. Hash those bytes with BLAKE3, get the hex digest.
    3. Note the file size and the current UTC time.
    4. Build and return the SealRecord.
    """

    with open(path, "rb") as f:
        data = f.read()
    digest = blake3.blake3(data).hexdigest()

    size = len(data)
    recieved_at = datetime.now(timezone.utc)
    pcap_filename = os.path.basename(path)
    hash_algorithm = 'blake3'

    return SealRecord(
        pcap_filename,
        size,
        hash_algorithm,
        digest,
        recieved_at
    )
    