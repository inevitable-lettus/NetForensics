"""Verifying a stored case — the one path shared by the API and the CLI, so both read,
record and demonstrate verification the same way.

    verify_stored       : load a case from the store and run `verify_case` (read-only)
    record_verification : append the `verify` custody event and anchor the new head,
                          unless the case is ALTERED
    tamper_test         : verify a throwaway COPY of the stored pcap, flip one bit of
                          the copy, verify again; the stored case is never touched

Interface concerns (HTTP status codes, exit codes, printing) stay with the callers.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from backend.config import Config
from backend.db.evidence_store import EvidenceNotFoundError
from backend.db.storage import Storage
from backend.evidence.timestamp import TokenVerifier
from backend.evidence.tsa_client import Timestamper
from backend.evidence.verify import verification_event, verify_case
from backend.intake import append_custody
from backend.models import ChainAnchor, Verdict, VerificationReport


@dataclass(frozen=True)
class TamperTest:
    """Verification of a copy before and after one flipped bit at `flipped_offset`."""

    before: VerificationReport
    after: VerificationReport
    flipped_offset: int


def _blob_path(storage: Storage, sha256_hex: str, config: Config) -> Path:
    """The stored blob, or where it should be: a missing blob is reported by the
    `pcap_digests` check as ALTERED, not raised."""
    try:
        return storage.evidence.path_for(sha256_hex)
    except EvidenceNotFoundError:
        return Path(config.evidence.evidence_store_dir) / "blobs" / sha256_hex


def verify_stored(storage: Storage, case_id: str, config: Config,
                  verify_token: TokenVerifier | None = None,
                  blob: Path | None = None) -> VerificationReport:
    """Read-only: load the case and run every check. Raises CaseNotFoundError.
    `blob` replaces the stored file (tamper_test passes its copy)."""
    seal = storage.cases.load(case_id).seal
    return verify_case(seal, storage.custody.entries(case_id), storage.anchors.anchors(case_id),
                       blob or _blob_path(storage, seal.sha256_hash, config), case_id, config,
                       verify_token)


def record_verification(storage: Storage, case_id: str, report: VerificationReport,
                        timestamper: Timestamper | None, config: Config) -> ChainAnchor | None:
    """Append the verify event and anchor the new head; return that anchor. An ALTERED
    case is left exactly as found and None is returned: writing onto a damaged chain
    would fill the slots of removed entries, change the next diagnosis and anchor a head
    already known to be bad. Storage errors propagate; the caller has the report."""
    if report.verdict is Verdict.ALTERED:
        return None
    seal = storage.cases.load(case_id).seal
    append_custody(storage, seal, [verification_event(case_id, report)], timestamper, config)
    return storage.anchors.anchors(case_id)[-1]


def flip_one_byte(path: Path) -> int:
    """Flip the low bit of the middle byte; return its offset. Lifts read-only first."""
    path.chmod(0o644)
    data = bytearray(path.read_bytes())
    offset = len(data) // 2
    data[offset] ^= 0x01
    path.write_bytes(bytes(data))
    return offset


def tamper_test(storage: Storage, case_id: str, config: Config,
                verify_token: TokenVerifier | None = None) -> TamperTest:
    """Copy the stored pcap to a temporary directory, verify the copy, flip one bit of
    it, verify again. Nothing is written to the store or the custody chain; the copy is
    deleted. Raises CaseNotFoundError, or EvidenceNotFoundError when the stored blob is
    already gone (a plain verify reports that case)."""
    seal = storage.cases.load(case_id).seal
    with tempfile.TemporaryDirectory(prefix="netforensics-tamper-") as scratch:
        copy = Path(scratch) / "copy.pcap"
        shutil.copyfile(storage.evidence.path_for(seal.sha256_hash), copy)
        before = verify_stored(storage, case_id, config, verify_token, blob=copy)
        offset = flip_one_byte(copy)
        after = verify_stored(storage, case_id, config, verify_token, blob=copy)
    return TamperTest(before, after, offset)
