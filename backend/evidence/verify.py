"""Stage 5 — case verification: is this still the evidence that was sealed? (issue #12)

`verify_case` re-hashes the stored pcap and re-checks everything recorded about it.
Five checks, in this order, and ALL of them always run — a magistrate wants the whole
picture, not the first failure:

    pcap_digests       BLAKE3, SHA-256 and size of the stored file vs the seal
    custody_chain      every entry re-hashes and links to the one before
    seal_binding       entry 0 is bound to THIS seal (genesis hash)
    rfc3161_timestamp  the seal's TSA token verifies (not run while PENDING)
    chain_head_anchor  no anchored entry has been removed (backend/evidence/anchor.py)

VERDICT RULE: any check `passed is False` -> ALTERED; else any `None` -> INCOMPLETE;
else INTACT. An exception inside a check is that check failing, with the error as its
evidence line — never a skipped check, never a crash.

INTACT means "the stored bytes match the seal, the custody record is unbroken and a
third-party timestamp vouches for both". It does not mean "legally admissible".

Pure: no database, no HTTP, no pcap parsing. The caller loads the inputs, and appends
the custody event `verification_event` builds (verify stays read-only, so it can be run
on a copy or a read-only store).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

from backend.config import Config
from backend.evidence import anchor, custody, timestamp
from backend.evidence.custody import CustodyEvent
from backend.evidence.seal import hash_file
from backend.evidence.timestamp import TokenVerifier
from backend.models import (
    ChainAnchor,
    CheckResult,
    CustodyEntry,
    SealRecord,
    Verdict,
    VerificationReport,
)

VERIFY_EVENT = "verify"


def verify_case(
    seal: SealRecord,
    entries: Sequence[CustodyEntry],
    anchors: Sequence[ChainAnchor],
    blob_path: Path,
    case_id: str,
    config: Config,
    verify_token: TokenVerifier | None = None,
) -> VerificationReport:
    """Run every check and apply the verdict rule (module docstring). `verify_token`
    defaults to `verify_reply` against the pinned TSA certificates in `config`."""
    entries = tuple(entries)

    def verifier() -> TokenVerifier:  # inside the guard: unreadable certificates fail a check
        return verify_token or timestamp.token_verifier(timestamp.load_trust(config))

    checks = (
        _guarded("pcap_digests", lambda: _check_digests(seal, blob_path, config)),
        _guarded(custody.CHECK_NAME, lambda: custody.verify_chain(seal, case_id, entries)),
        _guarded("seal_binding", lambda: _check_binding(seal, entries)),
        _guarded(timestamp.CHECK_NAME, lambda: _check_timestamp(seal, config, verifier())),
        _guarded(anchor.CHECK_NAME, lambda: anchor.check_anchors(case_id, entries, anchors,
                                                                 verifier())),
    )
    return VerificationReport(verdict_for(checks), checks)


def verdict_for(checks: Sequence[CheckResult]) -> Verdict:
    if any(check.passed is False for check in checks):
        return Verdict.ALTERED
    if any(check.passed is None for check in checks):
        return Verdict.INCOMPLETE
    return Verdict.INTACT


def verification_event(case_id: str, report: VerificationReport) -> CustodyEvent:
    """The custody event the caller appends after a verification."""
    failed = [check.name for check in report.checks if check.passed is False]
    return CustodyEvent(
        case_id, VERIFY_EVENT,
        f"Case verified: {report.verdict.value.upper()}"
        + (f" (failed: {', '.join(failed)})." if failed else "."),
        {"verdict": report.verdict.value,
         "checks": {check.name: _state(check.passed) for check in report.checks}},
    )


def _state(passed: bool | None) -> str:
    return {True: "passed", False: "failed", None: "not_run"}[passed]


def _guarded(name: str, run: Callable[[], CheckResult]) -> CheckResult:
    """A check that raises has failed: its error becomes the evidence line."""
    try:
        return run()
    except Exception as error:  # noqa: BLE001 — never hide a failure as a skip
        return CheckResult(name, False, f"The {name} check could not complete: "
                                        f"{type(error).__name__}: {error}")


def _check_digests(seal: SealRecord, blob_path: Path, config: Config) -> CheckResult:
    """Both digests AND the size: matching only one digest would leave a door half open
    (a future collision in one algorithm alone would pass). Plain `==` is fine — these
    digests are public values, not secrets, so timing leaks nothing an attacker lacks.
    The hash is of the stored blob itself, not a copy; whoever later reads the file must
    re-verify, since it could change after this check (time of check vs time of use)."""
    if not blob_path.is_file():
        return CheckResult("pcap_digests", False, f"The stored evidence file {blob_path.name} "
                           "is missing, so nothing can be compared with the seal.")
    measured = hash_file(str(blob_path), config.evidence.hash_chunk_bytes)
    pairs = (("BLAKE3", seal.pcap_hash, measured.blake3_hex),
             ("SHA-256", seal.sha256_hash, measured.sha256_hex),
             ("size", f"{seal.pcap_size_bytes} bytes", f"{measured.size_bytes} bytes"))
    differ = [f"{name} sealed {sealed}, measured {now}" for name, sealed, now in pairs
              if sealed != now]
    if differ:
        return CheckResult("pcap_digests", False, "The stored evidence no longer matches its "
                           f"seal: {'; '.join(differ)}.")
    return CheckResult("pcap_digests", True, f"The stored file re-hashes to the sealed values: "
                       f"BLAKE3 {measured.blake3_hex}, SHA-256 {measured.sha256_hex}, "
                       f"{measured.size_bytes} bytes.")


def _check_binding(seal: SealRecord, entries: Sequence[CustodyEntry]) -> CheckResult:
    if not entries:
        return CheckResult("seal_binding", False, "There is no custody entry 0 to bind to the seal.")
    expected = custody.genesis_prev_hash(seal)
    if entries[0].prev_hash != expected:
        return CheckResult("seal_binding", False, f"Custody entry 0 is bound to "
                           f"{entries[0].prev_hash}, not to this seal ({expected}): the chain "
                           "belongs to different evidence or the seal was edited.")
    return CheckResult("seal_binding", True, f"Custody entry 0 is bound to this seal "
                       f"(genesis hash {expected}).")


def _check_timestamp(seal: SealRecord, config: Config, verify: TokenVerifier) -> CheckResult:
    """Load the pinned certificates only for their display name; `verify` does the work."""
    return timestamp.check_seal_timestamp(seal, timestamp.load_trust(config), verify)
