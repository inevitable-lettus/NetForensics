"""Command-line front end for the evidence layer (issue #4). Thin by design: every
command calls `backend.intake`, the store or the TSA retry; nothing here hashes,
parses or judges evidence itself.

    python -m backend.cli [--store DIR] [--offline] seal <pcap>
    python -m backend.cli [--store DIR] [--offline] analyze <pcap>
    python -m backend.cli [--store DIR] [--offline] verify <case-id>
    python -m backend.cli [--offline] tamper-demo <pcap>
    python -m backend.cli [--store DIR] [--offline] retry-timestamps

`verify` calls `backend.evidence.verify.verify_case`; it hashes nothing itself.

Exit codes are defined once, in `EXIT_CODES_HELP`, which `--help` prints; the docs
site generates its CLI page from this parser, so help text is the source of truth.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import tempfile
import uuid
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from backend.config import CONFIG, Config
from backend.db.evidence_store import EvidenceNotFoundError
from backend.db.storage import Storage
from backend.evidence.timestamp import TokenVerifier, make_timestamper
from backend.evidence.tsa_client import RetryOutcome, Timestamper, retry_all_pending
from backend.evidence.verify import verification_event, verify_case
from backend.intake import append_custody, seal_and_store, stage_and_validate
from backend.models import (
    CaseRecord,
    CheckResult,
    Finding,
    TimestampStatus,
    Verdict,
    VerificationReport,
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_PENDING = 2
EXIT_CODES_HELP = f"""exit codes:
  {EXIT_OK}  success; verify: INTACT; tamper-demo: the altered copy was caught
  {EXIT_ERROR}  error: missing file, not a pcap, too large, unknown case, stored copy
     altered (one "error:" line on stderr); verify: ALTERED
  {EXIT_PENDING}  retry-timestamps left at least one seal PENDING; verify: INCOMPLETE
     (nothing failed, a timestamp is still PENDING); also a usage error"""

_VERDICT_EXIT = {Verdict.INTACT: EXIT_OK, Verdict.ALTERED: EXIT_ERROR,
                 Verdict.INCOMPLETE: EXIT_PENDING}
_STATE = {True: "PASS", False: "FAIL", None: "NOT RUN"}
_NO_TIMESTAMPER = "No TSA in use (offline). Seals stay PENDING; nothing is faked."


def main(
    argv: Sequence[str] | None = None,
    config: Config = CONFIG,
    timestamper: Timestamper | None = None,
    out: TextIO = sys.stdout,
    verify_token: TokenVerifier | None = None,
) -> int:
    """Parse `argv`, run one command, return its exit code. `timestamper` is the
    RFC 3161 hook (`make_timestamper` when run as a program; None = offline).
    `verify_token` replaces the pinned-certificate token check (tests only)."""
    args = _parser().parse_args(argv)
    args.verify_token = verify_token
    config = _with_store(config, args.store)
    timestamper = None if args.offline else timestamper
    try:
        return args.command(args, config, timestamper, out)
    except (OSError, ValueError, LookupError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m backend.cli",
        description="Seal, analyse and store packet captures as tamper-evident cases.",
        epilog=EXIT_CODES_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--store", type=Path, help="evidence store directory "
                        f"(default: {CONFIG.evidence.evidence_store_dir})")
    parser.add_argument("--offline", action="store_true",
                        help="never contact the TSA; timestamps and anchors stay PENDING")
    commands = parser.add_subparsers(required=True, metavar="command")
    for name, handler, help_text in (
        ("seal", cmd_seal, "seal a pcap and store it as a new case"),
        ("analyze", cmd_analyze, "seal, store and analyse a pcap; print its findings"),
        ("tamper-demo", cmd_tamper_demo, "in a throwaway store: seal a copy, verify, flip one "
                                         "stored byte, verify again"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("pcap", type=Path,
                             help="path to a classic .pcap capture (not pcapng)")
        command.set_defaults(command=handler)
    retry = commands.add_parser("retry-timestamps", help="retry every PENDING seal")
    retry.set_defaults(command=cmd_retry_timestamps)
    verify = commands.add_parser("verify", help="re-check a stored case: INTACT, ALTERED "
                                                "or INCOMPLETE")
    verify.add_argument("case_id", help="case id printed by seal or analyze")
    verify.set_defaults(command=cmd_verify)
    return parser


def _with_store(config: Config, store: Path | None) -> Config:
    """`--store DIR` keeps blobs and the database together under DIR."""
    if store is None:
        return config
    evidence = replace(config.evidence, evidence_store_dir=str(store),
                       db_path=str(store / "netforensics.sqlite"))
    return replace(config, evidence=evidence)


# --------------------------------------------------------------------------- #
# Commands — one function each
# --------------------------------------------------------------------------- #


def cmd_seal(args: argparse.Namespace, config: Config, timestamper: Timestamper | None,
             out: TextIO) -> int:
    record = _intake(args.pcap, config, timestamper)
    _print_seal(record, out)
    return EXIT_OK


def cmd_analyze(args: argparse.Namespace, config: Config, timestamper: Timestamper | None,
                out: TextIO) -> int:
    record = _intake(args.pcap, config, timestamper)
    _print_seal(record, out)
    print(f"Flows      {record.flow_count}", file=out)
    print(f"Findings   {len(record.findings)}", file=out)
    for finding in record.findings:
        _print_finding(finding, out)
    return EXIT_OK


def cmd_retry_timestamps(args: argparse.Namespace, config: Config,
                         timestamper: Timestamper | None, out: TextIO) -> int:
    cases = Storage.open(config.evidence).cases
    if timestamper is None:
        pending = cases.pending_timestamp_case_ids()
        print(f"{len(pending)} case(s) PENDING. {_NO_TIMESTAMPER}", file=out)
        return EXIT_PENDING if pending else EXIT_OK
    results = retry_all_pending(cases, timestamper, config)
    for result in results:
        print(f"{result.case_id}  {result.outcome.value.upper():<15}  "
              f"attempts {result.attempts}  {result.detail}", file=out)
    counts = {outcome: sum(r.outcome is outcome for r in results) for outcome in RetryOutcome}
    print(f"{len(results)} case(s): {counts[RetryOutcome.GRANTED]} granted, "
          f"{counts[RetryOutcome.STILL_PENDING]} still pending, "
          f"{counts[RetryOutcome.ERROR]} error(s).", file=out)
    if counts[RetryOutcome.ERROR]:
        return EXIT_ERROR
    return EXIT_PENDING if counts[RetryOutcome.STILL_PENDING] else EXIT_OK


def cmd_verify(args: argparse.Namespace, config: Config, timestamper: Timestamper | None,
               out: TextIO) -> int:
    storage = Storage.open(config.evidence)
    report = _verify(storage, args.case_id, config, args.verify_token)
    _print_report(report, out)  # before any bookkeeping, so nothing can hide it
    if _record(storage, args.case_id, report, timestamper, config):
        latest = storage.anchors.anchors(args.case_id)[-1]
        print(f"Anchor     entry {latest.head_index}, hash {latest.head_hash} "
              f"({latest.timestamp_status.value.upper()}); keep a copy outside this system: "
              "a later verify must still find this entry.", file=out)
    return _VERDICT_EXIT[report.verdict]


def cmd_tamper_demo(args: argparse.Namespace, config: Config, timestamper: Timestamper | None,
                    out: TextIO) -> int:
    """Always a fresh temporary store: the demo damages the stored blob, which a real
    store may share between cases (blobs are content-addressed)."""
    with tempfile.TemporaryDirectory(prefix="netforensics-demo-") as scratch:
        config = _with_store(config, Path(scratch))
        storage = Storage.open(config.evidence)
        record = _intake(args.pcap, config, timestamper)
        print(f"Throwaway store {scratch} (deleted afterwards); {args.pcap} is only read.",
              file=out)
        _print_seal(record, out)
        before = _verify(storage, record.case_id, config, args.verify_token)
        _record(storage, record.case_id, before, timestamper, config)
        blob = storage.evidence.path_for(record.seal.sha256_hash)
        offset = _flip_one_byte(blob)
        print(f"\nFlipped one bit of byte {offset} of the stored copy.", file=out)
        after = _verify(storage, record.case_id, config, args.verify_token)
        _record(storage, record.case_id, after, timestamper, config)
        _print_side_by_side(before, after, out)
    return EXIT_OK if after.verdict is Verdict.ALTERED else EXIT_ERROR


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _intake(pcap: Path, config: Config, timestamper: Timestamper | None) -> CaseRecord:
    """Same path as an API upload: stage a copy, validate, seal, analyse, store. The
    user's file is only ever opened for reading."""
    if not pcap.is_file():
        raise FileNotFoundError(f"{pcap} is not a file.")
    storage = Storage.open(config.evidence)
    case_id = uuid.uuid4().hex
    chunk = config.ingest.upload_chunk_bytes
    with pcap.open("rb") as source:
        staged = stage_and_validate(storage, case_id, pcap.name, lambda: source.read(chunk), config)
    return seal_and_store(storage, case_id, staged, config, timestamper)


def _verify(storage: Storage, case_id: str, config: Config,
            verify_token: TokenVerifier | None) -> VerificationReport:
    """Read-only: load the case and run every check."""
    record = storage.cases.load(case_id)
    try:
        blob = storage.evidence.path_for(record.seal.sha256_hash)
    except EvidenceNotFoundError:  # a missing blob is ALTERED, reported by the check
        blob = Path(config.evidence.evidence_store_dir) / "blobs" / record.seal.sha256_hash
    report = verify_case(record.seal, storage.custody.entries(case_id),
                         storage.anchors.anchors(case_id), blob, case_id, config, verify_token)
    return report


def _record(storage: Storage, case_id: str, report: VerificationReport,
            timestamper: Timestamper | None, config: Config) -> bool:
    """Append the verify event and anchor the new head, unless the case is ALTERED:
    writing onto a damaged chain would fill the slots of removed entries, change the
    diagnosis of the next verify and anchor a head already known to be bad. The case
    is left exactly as found for investigation. A bookkeeping failure is a warning on
    stderr, never a crash: the report has already been printed. True if recorded."""
    if report.verdict is Verdict.ALTERED:
        print("note: case is ALTERED; nothing was written to its custody chain, so it "
              "stays exactly as found.", file=sys.stderr)
        return False
    try:
        append_custody(storage, storage.cases.load(case_id).seal,
                       [verification_event(case_id, report)], timestamper, config)
    except (OSError, ValueError, LookupError, sqlite3.Error) as error:
        print(f"warning: verification not recorded in the custody chain: {error}",
              file=sys.stderr)
        return False
    return True


def _flip_one_byte(blob: Path) -> int:
    """Flip the low bit of the middle byte. Blobs are stored read-only; lift that first."""
    blob.chmod(0o644)
    data = bytearray(blob.read_bytes())
    offset = len(data) // 2
    data[offset] ^= 0x01
    blob.write_bytes(bytes(data))
    return offset


def _print_report(report: VerificationReport, out: TextIO) -> None:
    for check in report.checks:
        _print_check(check, out)
    print(f"\nVerdict    {report.verdict.value.upper()}", file=out)


def _print_check(check: CheckResult, out: TextIO) -> None:
    print(f"[{_STATE[check.passed]}] {check.name}: {check.evidence}", file=out)


def _print_side_by_side(before: VerificationReport, after: VerificationReport,
                        out: TextIO) -> None:
    print(f"\n{'check':<20} {'before':<11} after", file=out)
    for old, new in zip(before.checks, after.checks, strict=True):
        print(f"{old.name:<20} {_STATE[old.passed]:<11} {_STATE[new.passed]}", file=out)
    print(f"{'verdict':<20} {before.verdict.value.upper():<11} {after.verdict.value.upper()}",
          file=out)
    print("\nAfter tampering:", file=out)
    for check in after.checks:
        if check.passed is False:
            _print_check(check, out)


def _print_seal(record: CaseRecord, out: TextIO) -> None:
    seal = record.seal
    print(f"Case       {record.case_id}", file=out)
    print(f"File       {seal.pcap_filename} ({seal.pcap_size_bytes} bytes)", file=out)
    print(f"BLAKE3     {seal.pcap_hash}", file=out)
    print(f"SHA-256    {seal.sha256_hash}", file=out)
    print(f"Received   {_utc(seal.received_at)}", file=out)
    if seal.timestamp_status is TimestampStatus.GRANTED:
        print(f"Timestamp  GRANTED by {seal.tsa_url} at "
              f"{_utc(seal.timestamp_gen_time)} (checked on arrival; re-checked by verify)", file=out)
    else:
        print("Timestamp  PENDING (retry later: python -m backend.cli retry-timestamps)",
              file=out)


def _utc(moment: datetime | None) -> str:
    return "unknown" if moment is None else moment.astimezone(timezone.utc).isoformat()


def _print_finding(finding: Finding, out: TextIO) -> None:
    print(f"\n[{finding.severity.value.upper()}] {finding.detector}: {finding.what}", file=out)
    print(f"  Why       {finding.why}", file=out)
    print(f"  Evidence  {finding.evidence}", file=out)


if __name__ == "__main__":
    sys.exit(main(timestamper=make_timestamper(CONFIG)))
