"""Command-line front end for the evidence layer (issue #4). Thin by design: every
command calls `backend.intake`, the store or the TSA retry; nothing here hashes,
parses or judges evidence itself.

    python -m backend.cli [--store DIR] seal <pcap>
    python -m backend.cli [--store DIR] analyze <pcap>
    python -m backend.cli [--store DIR] retry-timestamps

`verify` and `tamper-demo` are listed but not built: they need the core custody
chain, timestamp check and case verification (#10, #11, #12).

Exit codes are defined once, in `EXIT_CODES_HELP`, which `--help` prints; the docs
site generates its CLI page from this parser, so help text is the source of truth.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import uuid
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from backend.config import CONFIG, Config
from backend.db.storage import Storage
from backend.evidence.tsa_client import RetryOutcome, Timestamper, retry_all_pending
from backend.intake import seal_and_store, stage_and_validate
from backend.models import CaseRecord, Finding, TimestampStatus

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_PENDING = 2
EXIT_NOT_BUILT = 3
EXIT_CODES_HELP = f"""exit codes:
  {EXIT_OK}  success (retry-timestamps: no seal left PENDING)
  {EXIT_ERROR}  error: missing file, not a pcap, too large, stored copy altered
     (one "error:" line on stderr)
  {EXIT_PENDING}  retry-timestamps left at least one seal PENDING; also a usage error
  {EXIT_NOT_BUILT}  command not built yet (verify, tamper-demo)
verify will use 0 = INTACT, 1 = ALTERED, 2 = INCOMPLETE when it lands."""

_NOT_BUILT = "not built yet (needs #10/#11/#12: custody chain, timestamp check, case verification)"
_NO_TIMESTAMPER = (
    "No timestamper is wired in yet: building the RFC 3161 request and checking the "
    "returned token is core issue #11. Seals stay PENDING; nothing is faked."
)


def main(
    argv: Sequence[str] | None = None,
    config: Config = CONFIG,
    timestamper: Timestamper | None = None,
    out: TextIO = sys.stdout,
) -> int:
    """Parse `argv`, run one command, return its exit code. `timestamper` is the
    core RFC 3161 hook (#11); tests inject a fake one, until then it is None."""
    args = _parser().parse_args(argv)
    config = _with_store(config, args.store)
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
    commands = parser.add_subparsers(required=True, metavar="command")
    for name, handler, help_text in (
        ("seal", cmd_seal, "seal a pcap and store it as a new case"),
        ("analyze", cmd_analyze, "seal, store and analyse a pcap; print its findings"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("pcap", type=Path)
        command.set_defaults(command=handler)
    retry = commands.add_parser("retry-timestamps", help="retry every PENDING seal")
    retry.set_defaults(command=cmd_retry_timestamps)
    for name, argument in (("verify", "case_id"), ("tamper-demo", "pcap")):
        stub = commands.add_parser(name, help=_NOT_BUILT)
        stub.add_argument(argument)
        stub.set_defaults(command=cmd_not_built, name=name)
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


def cmd_not_built(args: argparse.Namespace, config: Config, timestamper: Timestamper | None,
                  out: TextIO) -> int:
    print(f"{args.name}: {_NOT_BUILT}", file=sys.stderr)
    return EXIT_NOT_BUILT


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


def _print_seal(record: CaseRecord, out: TextIO) -> None:
    seal = record.seal
    print(f"Case       {record.case_id}", file=out)
    print(f"File       {seal.pcap_filename} ({seal.pcap_size_bytes} bytes)", file=out)
    print(f"BLAKE3     {seal.pcap_hash}", file=out)
    print(f"SHA-256    {seal.sha256_hash}", file=out)
    print(f"Received   {_utc(seal.received_at)}", file=out)
    if seal.timestamp_status is TimestampStatus.GRANTED:
        print(f"Timestamp  GRANTED by {seal.tsa_url} at "
              f"{_utc(seal.timestamp_gen_time)} (stored, not yet checked: #11)", file=out)
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
    sys.exit(main())
