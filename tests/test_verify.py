"""Case verification and chain-head anchoring (issue #12).

A real TSA cannot be made to sign arbitrary digests in a test, so tokens here are
stand-ins checked by `_fake_verify`; the real token check is covered in
test_timestamp.py, and `verify_case` uses it whenever no verifier is injected.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.config import CONFIG
from backend.db.anchor_log import SqliteAnchorLog
from backend.evidence.anchor import ANCHOR_EVENT, anchor_event, check_anchors, take_anchor
from backend.evidence.custody import CustodyEvent, build_entry
from backend.evidence.seal import seal_pcap
from backend.evidence.timestamp import TimestampInvalidError
from backend.evidence.tsa_client import TsaUnavailableError
from backend.evidence.verify import verdict_for, verification_event, verify_case
from backend.models import (
    CheckResult,
    CustodyEntry,
    SealRecord,
    TimestampStatus,
    Verdict,
)

CASE = "a" * 32
T0 = datetime(2026, 11, 9, 10, 0, tzinfo=timezone.utc)
GEN = datetime(2026, 11, 9, 10, 0, 5, tzinfo=timezone.utc)
TSA = CONFIG.evidence.tsa_url


def _token(sha256_hex: str) -> bytes:
    return b"token-over:" + sha256_hex.encode()


def _fake_verify(token: bytes, sha256_hex: str) -> datetime:
    if token != _token(sha256_hex):
        raise TimestampInvalidError(f"The token covers something other than {sha256_hex}.")
    return GEN


def _fake_timestamper(sha256_hex: str) -> tuple[bytes, datetime]:
    return _token(sha256_hex), GEN


def _granted(seal: SealRecord) -> SealRecord:
    return replace(seal, timestamp_status=TimestampStatus.GRANTED,
                   rfc3161_token=_token(seal.sha256_hash), timestamp_gen_time=GEN, tsa_url=TSA)


class Case:
    """A sealed blob, a custody chain with one anchor (entry 2, anchored by entry 3)
    and a verify event after it: ingest, finding, finding, anchor, verify."""

    def __init__(self, tmp_path: Path) -> None:
        self.blob = tmp_path / "blob.pcap"
        self.blob.write_bytes(bytes(range(256)) * 4)
        self.seal = _granted(seal_pcap(str(self.blob)))
        self.entries: list[CustodyEntry] = []
        for kind in ("ingest", "finding", "finding"):
            self.append(CustodyEvent(CASE, kind, f"{kind} event", {"n": len(self.entries)}))
        self.anchors = [take_anchor(self.entries[-1], T0, _fake_timestamper, TSA)]
        self.append(anchor_event(self.anchors[0]))
        self.append(CustodyEvent(CASE, "verify", "Case verified: INTACT.", {}))

    def append(self, event: CustodyEvent) -> None:
        prev = self.entries[-1] if self.entries else None
        self.entries.append(build_entry(self.seal, prev, event, T0 + timedelta(len(self.entries))))

    def verify(self, **changes):
        inputs = {"seal": self.seal, "entries": self.entries, "anchors": self.anchors,
                  "blob_path": self.blob} | changes
        return verify_case(inputs["seal"], inputs["entries"], inputs["anchors"],
                           inputs["blob_path"], CASE, CONFIG, verify_token=_fake_verify)


@pytest.fixture
def case(tmp_path: Path) -> Case:
    return Case(tmp_path)


def _by_name(report) -> dict[str, CheckResult]:
    return {check.name: check for check in report.checks}


ALL_CHECKS = ["pcap_digests", "custody_chain", "seal_binding", "rfc3161_timestamp",
              "chain_head_anchor"]


# --------------------------------------------------------------------------- #
# Untouched cases
# --------------------------------------------------------------------------- #


def test_untouched_case_is_intact_and_every_check_ran_in_order(case: Case):
    report = case.verify()
    assert report.verdict is Verdict.INTACT
    assert [check.name for check in report.checks] == ALL_CHECKS
    assert all(check.passed is True for check in report.checks)
    anchor = _by_name(report)["chain_head_anchor"].evidence
    assert "entry 2" in anchor and "2 later entries" in anchor


def test_untouched_case_with_pending_timestamps_is_incomplete(case: Case):
    seal = replace(case.seal, timestamp_status=TimestampStatus.PENDING, rfc3161_token=None,
                   timestamp_gen_time=None, tsa_url=None)
    case.seal = seal
    case.entries.clear()
    for kind in ("ingest", "finding"):
        case.append(CustodyEvent(CASE, kind, kind, {}))
    case.anchors = [take_anchor(case.entries[-1], T0, None, TSA)]
    case.append(anchor_event(case.anchors[0]))
    checks = _by_name(report := case.verify())
    assert report.verdict is Verdict.INCOMPLETE
    assert checks["rfc3161_timestamp"].passed is None
    assert checks["chain_head_anchor"].passed is None
    assert "PENDING" in checks["chain_head_anchor"].evidence


# --------------------------------------------------------------------------- #
# Tamper matrix
# --------------------------------------------------------------------------- #


def _flip_byte(case: Case) -> dict:
    data = bytearray(case.blob.read_bytes())
    data[100] ^= 0x01
    case.blob.write_bytes(bytes(data))
    return {}


def _grow(case: Case) -> dict:
    case.blob.write_bytes(case.blob.read_bytes() + b"\x00")
    return {}


def _edit_entry(case: Case) -> dict:
    return {"entries": [*case.entries[:1], replace(case.entries[1], detail="nothing found"),
                        *case.entries[2:]]}


def _delete_middle(case: Case) -> dict:
    return {"entries": [case.entries[0], *case.entries[2:]]}


def _truncate_past_anchor(case: Case) -> dict:
    return {"entries": case.entries[:2]}  # entry 2 was anchored; 2, 3 and 4 are cut


def _wrong_seal(case: Case) -> dict:
    return {"seal": replace(case.seal, pcap_filename="other.pcap")}


def _mutate_seal_token(case: Case) -> dict:
    return {"seal": replace(case.seal, rfc3161_token=case.seal.rfc3161_token + b"x")}


def _mutate_anchor_token(case: Case) -> dict:
    return {"anchors": [replace(case.anchors[0], rfc3161_token=b"forged")]}


def _drop_anchor_record(case: Case) -> dict:
    return {"anchors": []}


def _missing_blob(case: Case) -> dict:
    case.blob.unlink()
    return {}


@pytest.mark.parametrize(("tamper", "failing"), [
    (_flip_byte, {"pcap_digests"}),
    (_grow, {"pcap_digests"}),
    (_edit_entry, {"custody_chain"}),
    (_delete_middle, {"custody_chain", "chain_head_anchor"}),  # anchored entry moved
    (_truncate_past_anchor, {"chain_head_anchor"}),
    (_wrong_seal, {"custody_chain", "seal_binding"}),
    (_mutate_seal_token, {"rfc3161_timestamp"}),
    (_mutate_anchor_token, {"chain_head_anchor"}),
    (_drop_anchor_record, {"chain_head_anchor"}),
    (_missing_blob, {"pcap_digests"}),
])
def test_tamper_matrix(case: Case, tamper, failing: set[str]):
    report = case.verify(**tamper(case))
    assert report.verdict is Verdict.ALTERED
    assert {check.name for check in report.checks if check.passed is False} == failing
    assert [check.name for check in report.checks] == ALL_CHECKS  # nothing skipped


def test_byte_flip_evidence_shows_sealed_and_measured_digests(case: Case):
    sealed = case.seal.pcap_hash
    _flip_byte(case)
    evidence = _by_name(case.verify())["pcap_digests"].evidence
    assert f"BLAKE3 sealed {sealed}, measured " in evidence
    assert "SHA-256 sealed" in evidence and "size" not in evidence


def test_truncation_evidence_names_the_vanished_entry(case: Case):
    evidence = _by_name(case.verify(**_truncate_past_anchor(case)))["chain_head_anchor"].evidence
    assert "entry 2 was anchored" in evidence and "only 2 entries" in evidence


def test_anchoring_is_what_catches_tail_truncation(case: Case):
    """Same cut, with and without the anchor: the chain alone still verifies."""
    cut = case.entries[:2]
    without = _by_name(case.verify(entries=cut, anchors=[]))
    assert without["custody_chain"].passed is True
    assert without["chain_head_anchor"].passed is None   # INCOMPLETE, not caught
    with_anchor = case.verify(entries=cut)
    assert with_anchor.verdict is Verdict.ALTERED


def test_cut_after_the_latest_anchor_is_not_detectable(case: Case):
    """The documented limit: entries after the latest anchor rest on the chain alone."""
    report = case.verify(entries=case.entries[:4])  # verify event (entry 4) removed
    assert report.verdict is Verdict.INTACT


def test_rewritten_anchored_entry_is_named(case: Case):
    other = replace(case.entries[2], entry_hash="f" * 64)
    evidence = check_anchors(CASE, [*case.entries[:2], other], case.anchors, _fake_verify).evidence
    assert "the chain was rewritten" in evidence


def test_a_check_that_raises_fails_instead_of_being_skipped(case: Case):
    def broken(token: bytes, sha256_hex: str) -> datetime:
        raise RuntimeError("certificate store unreadable")

    report = verify_case(case.seal, case.entries, case.anchors, case.blob, CASE, CONFIG,
                         verify_token=broken)
    checks = _by_name(report)
    assert report.verdict is Verdict.ALTERED
    assert checks["rfc3161_timestamp"].passed is False
    assert "certificate store unreadable" in checks["rfc3161_timestamp"].evidence
    assert checks["pcap_digests"].passed is True


def test_default_verifier_checks_tokens_with_the_pinned_certificates(case: Case):
    report = verify_case(case.seal, case.entries, case.anchors, case.blob, CASE, CONFIG)
    checks = _by_name(report)
    assert checks["rfc3161_timestamp"].passed is False  # a stand-in token is not a TSA reply
    assert checks["chain_head_anchor"].passed is False


def test_tamper_demo_scenario_is_fast(case: Case):
    started = time.monotonic()
    assert case.verify().verdict is Verdict.INTACT
    _flip_byte(case)
    assert case.verify().verdict is Verdict.ALTERED
    assert time.monotonic() - started < 10


# --------------------------------------------------------------------------- #
# Verdict rule
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("states", "verdict"), [
    ((True, True), Verdict.INTACT),
    ((True, None), Verdict.INCOMPLETE),
    ((None, None), Verdict.INCOMPLETE),
    ((True, False), Verdict.ALTERED),
    ((None, False), Verdict.ALTERED),
])
def test_verdict_rule(states, verdict):
    assert verdict_for([CheckResult(f"c{i}", s, "") for i, s in enumerate(states)]) is verdict


def test_verification_event_chains_cleanly(case: Case):
    _flip_byte(case)
    event = verification_event(CASE, case.verify())
    assert event.event_type == "verify"
    assert event.payload["verdict"] == "altered"
    assert event.payload["checks"]["pcap_digests"] == "failed"
    case.append(event)  # canonical payload: no floats, hashes fine
    assert case.entries[-1].detail == "Case verified: ALTERED (failed: pcap_digests)."


# --------------------------------------------------------------------------- #
# Taking anchors
# --------------------------------------------------------------------------- #


def test_anchor_without_a_timestamper_is_pending_and_holds_no_token(case: Case):
    anchor = take_anchor(case.entries[0], T0, None, TSA)
    assert anchor.timestamp_status is TimestampStatus.PENDING
    assert anchor.rfc3161_token is None and anchor.timestamp_gen_time is None
    assert anchor.head_hash == case.entries[0].entry_hash


@pytest.mark.parametrize("error", [TsaUnavailableError("down"), TimestampInvalidError("bad")])
def test_anchor_degrades_to_pending_when_the_tsa_fails(case: Case, error):
    def failing(sha256_hex: str):
        raise error

    assert take_anchor(case.entries[0], T0, failing, TSA).timestamp_status is TimestampStatus.PENDING


def test_granted_anchor_timestamps_the_head_hash_itself(case: Case):
    anchor = case.anchors[0]
    assert anchor.timestamp_status is TimestampStatus.GRANTED
    assert anchor.rfc3161_token == _token(case.entries[2].entry_hash)
    assert case.entries[3].event_type == ANCHOR_EVENT
    assert case.entries[3].payload["head_index"] == 2


@pytest.mark.parametrize("changes", [
    {"timestamp_status": TimestampStatus.PENDING},                 # PENDING with a token
    {"rfc3161_token": None},                                       # GRANTED without one
    {"timestamp_gen_time": GEN + timedelta(seconds=1)},            # genTime edited
    {"case_id": "b" * 32},
])
def test_edited_anchor_records_fail(case: Case, changes):
    edited = replace(case.anchors[0], **changes)
    assert check_anchors(CASE, case.entries, [edited], _fake_verify).passed is False


# --------------------------------------------------------------------------- #
# Anchor store
# --------------------------------------------------------------------------- #


def test_anchor_log_round_trips_and_is_append_only(case: Case, tmp_path: Path):
    log = SqliteAnchorLog(tmp_path / "db.sqlite")
    pending = take_anchor(case.entries[0], T0, None, TSA)
    log.append(pending)
    log.append(case.anchors[0])
    assert log.anchors(CASE) == (pending, case.anchors[0])
    with pytest.raises(sqlite3.IntegrityError):
        log.append(replace(pending, head_hash="0" * 64))
    with sqlite3.connect(tmp_path / "db.sqlite") as connection:
        for statement in ("DELETE FROM chain_anchors", "UPDATE chain_anchors SET head_hash = 'x'"):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute(statement)
