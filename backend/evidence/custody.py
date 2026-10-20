"""Stage 4 — the hash-chained, append-only chain of custody (issue #10).

Pure functions: no database, no HTTP, no clock. Persistence is `backend/db/`
(it stores entries exactly as built here); the caller injects `now`.

HOW AN ENTRY IS HASHED (precise enough to reimplement in another language)
---------------------------------------------------------------------------
    entry_hash = HEX( H( UTF8(entry_tag) || 0x00 || UTF8(canonical_json(body)) ) )

    H          = SHA-256                          (fixed in code: HASH_NAME)
    entry_tag  = "netforensics/custody-entry/v1"  (fixed in code: ENTRY_TAG)
    HEX        = lowercase hexadecimal, 64 chars
    body       = {"case_id", "detail", "event_type", "index", "payload",
                  "prev_hash", "timestamp"}       — every CustodyEntry field except
                                                    entry_hash itself
    timestamp  = UTC, "YYYY-MM-DDTHH:MM:SS.ffffffZ" (always 6 fractional digits)

    canonical_json = JSON with object keys sorted by Unicode code point, no
    whitespace (separators "," and ":"), non-ASCII characters emitted as raw UTF-8
    (not \\u escapes), and only these value types: string, integer, true/false,
    null, array, object with string keys, nested at most MAX_PAYLOAD_DEPTH (32)
    levels. Floats, NaN/Infinity, tuples, bytes, other types and deeper nesting are
    REJECTED (TypeError), never silently converted. Strings are
    hashed exactly as stored — no Unicode normalisation.

Entry 0's prev_hash is the GENESIS hash, which binds the chain to the evidence:

    genesis = HEX( H( UTF8(genesis_tag) || 0x00 || UTF8(canonical_json(seal_body)) ) )

    genesis_tag = "netforensics/custody-genesis/v1"
    seal_body   = {"hash_algorithm", "pcap_filename", "pcap_hash", "pcap_size_bytes",
                   "received_at", "sha256_hash"}  — received_at formatted as above.
    The seal's timestamp fields (status, token, genTime, TSA url) are deliberately
    excluded: they legitimately change once (PENDING -> GRANTED) after the chain
    has started, and must not break it.

WHAT THE CHAIN PROVES — AND WHAT IT DOES NOT
-------------------------------------------
Editing, removing, inserting, reordering or duplicating any entry that has a later
entry after it breaks verification at the first affected index. It does NOT detect
removal of the LAST N entries (the remaining prefix is still a valid chain), and it
does NOT stop someone with write access from rewriting the whole chain from the
point of change and recomputing every hash — there is no secret in it. Both gaps
are closed by chain-head anchoring (RFC 3161 timestamp over the head hash, #12).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

from backend.models import CheckResult, CustodyEntry, SealRecord

CHECK_NAME = "custody_chain"

# Part of the hash-input format, so deliberately NOT configuration: changing any of
# these would make every existing chain read as "broken at entry 0" (a false alarm),
# and a weak algorithm (MD5, SHA-1) must never be selectable. A new format means a
# new tag version ("v2") with its own code path, not a config edit.
HASH_NAME = "sha256"
ENTRY_TAG = "netforensics/custody-entry/v1"
GENESIS_TAG = "netforensics/custody-genesis/v1"
# Far beyond any real payload; stops a crafted, deeply nested payload from turning
# verification into a RecursionError crash instead of a reported break.
MAX_PAYLOAD_DEPTH = 32


@dataclass(frozen=True)
class CustodyEvent:
    """What happened, before it becomes a chained entry."""

    case_id: str
    event_type: str      # "ingest" | "parse" | "finding" | "report" | "verify" | ...
    detail: str          # human-readable sentence
    payload: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ChainBreak:
    """The first position where the chain stops being trustworthy, and why."""

    index: int
    reason: str


# --------------------------------------------------------------------------- #
# Canonical hash input
# --------------------------------------------------------------------------- #


def _check_canonical(value: object, path: str, depth: int = 0) -> None:
    """Reject any value whose JSON text is not stable across languages and round
    trips. (bool passes as a subclass of int and serialises as true/false.)"""
    if value is None or isinstance(value, (str, int)):
        return
    if depth >= MAX_PAYLOAD_DEPTH:
        raise TypeError(f"{path} is nested deeper than {MAX_PAYLOAD_DEPTH} levels.")
    if isinstance(value, list):
        for position, item in enumerate(value):
            _check_canonical(item, f"{path}[{position}]", depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} has a non-string key {key!r}.")
            _check_canonical(item, f"{path}.{key}", depth + 1)
        return
    hint = " Store it as a string so its exact text is hashed." if isinstance(value, float) else ""
    raise TypeError(f"{path} is a {type(value).__name__}, which has no canonical form.{hint}")


def canonical_json(value: object) -> str:
    _check_canonical(value, "value")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def utc_text(moment: datetime) -> str:
    """Fixed-precision UTC text. Naive datetimes are refused: their meaning depends
    on the machine's local zone, which is exactly the drift we must not hash."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError(f"Timestamp {moment!r} has no timezone.")
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _tagged_hash(tag: str, body: dict[str, object]) -> str:
    hasher = hashlib.new(HASH_NAME)
    hasher.update(tag.encode("utf-8") + b"\x00" + canonical_json(body).encode("utf-8"))
    return hasher.hexdigest()


def genesis_prev_hash(seal: SealRecord) -> str:
    """Entry 0's prev_hash: a digest of the seal, so a chain cannot be moved onto
    different evidence."""
    body: dict[str, object] = {
        "hash_algorithm": seal.hash_algorithm,
        "pcap_filename": seal.pcap_filename,
        "pcap_hash": seal.pcap_hash,
        "pcap_size_bytes": seal.pcap_size_bytes,
        "received_at": utc_text(seal.received_at),
        "sha256_hash": seal.sha256_hash,
    }
    return _tagged_hash(GENESIS_TAG, body)


def compute_entry_hash(entry: CustodyEntry) -> str:
    """Hash of every field except `entry_hash` itself (see module docstring)."""
    body: dict[str, object] = {
        "case_id": entry.case_id,
        "detail": entry.detail,
        "event_type": entry.event_type,
        "index": entry.index,
        "payload": entry.payload,
        "prev_hash": entry.prev_hash,
        "timestamp": utc_text(entry.timestamp),
    }
    return _tagged_hash(ENTRY_TAG, body)


# --------------------------------------------------------------------------- #
# Building
# --------------------------------------------------------------------------- #


def build_entry(
    seal: SealRecord,
    prev: CustodyEntry | None,
    event: CustodyEvent,
    now: datetime,
) -> CustodyEntry:
    """Chain `event` after `prev` (or start the chain from the seal when `prev` is
    None). `now` is injected so the same inputs always build the same entry."""
    if prev is not None and prev.case_id != event.case_id:
        raise ValueError(f"Cannot chain case {event.case_id} after an entry of {prev.case_id}.")
    unhashed = CustodyEntry(
        case_id=event.case_id,
        index=0 if prev is None else prev.index + 1,
        timestamp=_as_utc(now),
        event_type=event.event_type,
        detail=event.detail,
        prev_hash=genesis_prev_hash(seal) if prev is None else prev.entry_hash,
        entry_hash="",
        payload=event.payload,
    )
    return replace(unhashed, entry_hash=compute_entry_hash(unhashed))


def _as_utc(moment: datetime) -> datetime:
    """Store the entry's time in UTC, so what is persisted reads back as exactly
    the text that was hashed (utc_text also refuses naive datetimes)."""
    utc_text(moment)
    return moment.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# Verifying
# --------------------------------------------------------------------------- #


def _entry_problem(
    entry: CustodyEntry, position: int, expected_prev: str, case_id: str
) -> str | None:
    """First thing wrong with one entry, in the order a reader would check it."""
    if entry.index != position:
        return (f"the entry at position {position} carries index {entry.index}: entries "
                "are missing, duplicated or out of order")
    if entry.case_id != case_id:
        return f"entry {position} belongs to case {entry.case_id}, not {case_id}"
    if entry.prev_hash != expected_prev:
        if position == 0:
            return (f"entry 0 is not bound to this evidence: its prev_hash {entry.prev_hash} "
                    f"differs from {expected_prev}, derived from the seal")
        return (f"entry {position} does not link to entry {position - 1}: its prev_hash "
                f"{entry.prev_hash} differs from entry {position - 1}'s hash {expected_prev}")
    try:
        recomputed = compute_entry_hash(entry)
    except (TypeError, ValueError, RecursionError) as error:
        return f"entry {position} cannot be re-hashed: {error}"
    if recomputed != entry.entry_hash:
        return (f"entry {position} was altered after it was written: its contents hash to "
                f"{recomputed}, not the stored {entry.entry_hash}")
    return None


def find_chain_break(
    seal: SealRecord, case_id: str, entries: tuple[CustodyEntry, ...] | list[CustodyEntry],
) -> ChainBreak | None:
    """Walk the chain from the seal; return the first break, or None if intact.
    An empty log is a break: every sealed case has at least its ingest entry."""
    if not entries:
        return ChainBreak(0, "the custody log is empty, but every sealed case starts "
                             "with an ingest entry")
    try:
        expected_prev = genesis_prev_hash(seal)
    except ValueError as error:  # e.g. a seal whose received_at has no timezone
        return ChainBreak(0, f"the genesis link cannot be derived from the seal: {error}")
    for position, entry in enumerate(entries):
        problem = _entry_problem(entry, position, expected_prev, case_id)
        if problem is not None:
            return ChainBreak(position, problem)
        expected_prev = entry.entry_hash
    return None


def verify_chain(
    seal: SealRecord, case_id: str, entries: tuple[CustodyEntry, ...] | list[CustodyEntry],
) -> CheckResult:
    """The custody check as a magistrate-readable `CheckResult`."""
    broken = find_chain_break(seal, case_id, entries)
    if broken is not None:
        return CheckResult(CHECK_NAME, False, f"Chain of custody broken at entry "
                                              f"{broken.index}: {broken.reason}.")
    return CheckResult(
        CHECK_NAME,
        True,
        f"All {len(entries)} custody entries recompute to their stored hashes and each "
        f"links to the one before; entry 0 is bound to the seal of {seal.pcap_filename} "
        f"(SHA-256 {seal.sha256_hash}). Head hash: {entries[-1].entry_hash}. The chain "
        "alone cannot show that no entries were removed from the end; that needs the "
        "anchored head.",
    )
