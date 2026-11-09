"""Chain-head anchoring — makes removal of the LAST custody entries detectable (issue #12).

THE GAP
-------
A hash chain proves every entry links to the one before it. Cut entries 8 and 9 off a
10-entry chain and entries 0-7 are still a perfectly valid chain: nothing inside the
chain says it used to be longer.

THE FIX
-------
From time to time (at intake, after each verification; report export should do the
same) the caller takes an ANCHOR: the current head's index and hash, timestamped by
the RFC 3161 TSA. The head's `entry_hash` is already a SHA-256 hex digest, and it
covers the entry's index and case id, so the TSA signs it directly — a stored anchor
can be re-checked with `openssl ts -verify -digest <head_hash>`.

The anchor is stored OUTSIDE the custody log (its own append-only table), so cutting
the chain does not cut the anchor. Verification then requires, for every anchor:
  1. entry `head_index` still exists       (else: the tail was removed);
  2. its hash still equals `head_hash`     (else: the chain was rewritten);
  3. a GRANTED token verifies over `head_hash` and its genTime matches the record.
The caller also appends an "anchor" custody event naming the anchored head, so an
anchor record deleted while those events remain is caught too (check 4).

WHAT IT DOES NOT PROVE
----------------------
Entries after the latest anchor are protected only by the chain (the evidence line
says how many). Someone who can write the database could delete the anchor rows AND
the tail together; the TSA token then lives on only in copies already handed out
(the CLI / report print the latest anchor), which is why it is printed. A rewritten
chain can be re-anchored, but only with a genTime from after the rewrite.

Degrades like sealing: TSA down or a reply that fails its checks -> the anchor is
recorded PENDING with no token. Nothing is faked; PENDING makes the verdict INCOMPLETE.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone

from backend.evidence.custody import CustodyEvent
from backend.evidence.timestamp import TimestampInvalidError, TokenVerifier
from backend.evidence.tsa_client import Timestamper
from backend.models import ChainAnchor, CheckResult, CustodyEntry, TimestampStatus

CHECK_NAME = "chain_head_anchor"
ANCHOR_EVENT = "anchor"


def take_anchor(
    head: CustodyEntry, now: datetime, timestamper: Timestamper | None, tsa_url: str
) -> ChainAnchor:
    """Anchor `head`. One TSA attempt; any failure leaves the anchor PENDING (a token
    that fails its checks is never stored). A later anchor supersedes a PENDING one,
    so PENDING anchors are not retried."""
    anchor = ChainAnchor(head.case_id, head.index, head.entry_hash, now.astimezone(timezone.utc))
    if timestamper is None:
        return anchor
    try:
        token, gen_time = timestamper(head.entry_hash)
    except Exception:  # noqa: BLE001 — TSA down, bad reply, anything: PENDING, never faked
        return anchor
    return ChainAnchor(anchor.case_id, anchor.head_index, anchor.head_hash, anchor.anchored_at,
                       TimestampStatus.GRANTED, token, gen_time, tsa_url)


def anchor_event(anchor: ChainAnchor) -> CustodyEvent:
    """The custody event the caller appends after storing `anchor`."""
    status = anchor.timestamp_status.value.upper()
    return CustodyEvent(
        anchor.case_id, ANCHOR_EVENT,
        f"Chain head anchored: entry {anchor.head_index}, hash {anchor.head_hash} ({status}).",
        {"head_index": anchor.head_index, "head_hash": anchor.head_hash,
         "timestamp_status": anchor.timestamp_status.value},
    )


def _anchor_problem(
    anchor: ChainAnchor, case_id: str, entries: Sequence[CustodyEntry], verify: TokenVerifier
) -> str | None:
    """First thing wrong with one anchor, or None."""
    i = anchor.head_index
    if anchor.case_id != case_id:
        return f"the anchor of entry {i} belongs to case {anchor.case_id}, not {case_id}"
    if not 0 <= i < len(entries):
        return (f"entry {i} was anchored (hash {anchor.head_hash}) but the chain now has only "
                f"{len(entries)} entries: entries were removed from the end")
    if entries[i].entry_hash != anchor.head_hash:
        return (f"entry {i} now has hash {entries[i].entry_hash}, but {anchor.head_hash} was "
                "anchored: the chain was rewritten")
    has_token = bool(anchor.rfc3161_token)
    has_time = anchor.timestamp_gen_time is not None
    if anchor.timestamp_status is TimestampStatus.PENDING:
        if has_token or has_time:
            return f"the anchor of entry {i} is PENDING but holds a token or genTime: it was edited"
        return None
    if not (has_token and has_time):
        return f"the anchor of entry {i} is GRANTED but has no token or genTime: it was edited"
    try:
        gen_time = verify(anchor.rfc3161_token or b"", anchor.head_hash)
    except TimestampInvalidError as error:
        return f"the anchor token of entry {i} does not hold: {error}"
    if gen_time != anchor.timestamp_gen_time:
        return (f"the anchor of entry {i} records genTime {anchor.timestamp_gen_time}, but the "
                f"token was signed at {gen_time}: it was edited")
    return None


def _missing_records(entries: Sequence[CustodyEntry], anchors: Sequence[ChainAnchor]) -> str | None:
    """An "anchor" event in the chain whose anchor record is gone."""
    recorded = {(a.head_index, a.head_hash) for a in anchors}
    for entry in entries:
        if entry.event_type != ANCHOR_EVENT:
            continue
        key = (entry.payload.get("head_index"), entry.payload.get("head_hash"))
        if key not in recorded:
            return (f"custody entry {entry.index} records an anchor of entry {key[0]} "
                    f"(hash {key[1]}), but no such anchor record exists: it was removed")
    return None


def check_anchors(
    case_id: str, entries: Sequence[CustodyEntry], anchors: Sequence[ChainAnchor],
    verify: TokenVerifier,
) -> CheckResult:
    """The anchoring check as a CheckResult: False on any problem; None when the case
    has no anchor or its latest anchor is PENDING; True otherwise."""
    ordered = sorted(anchors, key=lambda a: a.head_index)
    for anchor in ordered:
        problem = _anchor_problem(anchor, case_id, entries, verify)
        if problem is not None:
            return CheckResult(CHECK_NAME, False, f"Chain-head anchor broken: {problem}.")
    missing = _missing_records(entries, ordered)
    if missing is not None:
        return CheckResult(CHECK_NAME, False, f"Chain-head anchor broken: {missing}.")
    if not ordered:
        return CheckResult(CHECK_NAME, None, "The chain head was never anchored, so removal of "
                           "entries from the end of the chain cannot be detected.")
    latest = ordered[-1]
    unanchored = len(entries) - 1 - latest.head_index
    tail = f"; the {unanchored} later entries are protected by the chain alone" if unanchored else ""
    head = f"entry {latest.head_index} (hash {latest.head_hash})"
    if latest.timestamp_status is TimestampStatus.PENDING:
        return CheckResult(CHECK_NAME, None, f"{len(ordered)} anchor(s) match the chain, but the "
                           f"latest, {head}, is PENDING: no TSA has signed it yet{tail}.")
    gen_time = latest.timestamp_gen_time.isoformat() if latest.timestamp_gen_time else "?"
    return CheckResult(CHECK_NAME, True, f"{len(ordered)} anchor(s) match the chain; the latest, "
                       f"{head}, was signed by the TSA at {gen_time}, so no anchored entry has "
                       f"been removed{tail}.")
