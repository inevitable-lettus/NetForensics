from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from backend.db.serialization import to_jsonable
from backend.evidence.custody import (
    CustodyEvent,
    build_entry,
    compute_entry_hash,
    find_chain_break,
    genesis_prev_hash,
    verify_chain,
)
from backend.models import CustodyEntry, SealRecord

CASE = "c" * 32
T0 = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)
SEAL = SealRecord(
    pcap_filename="capture.pcap",
    pcap_size_bytes=1234,
    hash_algorithm="blake3",
    pcap_hash="b" * 64,
    sha256_hash="5" * 64,
    received_at=T0,
)


def _chain(length: int = 4, seal: SealRecord = SEAL, case_id: str = CASE) -> list[CustodyEntry]:
    entries: list[CustodyEntry] = []
    for i in range(length):
        event = CustodyEvent(case_id, "ingest" if i == 0 else "finding", f"event {i}",
                             {"n": i, "tags": ["a", "b"], "nested": {"ok": True, "none": None}})
        prev = entries[-1] if entries else None
        entries.append(build_entry(seal, prev, event, T0 + timedelta(seconds=i)))
    return entries


# --------------------------------------------------------------------------- #
# Golden vectors — reproducible by hand, independent of canonical_json
# --------------------------------------------------------------------------- #

GENESIS_JSON = (
    '{"hash_algorithm":"blake3","pcap_filename":"capture.pcap","pcap_hash":"' + "b" * 64
    + '","pcap_size_bytes":1234,"received_at":"2026-10-20T12:00:00.000000Z","sha256_hash":"'
    + "5" * 64 + '"}'
)


def test_genesis_golden_vector():
    expected = hashlib.sha256(b"netforensics/custody-genesis/v1\x00" + GENESIS_JSON.encode()).hexdigest()
    assert genesis_prev_hash(SEAL) == expected == GENESIS_HEX


def test_entry_golden_vector():
    entry = build_entry(SEAL, None, CustodyEvent(CASE, "ingest", "Sealed capture.pcap",
                                                 {"bytes": 1234, "note": "é"}), T0)
    body = (
        '{"case_id":"' + CASE + '","detail":"Sealed capture.pcap","event_type":"ingest",'
        '"index":0,"payload":{"bytes":1234,"note":"é"},"prev_hash":"' + GENESIS_HEX + '",'
        '"timestamp":"2026-10-20T12:00:00.000000Z"}'
    )
    expected = hashlib.sha256(b"netforensics/custody-entry/v1\x00" + body.encode("utf-8")).hexdigest()
    assert entry.entry_hash == expected == ENTRY_HEX


# --------------------------------------------------------------------------- #
# Building
# --------------------------------------------------------------------------- #


def test_build_assigns_index_and_links():
    entries = _chain(3)
    assert [e.index for e in entries] == [0, 1, 2]
    assert entries[0].prev_hash == genesis_prev_hash(SEAL)
    assert entries[1].prev_hash == entries[0].entry_hash
    assert entries[2].prev_hash == entries[1].entry_hash


def test_build_is_deterministic():
    assert _chain(3) == _chain(3)


def test_build_stores_time_in_utc():
    ist = timezone(timedelta(hours=5, minutes=30))
    entry = build_entry(SEAL, None, CustodyEvent(CASE, "ingest", "x"), T0.astimezone(ist))
    assert entry.timestamp.utcoffset() == timedelta(0)
    assert entry.entry_hash == build_entry(SEAL, None, CustodyEvent(CASE, "ingest", "x"), T0).entry_hash


@pytest.mark.parametrize(
    "payload",
    [{"entropy": 4.2}, {"nan": float("nan")}, {"t": (1, 2)}, {1: "x"}, {"b": b"x"},
     {"deep": [{"x": 1.5}]}],
    ids=["float", "nan", "tuple", "int-key", "bytes", "nested-float"],
)
def test_non_canonical_payloads_are_refused(payload):
    with pytest.raises(TypeError):
        build_entry(SEAL, None, CustodyEvent(CASE, "ingest", "x", payload), T0)


def test_naive_timestamp_is_refused():
    with pytest.raises(ValueError, match="timezone"):
        build_entry(SEAL, None, CustodyEvent(CASE, "ingest", "x"), T0.replace(tzinfo=None))


def test_cannot_chain_after_another_cases_entry():
    other = _chain(1, case_id="d" * 32)[0]
    with pytest.raises(ValueError, match="Cannot chain"):
        build_entry(SEAL, other, CustodyEvent(CASE, "finding", "x"), T0)


def test_field_boundaries_cannot_shift():
    """With a naive "|".join these two would hash identically."""
    a = build_entry(SEAL, None, CustodyEvent(CASE, "ingest", "x|y"), T0)
    b = build_entry(SEAL, None, CustodyEvent(CASE, "ingest|x", "y"), T0)
    assert a.entry_hash != b.entry_hash


def test_unicode_is_hashed_exactly_without_normalisation():
    composed = build_entry(SEAL, None, CustodyEvent(CASE, "ingest", "café"), T0)
    decomposed = build_entry(SEAL, None, CustodyEvent(CASE, "ingest", "café"), T0)
    assert composed.entry_hash != decomposed.entry_hash


# --------------------------------------------------------------------------- #
# Verifying
# --------------------------------------------------------------------------- #


def test_intact_chain_passes_and_names_its_head():
    entries = _chain(4)
    assert find_chain_break(SEAL, CASE, entries) is None
    result = verify_chain(SEAL, CASE, entries)
    assert result.passed is True
    assert entries[-1].entry_hash in result.evidence
    assert "removed from the end" in result.evidence


def test_single_entry_chain_passes():
    assert find_chain_break(SEAL, CASE, _chain(1)) is None


def test_empty_chain_is_a_break():
    broken = find_chain_break(SEAL, CASE, [])
    assert broken is not None and broken.index == 0
    assert verify_chain(SEAL, CASE, []).passed is False


def test_every_entry_field_has_a_mutation():
    assert {f.name for f in dataclasses.fields(CustodyEntry)} == {
        name.split("-")[0] for name in MUTATIONS
    }


MUTATIONS = {
    "case_id": lambda e: dataclasses.replace(e, case_id="f" * 32),
    "index": lambda e: dataclasses.replace(e, index=e.index + 10),
    "timestamp": lambda e: dataclasses.replace(e, timestamp=e.timestamp + timedelta(microseconds=1)),
    "event_type": lambda e: dataclasses.replace(e, event_type=e.event_type + "x"),
    "detail": lambda e: dataclasses.replace(e, detail=e.detail + " "),
    "prev_hash": lambda e: dataclasses.replace(e, prev_hash="0" * 64),
    "entry_hash": lambda e: dataclasses.replace(e, entry_hash="0" * 64),
    "payload-value": lambda e: dataclasses.replace(e, payload={**e.payload, "n": -1}),
    "payload-nested": lambda e: dataclasses.replace(
        e, payload={**e.payload, "nested": {"ok": False, "none": None}}),
    "payload-added-key": lambda e: dataclasses.replace(e, payload={**e.payload, "extra": 1}),
}


@pytest.mark.parametrize("field_name", list(MUTATIONS))
@pytest.mark.parametrize("position", range(4))
def test_any_single_field_change_breaks_at_exactly_that_index(field_name: str, position: int):
    entries = _chain(4)
    entries[position] = MUTATIONS[field_name](entries[position])
    broken = find_chain_break(SEAL, CASE, entries)
    assert broken is not None and broken.index == position, broken


def test_deleting_a_middle_entry_breaks():
    entries = _chain(4)
    del entries[1]
    assert find_chain_break(SEAL, CASE, entries).index == 1


def test_swapping_two_entries_breaks():
    entries = _chain(4)
    entries[1], entries[2] = entries[2], entries[1]
    assert find_chain_break(SEAL, CASE, entries).index == 1


def test_duplicating_an_entry_breaks():
    entries = _chain(3)
    entries.insert(2, entries[1])
    assert find_chain_break(SEAL, CASE, entries).index == 2


def test_inserting_a_forged_entry_breaks():
    """A forger can build a perfectly valid entry 2 off the real entry 1, but the
    real entry 2 that follows no longer sits at its own index."""
    entries = _chain(4)
    forged = build_entry(SEAL, entries[1], CustodyEvent(CASE, "finding", "forged"), T0)
    entries.insert(2, forged)
    assert find_chain_break(SEAL, CASE, entries).index == 3


def test_chain_built_for_one_seal_fails_against_another():
    other_seal = dataclasses.replace(SEAL, received_at=T0 + timedelta(seconds=1))
    broken = find_chain_break(other_seal, CASE, _chain(3))
    assert broken.index == 0 and "not bound to this evidence" in broken.reason


def test_chain_of_another_case_fails():
    broken = find_chain_break(SEAL, CASE, _chain(3, case_id="d" * 32))
    assert broken.index == 0 and "belongs to case" in broken.reason


def test_entry_spliced_in_from_another_case_fails():
    entries = _chain(3)
    entries[1] = _chain(3, case_id="d" * 32)[1]
    assert find_chain_break(SEAL, CASE, entries).index == 1


def test_seal_timestamp_grant_does_not_break_the_chain():
    granted = dataclasses.replace(SEAL, rfc3161_token=b"t", timestamp_gen_time=T0, tsa_url="u")
    assert find_chain_break(granted, CASE, _chain(3)) is None


def test_tail_truncation_is_not_detected_by_the_chain_alone():
    """Documented limitation: closed by chain-head anchoring (#12), not here."""
    assert find_chain_break(SEAL, CASE, _chain(4)[:2]) is None


def test_hash_is_stable_across_json_round_trip_in_another_offset():
    original = _chain(2)[1]
    raw = json.loads(json.dumps(to_jsonable(original)))
    ist = timezone(timedelta(hours=5, minutes=30))
    restored = CustodyEntry(
        case_id=raw["case_id"],
        index=raw["index"],
        timestamp=datetime.fromisoformat(raw["timestamp"]).astimezone(ist),
        event_type=raw["event_type"],
        detail=raw["detail"],
        prev_hash=raw["prev_hash"],
        entry_hash=raw["entry_hash"],
        payload=raw["payload"],
    )
    assert compute_entry_hash(restored) == original.entry_hash


GENESIS_HEX = "f3504c93b04789014fd97e61ae693703bc8ba15ce72fcfe2f3c46a1a09db360d"
ENTRY_HEX = "d09e4a5f14245902532a8b648e027c6106d38f1b9df6b683a302df802c6939fe"


def _nested(depth: int) -> object:
    value: object = "leaf"
    for _ in range(depth):
        value = [value]
    return value


def test_deeply_nested_payload_is_refused_at_build():
    with pytest.raises(TypeError, match="nested deeper"):
        build_entry(SEAL, None, CustodyEvent(CASE, "ingest", "x", {"p": _nested(40)}), T0)


def test_crafted_deep_payload_in_storage_is_a_break_not_a_crash():
    entries = _chain(2)
    entries[1] = dataclasses.replace(entries[1], payload={"p": _nested(5000)})
    broken = find_chain_break(SEAL, CASE, entries)
    assert broken is not None and broken.index == 1
    assert "cannot be re-hashed" in broken.reason


def test_hash_algorithm_and_tags_are_pinned_in_code_not_config():
    import backend.config as config_module
    import backend.evidence.custody as custody

    assert (custody.HASH_NAME, custody.ENTRY_TAG, custody.GENESIS_TAG) == (
        "sha256", "netforensics/custody-entry/v1", "netforensics/custody-genesis/v1",
    )
    assert "custody" not in " ".join(f.name for f in dataclasses.fields(config_module.EvidenceConfig))


def test_naive_seal_time_is_a_reported_break_not_a_crash():
    naive = dataclasses.replace(SEAL, received_at=T0.replace(tzinfo=None))
    broken = find_chain_break(naive, CASE, _chain(1))
    assert broken.index == 0 and "genesis link cannot be derived" in broken.reason
    assert verify_chain(naive, CASE, _chain(1)).passed is False
