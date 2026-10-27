"""RFC 3161 request building and token checking (issue #11).

Fixtures in tests/fixtures/tsa/ (see the README there):
  freetsa_vector.tsq / .tsr  a real request and FreeTSA's real reply, 2026-10-27
  forged_own_ca.tsr          signed by a home-made "TSA" that embeds its own CA
  forged_no_ca.tsr           signed by the same home-made TSA, no CA embedded
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from rfc3161_client import VerifierBuilder, decode_timestamp_response

from backend.config import CONFIG, Config
from backend.db.storage import Storage
from backend.evidence.timestamp import (
    TimestampInvalidError,
    build_request,
    check_seal_timestamp,
    load_trust,
    make_timestamper,
    verify_reply,
)
from backend.evidence.tsa_client import RetryOutcome, TsaUnavailableError, retry_pending
from backend.models import CaseRecord, SealRecord, TimestampStatus

FIXTURES = Path(__file__).parent / "fixtures" / "tsa"
VECTOR_SHA256 = "3880d492474a081da2f86d7e886aa25d579b1f4bcc3f9e387c6d681aaa76a3e7"
VECTOR_NONCE = 0x5EEDF00DCAFEBEEF
VECTOR_GEN_TIME = datetime(2026, 10, 27, 9, 29, 26, tzinfo=timezone.utc)
OTHER_SHA256 = "0" * 64
REJECTION_REPLY = bytes.fromhex("3005300302 0102".replace(" ", ""))  # status: rejection (2)


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


@pytest.fixture(scope="module")
def trust():
    return load_trust(CONFIG)


def _seal(sha256: str = VECTOR_SHA256, **changes) -> SealRecord:
    seal = SealRecord(
        pcap_filename="vector.pcap", pcap_size_bytes=34, hash_algorithm="blake3",
        pcap_hash="1" * 64, sha256_hash=sha256,
        received_at=datetime(2026, 10, 27, 9, 29, 0, tzinfo=timezone.utc),
    )
    return replace(seal, **changes)


def _granted(sha256: str = VECTOR_SHA256, **changes) -> SealRecord:
    granted = {"timestamp_status": TimestampStatus.GRANTED,
               "rfc3161_token": _fixture("freetsa_vector.tsr"),
               "timestamp_gen_time": VECTOR_GEN_TIME, "tsa_url": CONFIG.evidence.tsa_url}
    return _seal(sha256, **(granted | changes))


def _transport(reply: bytes) -> httpx.MockTransport:
    return httpx.MockTransport(lambda _request: httpx.Response(200, content=reply))


# --------------------------------------------------------------------------- #
# Request
# --------------------------------------------------------------------------- #


def test_request_matches_the_one_freetsa_answered_byte_for_byte():
    assert build_request(VECTOR_SHA256, VECTOR_NONCE) == _fixture("freetsa_vector.tsq")


@pytest.mark.parametrize(("nonce", "der"), [
    (0, "020100"), (127, "02017f"), (128, "02020080"), (2**64 - 1, "020900ffffffffffffffff"),
])
def test_nonce_is_a_minimal_non_negative_der_integer(nonce, der):
    assert build_request(OTHER_SHA256, nonce).endswith(bytes.fromhex(der + "0101ff"))


@pytest.mark.parametrize("bad", ["", "ab" * 31, "AB" * 32, "ab " * 21 + "a", "zz" * 32])
def test_request_refuses_anything_but_a_lowercase_sha256_hex(bad):
    with pytest.raises(ValueError):
        build_request(bad, 1)


# --------------------------------------------------------------------------- #
# Reply checks
# --------------------------------------------------------------------------- #


def test_real_freetsa_reply_verifies_and_yields_its_gen_time(trust):
    assert verify_reply(_fixture("freetsa_vector.tsr"), VECTOR_SHA256, trust,
                        VECTOR_NONCE) == VECTOR_GEN_TIME


def test_reply_for_a_different_hash_is_refused(trust):
    with pytest.raises(TimestampInvalidError, match=f"covers SHA-256 {VECTOR_SHA256}, not the sealed"):
        verify_reply(_fixture("freetsa_vector.tsr"), OTHER_SHA256, trust)


def test_replayed_reply_with_the_wrong_nonce_is_refused(trust):
    with pytest.raises(TimestampInvalidError, match="Nonce mismatch"):
        verify_reply(_fixture("freetsa_vector.tsr"), VECTOR_SHA256, trust, VECTOR_NONCE + 1)


@pytest.mark.parametrize("name", ["forged_own_ca.tsr", "forged_no_ca.tsr"])
def test_reply_signed_by_anyone_but_the_pinned_tsa_is_refused(trust, name):
    with pytest.raises(TimestampInvalidError, match="signature or certificate check failed"):
        verify_reply(_fixture(name), VECTOR_SHA256, trust, VECTOR_NONCE)


def test_why_the_tsa_certificate_is_pinned(trust):
    """Documents the library behaviour the pin defends against: with only a root
    configured, rfc3161-client 1.0.8 accepts a forgery that embeds its own CA. If this
    test starts failing, the library got stricter; the pin stays either way."""
    forged = decode_timestamp_response(_fixture("forged_own_ca.tsr"))
    verifier = VerifierBuilder(roots=[trust.ca_certificate]).build()
    assert verifier.verify(forged, bytes.fromhex(VECTOR_SHA256))


def test_every_single_byte_flip_in_the_signed_token_is_refused(trust):
    reply = _fixture("freetsa_vector.tsr")
    survivors = []
    for position in range(len(reply)):
        tampered = bytearray(reply)
        tampered[position] ^= 0x01
        try:
            verify_reply(bytes(tampered), VECTOR_SHA256, trust, VECTOR_NONCE)
        except TimestampInvalidError:
            continue
        survivors.append(position)
    # Only bytes outside what the signature covers may survive, and none of them may
    # change the hash or the time the token vouches for.
    for position in survivors:
        tampered = bytearray(reply)
        tampered[position] ^= 0x01
        info = decode_timestamp_response(bytes(tampered)).tst_info
        assert (info.message_imprint.message.hex(), info.gen_time) == (VECTOR_SHA256, VECTOR_GEN_TIME)


@pytest.mark.parametrize("reply", [b"", b"not der at all", REJECTION_REPLY])
def test_garbage_or_rejected_reply_is_refused(trust, reply):
    with pytest.raises(TimestampInvalidError):
        verify_reply(reply, VECTOR_SHA256, trust)


def test_trust_refuses_a_tsa_certificate_the_ca_did_not_issue():
    wrong = replace(CONFIG, evidence=replace(
        CONFIG.evidence, tsa_ca_path=CONFIG.evidence.tsa_cert_path))
    with pytest.raises(TimestampInvalidError, match="was not issued by"):
        load_trust(wrong)


def test_pinned_certificates_are_the_freetsa_ones(trust):
    assert trust.tsa_name == "www.freetsa.org"
    usage = trust.tsa_certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert usage.critical and x509.ExtendedKeyUsageOID.TIME_STAMPING in usage.value


# --------------------------------------------------------------------------- #
# Timestamper hook
# --------------------------------------------------------------------------- #


def _timestamper(reply: bytes, config: Config = CONFIG):
    return make_timestamper(config, _transport(reply), new_nonce=lambda: VECTOR_NONCE)


def test_timestamper_returns_the_whole_reply_and_its_gen_time():
    reply = _fixture("freetsa_vector.tsr")
    assert _timestamper(reply)(VECTOR_SHA256) == (reply, VECTOR_GEN_TIME)


def test_timestamper_treats_a_rejection_as_unavailable_so_it_is_retried():
    with pytest.raises(TsaUnavailableError, match="did not grant"):
        _timestamper(REJECTION_REPLY)(VECTOR_SHA256)


def test_timestamper_refuses_a_forged_reply():
    with pytest.raises(TimestampInvalidError):
        _timestamper(_fixture("forged_own_ca.tsr"))(VECTOR_SHA256)


def _stored_case(tmp_path: Path) -> tuple[Storage, str]:
    storage = Storage.open(replace(CONFIG.evidence, evidence_store_dir=str(tmp_path),
                                   db_path=str(tmp_path / "nf.sqlite")))
    case_id = "a" * 32
    storage.cases.save(CaseRecord(case_id, _seal(), (), 0))
    return storage, case_id


def test_granted_token_survives_storage_and_rechecks(tmp_path: Path, trust):
    storage, case_id = _stored_case(tmp_path)
    result = retry_pending(case_id, storage.cases, _timestamper(_fixture("freetsa_vector.tsr")),
                           CONFIG, attempts=1)
    assert result.outcome is RetryOutcome.GRANTED
    check = check_seal_timestamp(storage.cases.load(case_id).seal, trust)
    assert check.passed is True
    assert "www.freetsa.org signed SHA-256 " + VECTOR_SHA256 in check.evidence
    assert "2026-10-27T09:29:26+00:00" in check.evidence


def test_forged_reply_is_never_stored(tmp_path: Path):
    storage, case_id = _stored_case(tmp_path)
    with pytest.raises(TimestampInvalidError):
        retry_pending(case_id, storage.cases, _timestamper(_fixture("forged_own_ca.tsr")),
                      CONFIG, attempts=1)
    assert storage.cases.load(case_id).seal.timestamp_status is TimestampStatus.PENDING


# --------------------------------------------------------------------------- #
# Stored-token check (for #12)
# --------------------------------------------------------------------------- #


def test_pending_seal_is_not_run_never_a_pass(trust):
    check = check_seal_timestamp(_seal(), trust)
    assert check.passed is None and "PENDING" in check.evidence


def test_token_for_other_evidence_fails(trust):
    check = check_seal_timestamp(_granted(OTHER_SHA256), trust)
    assert check.passed is False and "not the sealed " + OTHER_SHA256 in check.evidence


def test_edited_gen_time_column_fails(trust):
    edited = _granted(timestamp_gen_time=datetime(2026, 1, 1, tzinfo=timezone.utc))
    check = check_seal_timestamp(edited, trust)
    assert check.passed is False and "the record was edited" in check.evidence


def test_corrupted_stored_token_fails(trust):
    token = bytearray(_fixture("freetsa_vector.tsr"))
    token[-1] ^= 0xFF
    check = check_seal_timestamp(_granted(rfc3161_token=bytes(token)), trust)
    assert check.passed is False


@pytest.mark.network
def test_live_freetsa_round_trip():
    reply, gen_time = make_timestamper(CONFIG)(VECTOR_SHA256)
    assert verify_reply(reply, VECTOR_SHA256, load_trust(CONFIG)) == gen_time
