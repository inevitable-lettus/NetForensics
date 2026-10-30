"""Stage 1b — RFC 3161 trusted timestamps: build the request, check the reply (issue #11).

A Timestamp Authority (TSA) signs "I saw this SHA-256 at time T". This module:
  * builds the DER `TimeStampReq` for a seal's SHA-256 (`build_request`);
  * checks a TSA reply before anything stores it (`verify_reply`);
  * supplies the `Timestamper` hook that `tsa_client.retry_pending` drives
    (`make_timestamper`);
  * re-checks a stored token against its seal for case verification (`check_seal_timestamp`).

The bytes stored in `SealRecord.rfc3161_token` are the TSA's whole DER reply
(`TimeStampResp`), so a stored token can be re-checked with stock tools:
    openssl ts -verify -in reply.tsr -digest <sha256 hex> \\
        -CAfile freetsa_cacert.pem -untrusted freetsa_tsa.crt

WHAT A PASSING CHECK MEANS
--------------------------
`verify_reply` accepts a reply only if ALL of these hold:
  1. Its status is "granted".
  2. Its CMS signature is valid, made by the key of the PINNED TSA certificate
     (backend/evidence/certs/freetsa_tsa.crt), which chains to the pinned CA and was
     valid at the token's own genTime.
  3. The signer certificate carries the critical "time stamping" key purpose.
  4. The token's message imprint is SHA-256 and equals the seal's SHA-256.
  5. At request time, its nonce equals the one we sent (a replayed old reply fails).

Why the TSA certificate is pinned, not just the CA: rfc3161-client up to 1.0.8 adds
the certificates embedded in a reply to the set it trusts, so a forged reply that
embeds its own CA and its own "TSA" certificate verifies against ANY configured root
(reproduced with tests/fixtures/tsa/forged_own_ca.tsr). 1.0.9 refuses that forgery
itself; we keep the pin as defence in depth, so the check never depends on which
library version is installed.

Only "granted" (status 0) is accepted. "waiting" (3) means try later. Every other
status, including "granted with modifications" (1), is refused: the library verifier
only accepts unmodified grants, and a refusal does not improve by asking again.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import httpx
from cryptography import x509
from rfc3161_client import (
    PKIStatus,
    TimeStampResponse,
    VerificationError,
    VerifierBuilder,
    decode_timestamp_response,
)

from backend.config import Config
from backend.evidence.tsa_client import Timestamper, TsaUnavailableError, request_timestamp
from backend.models import CheckResult, SealRecord, TimestampStatus

CHECK_NAME = "rfc3161_timestamp"

_REPO_ROOT = Path(__file__).resolve().parents[2]
# DER of AlgorithmIdentifier { id-sha256 (2.16.840.1.101.3.4.2.1), NULL }. Fixed bytes:
# the request only ever names SHA-256, the digest the seal already computed.
_SHA256_ALGORITHM_ID = bytes.fromhex("300d06096086480165030402010500")
_SHA256_OID = x509.ObjectIdentifier("2.16.840.1.101.3.4.2.1")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class TimestampInvalidError(ValueError):
    """A TSA reply or stored token failed a check. Never stored, never retried: a
    bad signature does not get better by asking again."""


@dataclass(frozen=True)
class TsaTrust:
    """The two certificates a token is checked against, both pinned in the repo."""

    tsa_certificate: x509.Certificate
    ca_certificate: x509.Certificate

    @property
    def tsa_name(self) -> str:
        names = self.tsa_certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return str(names[0].value) if names else self.tsa_certificate.subject.rfc4514_string()


def load_trust(config: Config) -> TsaTrust:
    """Read the pinned certificates and refuse a TSA certificate the CA did not issue,
    so a wrong file fails at start-up rather than as a confusing per-token error."""
    tsa = _load_certificate(config.evidence.tsa_cert_path)
    ca = _load_certificate(config.evidence.tsa_ca_path)
    if tsa == ca:  # a self-signed certificate would pass the issuer check against itself
        raise TimestampInvalidError(
            f"{config.evidence.tsa_cert_path} and {config.evidence.tsa_ca_path} are the same "
            "certificate; the TSA certificate must be issued by a separate CA"
        )
    try:
        tsa.verify_directly_issued_by(ca)
    except (ValueError, TypeError) as error:
        raise TimestampInvalidError(
            f"{config.evidence.tsa_cert_path} was not issued by {config.evidence.tsa_ca_path}: {error}"
        ) from error
    return TsaTrust(tsa, ca)


def _load_certificate(path_text: str) -> x509.Certificate:
    path = Path(path_text)
    path = path if path.is_absolute() else _REPO_ROOT / path
    return x509.load_pem_x509_certificate(path.read_bytes())


# --------------------------------------------------------------------------- #
# Building the request
# --------------------------------------------------------------------------- #


def _der(tag: int, body: bytes) -> bytes:
    """One DER element: tag byte, length (short form < 128, else long form), body."""
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    length = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + body


def _der_integer(value: int) -> bytes:
    """Non-negative DER INTEGER, big-endian, in the fewest bytes plus room for a leading
    0x00 when the top bit is set (otherwise the number would read as negative)."""
    return _der(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def build_request(sha256_hex: str, nonce: int) -> bytes:
    """DER TimeStampReq (RFC 3161 section 2.4.1) for an existing SHA-256 digest:

        SEQUENCE { version 1, messageImprint { sha256, digest }, nonce, certReq TRUE }

    Built by hand because rfc3161-client only builds requests from the raw data, and
    re-reading a multi-GB capture to hash it again is exactly what the seal avoids."""
    digest = _digest_bytes(sha256_hex)
    if nonce < 0:
        raise ValueError("The nonce must not be negative.")
    message_imprint = _der(0x30, _SHA256_ALGORITHM_ID + _der(0x04, digest))
    return _der(0x30, _der_integer(1) + message_imprint + _der_integer(nonce) + _der(0x01, b"\xff"))


def _digest_bytes(sha256_hex: str) -> bytes:
    if not _SHA256_HEX.fullmatch(sha256_hex):
        raise ValueError(f"Not a SHA-256 hex digest: {sha256_hex!r}")
    return bytes.fromhex(sha256_hex)


# --------------------------------------------------------------------------- #
# Checking a reply
# --------------------------------------------------------------------------- #


def decode_reply(reply_der: bytes) -> TimeStampResponse:
    try:
        return decode_timestamp_response(reply_der)
    except ValueError as error:
        raise TimestampInvalidError(f"The reply is not a valid RFC 3161 response: {error}") from error


def verify_reply(
    reply_der: bytes, sha256_hex: str, trust: TsaTrust, nonce: int | None = None
) -> datetime:
    """Run every check in the module docstring; return the TSA's genTime (UTC).
    Raises TimestampInvalidError naming the first check that failed. The token is
    untrusted bytes and the libraries parse parts of it lazily, so a malformed inner
    field can raise from any step with many exception types (ValueError, cryptography's
    InvalidVersion, ...). Every one of them is a failed check, never a crash."""
    digest = _digest_bytes(sha256_hex)
    try:
        return _check_decoded(decode_reply(reply_der), digest, trust, nonce)
    except TimestampInvalidError:
        raise
    except TsaUnavailableError as error:  # "waiting" carries no token to check
        raise TimestampInvalidError(str(error)) from error
    except Exception as error:  # noqa: BLE001 — see docstring: untrusted input
        raise TimestampInvalidError(
            f"The token cannot be read or checked: {type(error).__name__}: {error}"
        ) from error


def _require_granted(reply: TimeStampResponse) -> None:
    """Granted passes; "waiting" is a TsaUnavailableError (retry later); any other or
    unknown status is a TimestampInvalidError."""
    try:
        status = PKIStatus(reply.status)
    except ValueError as error:
        raise TimestampInvalidError(f"The TSA answered with unknown status {reply.status}.") from error
    if status is PKIStatus.GRANTED:
        return
    if status is PKIStatus.WAITING:
        raise TsaUnavailableError("The TSA asked us to wait (status 3, waiting).")
    raise TimestampInvalidError(f"The TSA did not grant a timestamp (status {status.value}, "
                                f"{status.name.lower()}).")


def _check_decoded(
    reply: TimeStampResponse, digest: bytes, trust: TsaTrust, nonce: int | None
) -> datetime:
    _require_granted(reply)
    imprint = reply.tst_info.message_imprint
    if imprint.hash_algorithm != _SHA256_OID:
        raise TimestampInvalidError(f"The token covers a {imprint.hash_algorithm.dotted_string} "
                                    "digest, not SHA-256.")
    if imprint.message != digest:
        raise TimestampInvalidError(f"The token covers SHA-256 {imprint.message.hex()}, not the "
                                    f"sealed {digest.hex()}.")
    builder = VerifierBuilder(tsa_certificate=trust.tsa_certificate, roots=[trust.ca_certificate])
    if nonce is not None:
        builder = builder.nonce(nonce)
    try:
        builder.build().verify(reply, digest)
    except VerificationError as error:
        raise TimestampInvalidError(f"The token's signature or certificate check failed: {error}") from error
    return reply.tst_info.gen_time


# --------------------------------------------------------------------------- #
# The Timestamper hook (tsa_client drives it)
# --------------------------------------------------------------------------- #


def make_timestamper(
    config: Config,
    transport: httpx.BaseTransport | None = None,
    new_nonce: Callable[[], int] = lambda: secrets.randbits(64),
) -> Timestamper:
    """Return `(sha256_hex) -> (reply_der, gen_time)` for `retry_pending`. "waiting"
    raises TsaUnavailableError (retried with backoff, seal stays PENDING); any other
    refusal, or a reply that fails a check, raises TimestampInvalidError and is never
    stored (the retry batch reports it as an error)."""
    trust = load_trust(config)

    def timestamp(sha256_hex: str) -> tuple[bytes, datetime]:
        nonce = new_nonce()
        reply_der = request_timestamp(build_request(sha256_hex, nonce), config, transport)
        _require_granted(decode_reply(reply_der))
        return reply_der, verify_reply(reply_der, sha256_hex, trust, nonce)

    return timestamp


# --------------------------------------------------------------------------- #
# Re-checking a stored token (used by case verification, #12)
# --------------------------------------------------------------------------- #


def check_seal_timestamp(seal: SealRecord, trust: TsaTrust) -> CheckResult:
    """The timestamp check as a magistrate-readable CheckResult. Only a seal that was
    never stamped (PENDING, no token, no genTime) is "not run" (passed=None), never a
    pass. Any half-stamped combination fails: the record moves PENDING -> GRANTED in one
    database update, so a mix can only come from editing it. The nonce is not
    re-checked: it only proves the reply was fresh when it arrived, which
    `make_timestamper` already did."""
    inconsistency = _inconsistency(seal)
    if inconsistency is not None:
        return CheckResult(CHECK_NAME, False, f"The timestamp record is inconsistent "
                           f"({inconsistency}): it was edited after it was written.")
    if seal.timestamp_status is TimestampStatus.PENDING:
        return CheckResult(CHECK_NAME, None, "No trusted timestamp yet: the seal is PENDING, so "
                           "when the evidence was sealed rests on this system's clock alone.")
    try:
        gen_time = verify_reply(seal.rfc3161_token or b"", seal.sha256_hash, trust)
    except TimestampInvalidError as error:
        return CheckResult(CHECK_NAME, False, f"The stored timestamp token does not hold: {error}")
    if seal.timestamp_gen_time != gen_time:
        return CheckResult(CHECK_NAME, False, f"The stored genTime {seal.timestamp_gen_time} differs "
                           f"from the {gen_time} signed inside the token: the record was edited.")
    return CheckResult(
        CHECK_NAME,
        True,
        f"{trust.tsa_name} signed SHA-256 {seal.sha256_hash} at {gen_time.isoformat()} "
        f"(its clock; this system logged receipt at {seal.received_at.isoformat()}); the "
        "signature verifies with the pinned TSA certificate.",
    )


def _inconsistency(seal: SealRecord) -> str | None:
    has_token = bool(seal.rfc3161_token)
    has_time = seal.timestamp_gen_time is not None
    if seal.timestamp_status is TimestampStatus.GRANTED and not (has_token and has_time):
        missing = " and ".join(n for n, ok in (("token", has_token), ("genTime", has_time)) if not ok)
        return f"GRANTED but no {missing}"
    if seal.timestamp_status is TimestampStatus.PENDING and (has_token or has_time):
        present = " and ".join(n for n, ok in (("a token", has_token), ("a genTime", has_time)) if ok)
        return f"PENDING but holds {present}"
    return None
