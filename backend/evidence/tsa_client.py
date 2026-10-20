"""RFC 3161 transport + retry plumbing (issue #3). Moves bytes; never judges them.

Building the `TimeStampReq` and verifying the returned token (signature, cert chain,
message imprint, genTime) is core work in `timestamp.py` (#11). This module only:
  * POSTs request bytes to the TSA and hands back the raw response (`request_timestamp`);
  * drives a *timestamper* — a callable `(sha256_hex) -> (token, gen_time)` supplied by
    the core — for seals still PENDING, and records GRANTED through the store's
    one-time update path (`retry_pending`, `retry_all_pending`).

A timestamp is never faked: if the TSA cannot be reached the seal stays PENDING and
the reason is reported. Storing a token is not verifying it — `verify.py` does that.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

import httpx

from backend.config import Config
from backend.db.interfaces import CaseRepository
from backend.models import TimestampStatus

_QUERY_CONTENT_TYPE = "application/timestamp-query"
_REPLY_CONTENT_TYPE = "application/timestamp-reply"

Timestamper = Callable[[str], tuple[bytes, datetime]]


class TsaUnavailableError(RuntimeError):
    """The TSA could not be reached or gave no usable reply (timeout, DNS/connection
    failure, non-200, empty body). The cause is chained and named in the message."""


class RetryOutcome(str, Enum):
    GRANTED = "granted"                  # token obtained and stored this run
    ALREADY_GRANTED = "already_granted"  # nothing to do
    STILL_PENDING = "still_pending"      # TSA unavailable on every attempt
    ERROR = "error"                      # anything else (e.g. core rejected the token)


@dataclass(frozen=True)
class RetryResult:
    case_id: str
    outcome: RetryOutcome
    attempts: int
    detail: str


def request_timestamp(
    request_der: bytes, config: Config, transport: httpx.BaseTransport | None = None
) -> bytes:
    """POST one DER `TimeStampReq` to the configured TSA and return the DER reply.
    No retries here — the caller decides. `transport` lets tests stub the network."""
    url = config.evidence.tsa_url
    try:
        with httpx.Client(transport=transport, timeout=config.evidence.tsa_timeout_secs) as client:
            response = client.post(
                url,
                content=request_der,
                headers={"Content-Type": _QUERY_CONTENT_TYPE, "Accept": _REPLY_CONTENT_TYPE},
            )
    except httpx.HTTPError as error:  # timeouts, DNS, refused connections, ...
        raise TsaUnavailableError(f"TSA {url} unreachable: {error!r}") from error
    if response.status_code != 200:
        raise TsaUnavailableError(f"TSA {url} answered HTTP {response.status_code}.")
    if not response.content:
        raise TsaUnavailableError(f"TSA {url} answered HTTP 200 with an empty body.")
    return response.content


def backoff_delay(config: Config, failed_attempts: int) -> float:
    """Pause after the n-th failed attempt: base, 2*base, 4*base, ... capped at max."""
    evidence = config.evidence
    delay = evidence.tsa_retry_backoff_secs * 2 ** (failed_attempts - 1)
    return min(delay, evidence.tsa_retry_backoff_max_secs)


def retry_pending(
    case_id: str,
    store: CaseRepository,
    timestamper: Timestamper,
    config: Config,
    sleep: Callable[[float], None] = time.sleep,
    attempts: int | None = None,
) -> RetryResult:
    """Try to obtain and store a token for one PENDING seal. TSA unavailability is
    retried with backoff and reported, never raised; other errors propagate."""
    seal = store.load(case_id).seal
    if seal.timestamp_status is TimestampStatus.GRANTED:
        return RetryResult(case_id, RetryOutcome.ALREADY_GRANTED, 0, "Seal already timestamped.")
    attempts = attempts or config.evidence.tsa_retry_attempts
    last_error = ""
    for attempt in range(1, attempts + 1):
        try:
            token, gen_time = timestamper(seal.sha256_hash)
        except TsaUnavailableError as error:
            last_error = str(error)
            if attempt < attempts:
                sleep(backoff_delay(config, attempt))
            continue
        store.record_timestamp(case_id, token, gen_time, config.evidence.tsa_url)
        return RetryResult(case_id, RetryOutcome.GRANTED, attempt, f"TSA genTime {gen_time}.")
    return RetryResult(case_id, RetryOutcome.STILL_PENDING, attempts, last_error)


def retry_all_pending(
    store: CaseRepository,
    timestamper: Timestamper,
    config: Config,
    sleep: Callable[[float], None] = time.sleep,
) -> list[RetryResult]:
    """Retry every PENDING seal. One case failing never stops the rest."""
    results = []
    for case_id in store.pending_timestamp_case_ids():
        try:
            results.append(retry_pending(case_id, store, timestamper, config, sleep))
        except Exception as error:  # noqa: BLE001 — report, keep going (issue #3)
            results.append(RetryResult(case_id, RetryOutcome.ERROR, 0, repr(error)))
    return results
