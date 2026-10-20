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

import contextlib
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

import httpx

from backend.config import Config
from backend.db.interfaces import CaseRepository, SealUpdateError
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
    No retries here — the caller decides. `transport` lets tests stub the network.

    httpx timeouts apply per network operation, so a server dripping one byte at a
    time — in the headers or the body — could hold a plain request open forever.
    The whole exchange therefore runs in a daemon worker thread and the caller
    waits at most `tsa_timeout_secs` in total. On timeout the client is closed to
    release the socket; a worker stuck on a hostile server is abandoned (daemon, so
    it can never block process exit). The body is also size-capped.
    """
    url = config.evidence.tsa_url
    timeout = config.evidence.tsa_timeout_secs
    client = httpx.Client(transport=transport, timeout=timeout)
    outcome: dict[str, object] = {}

    def exchange() -> None:
        try:
            outcome["body"] = _post_and_read(client, request_der, config, time.monotonic() + timeout)
        except BaseException as error:  # handed to the caller below
            outcome["error"] = error

    worker = threading.Thread(target=exchange, name="tsa-request", daemon=True)
    worker.start()
    worker.join(timeout)
    with contextlib.suppress(Exception):
        client.close()
    if worker.is_alive():
        raise TsaUnavailableError(f"TSA {url} gave no complete reply within {timeout}s.")
    return _unwrap(outcome, url)


def _post_and_read(client: httpx.Client, request_der: bytes, config: Config, deadline: float) -> bytes:
    url = config.evidence.tsa_url
    with client.stream(
        "POST",
        url,
        content=request_der,
        headers={"Content-Type": _QUERY_CONTENT_TYPE, "Accept": _REPLY_CONTENT_TYPE},
    ) as response:
        if response.status_code != 200:
            raise TsaUnavailableError(f"TSA {url} answered HTTP {response.status_code}.")
        return _read_bounded(response, url, deadline, config.evidence.tsa_max_reply_bytes)


def _unwrap(outcome: dict[str, object], url: str) -> bytes:
    """Turn the worker's result into bytes or a typed TsaUnavailableError."""
    error = outcome.get("error")
    if isinstance(error, httpx.HTTPError):  # timeouts, DNS, refused connections, ...
        raise TsaUnavailableError(f"TSA {url} unreachable: {error!r}") from error
    if isinstance(error, BaseException):
        raise error
    body = outcome.get("body")
    if not isinstance(body, bytes) or not body:
        raise TsaUnavailableError(f"TSA {url} answered HTTP 200 with an empty body.")
    return body


def _read_bounded(response: httpx.Response, url: str, deadline: float, max_bytes: int) -> bytes:
    body = bytearray()
    for chunk in response.iter_bytes():
        body += chunk
        if len(body) > max_bytes:
            raise TsaUnavailableError(f"TSA {url} reply exceeds {max_bytes} bytes.")
        if time.monotonic() > deadline:
            raise TsaUnavailableError(f"TSA {url} reply not complete within the deadline.")
    return bytes(body)


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
    retried with backoff and reported, and a token the store refuses is reported as
    ERROR; any other exception (e.g. from the core timestamper) propagates."""
    seal = store.load(case_id).seal
    if seal.timestamp_status is TimestampStatus.GRANTED:
        return RetryResult(case_id, RetryOutcome.ALREADY_GRANTED, 0, "Seal already timestamped.")
    attempts = max(1, attempts or config.evidence.tsa_retry_attempts)
    last_error = ""
    for attempt in range(1, attempts + 1):
        try:
            token, gen_time = timestamper(seal.sha256_hash)
        except TsaUnavailableError as error:
            last_error = str(error)
            if attempt < attempts:
                sleep(backoff_delay(config, attempt))
            continue
        return _record(case_id, store, token, gen_time, config, attempt)
    return RetryResult(case_id, RetryOutcome.STILL_PENDING, attempts, last_error)


def _record(
    case_id: str, store: CaseRepository, token: bytes, gen_time: datetime, config: Config,
    attempt: int,
) -> RetryResult:
    """Store the token. If a concurrent retry granted the seal first, the store's
    one-time rule refuses ours — report that as already granted, not as an error."""
    try:
        store.record_timestamp(case_id, token, gen_time, config.evidence.tsa_url)
    except SealUpdateError as error:
        if store.load(case_id).seal.timestamp_status is not TimestampStatus.GRANTED:
            # A real refusal (e.g. an empty token): the seal stays PENDING.
            return RetryResult(case_id, RetryOutcome.ERROR, attempt, str(error))
        return RetryResult(case_id, RetryOutcome.ALREADY_GRANTED, attempt,
                           "Another retry granted this seal first.")
    return RetryResult(case_id, RetryOutcome.GRANTED, attempt, f"TSA genTime {gen_time}.")


def retry_all_pending(
    store: CaseRepository,
    timestamper: Timestamper,
    config: Config,
    sleep: Callable[[float], None] = time.sleep,
) -> list[RetryResult]:
    """Retry every PENDING seal. One case failing never stops the rest — except
    the circuit breaker: after `tsa_batch_stop_after_unavailable` consecutive cases
    find the TSA down, the remaining cases are skipped (left PENDING) for this run."""
    results: list[RetryResult] = []
    unavailable_streak = 0
    limit = config.evidence.tsa_batch_stop_after_unavailable
    for case_id in store.pending_timestamp_case_ids():
        if unavailable_streak >= limit:
            results.append(RetryResult(case_id, RetryOutcome.STILL_PENDING, 0,
                                       f"Skipped: TSA down for {limit} cases in a row."))
            continue
        try:
            result = retry_pending(case_id, store, timestamper, config, sleep)
        except Exception as error:  # noqa: BLE001 — report, keep going (issue #3)
            result = RetryResult(case_id, RetryOutcome.ERROR, 0, repr(error))
        tsa_down = result.outcome is RetryOutcome.STILL_PENDING
        unavailable_streak = unavailable_streak + 1 if tsa_down else 0
        results.append(result)
    return results
