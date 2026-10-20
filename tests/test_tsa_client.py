from __future__ import annotations

import dataclasses
import socket
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from backend.config import Config, EvidenceConfig
from backend.db.case_repository import SqliteCaseRepository
from backend.evidence.tsa_client import (
    RetryOutcome,
    TsaUnavailableError,
    backoff_delay,
    request_timestamp,
    retry_all_pending,
    retry_pending,
)
from backend.models import TimestampStatus
from backend.pipeline import analyze_pcap
from tests.fixtures.packets import syn_frame, write_timed_pcap

GEN_TIME = datetime(2026, 10, 20, 12, 0, 5, tzinfo=timezone.utc)
CONFIG = Config(
    evidence=EvidenceConfig(
        tsa_url="https://tsa.invalid/tsr",
        tsa_timeout_secs=1,
        tsa_retry_attempts=3,
        tsa_retry_backoff_secs=2.0,
        tsa_retry_backoff_max_secs=3.0,
    )
)


# --------------------------------------------------------------------------- #
# request_timestamp — transport only, network stubbed with httpx.MockTransport
# --------------------------------------------------------------------------- #


def test_returns_reply_bytes_and_sends_rfc3161_headers():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"\x30\x82reply")

    reply = request_timestamp(b"\x30\x82query", CONFIG, httpx.MockTransport(handler))
    assert reply == b"\x30\x82reply"
    (request,) = seen
    assert request.method == "POST"
    assert str(request.url) == CONFIG.evidence.tsa_url
    assert request.headers["content-type"] == "application/timestamp-query"
    assert request.content == b"\x30\x82query"


@pytest.mark.parametrize(
    ("handler", "message"),
    [
        (lambda request: httpx.Response(500), "HTTP 500"),
        (lambda request: httpx.Response(200, content=b""), "empty body"),
        (lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("slow")), "ReadTimeout"),
        (lambda request: (_ for _ in ()).throw(httpx.ConnectError("dns")), "ConnectError"),
    ],
    ids=["5xx", "empty-200", "timeout", "dns-failure"],
)
def test_unusable_replies_raise_tsa_unavailable(handler, message: str):
    with pytest.raises(TsaUnavailableError, match=message):
        request_timestamp(b"q", CONFIG, httpx.MockTransport(handler))


def test_refused_connection_on_dead_local_port_raises_tsa_unavailable():
    with socket.socket() as probe:  # bind then close: nothing listens on this port
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = Config(evidence=EvidenceConfig(tsa_url=f"http://127.0.0.1:{port}/tsr"))
    with pytest.raises(TsaUnavailableError, match="unreachable"):
        request_timestamp(b"q", config)


# --------------------------------------------------------------------------- #
# retry_pending / retry_all_pending — fake timestamper, real SQLite store
# --------------------------------------------------------------------------- #


def _saved_case(tmp_path: Path, repo: SqliteCaseRepository, case_id: str) -> str:
    start = 1_700_000_000.0 + int(case_id[0], 16)  # distinct bytes -> distinct digest
    packets = [(start + i, syn_frame("10.0.0.5", "203.0.113.7", 40000 + i, 443))
               for i in range(3)]
    pcap = write_timed_pcap(tmp_path / f"{case_id}.pcap", packets)
    repo.save(analyze_pcap(case_id, str(pcap)))
    return case_id


def _unavailable(_sha256: str):
    raise TsaUnavailableError("TSA down")


@pytest.fixture
def repo(tmp_path: Path) -> SqliteCaseRepository:
    return SqliteCaseRepository(tmp_path / "nf.sqlite")


def test_retry_success_records_granted_token(tmp_path: Path, repo: SqliteCaseRepository):
    case_id = _saved_case(tmp_path, repo, "a" * 32)
    sha256 = repo.load(case_id).seal.sha256_hash
    asked: list[str] = []

    def timestamper(digest: str):
        asked.append(digest)
        return b"token", GEN_TIME

    result = retry_pending(case_id, repo, timestamper, CONFIG, sleep=lambda _: None)
    assert (result.outcome, result.attempts) == (RetryOutcome.GRANTED, 1)
    assert asked == [sha256]
    seal = repo.load(case_id).seal
    assert seal.timestamp_status is TimestampStatus.GRANTED
    assert (seal.rfc3161_token, seal.timestamp_gen_time, seal.tsa_url) == (
        b"token", GEN_TIME, CONFIG.evidence.tsa_url,
    )
    assert repo.pending_timestamp_case_ids() == ()


def test_retry_failure_leaves_pending_after_bounded_backoff(
    tmp_path: Path, repo: SqliteCaseRepository
):
    case_id = _saved_case(tmp_path, repo, "a" * 32)
    slept: list[float] = []
    result = retry_pending(case_id, repo, _unavailable, CONFIG, sleep=slept.append)
    assert (result.outcome, result.attempts, result.detail) == (
        RetryOutcome.STILL_PENDING, 3, "TSA down",
    )
    assert slept == [2.0, 3.0]  # 2s, then 4s capped at 3s; no sleep after the last try
    assert repo.load(case_id).seal.timestamp_status is TimestampStatus.PENDING


def test_retry_on_granted_seal_does_nothing(tmp_path: Path, repo: SqliteCaseRepository):
    case_id = _saved_case(tmp_path, repo, "a" * 32)
    repo.record_timestamp(case_id, b"token", GEN_TIME, "u")
    result = retry_pending(case_id, repo, _unavailable, CONFIG)
    assert result.outcome is RetryOutcome.ALREADY_GRANTED


def test_retry_all_continues_past_failing_cases(tmp_path: Path, repo: SqliteCaseRepository):
    ids = [_saved_case(tmp_path, repo, c * 32) for c in "abc"]
    broken = repo.load(ids[0]).seal.sha256_hash
    down = repo.load(ids[1]).seal.sha256_hash

    def timestamper(digest: str):
        if digest == broken:
            raise ValueError("core rejected the token")
        if digest == down:
            raise TsaUnavailableError("TSA down")
        return b"token", GEN_TIME

    results = retry_all_pending(repo, timestamper, CONFIG, sleep=lambda _: None)
    assert [r.outcome for r in results] == [
        RetryOutcome.ERROR, RetryOutcome.STILL_PENDING, RetryOutcome.GRANTED,
    ]
    assert repo.pending_timestamp_case_ids() == tuple(ids[:2])


def test_backoff_is_exponential_and_capped():
    config = dataclasses.replace(
        CONFIG,
        evidence=dataclasses.replace(
            CONFIG.evidence, tsa_retry_backoff_secs=1.0, tsa_retry_backoff_max_secs=5.0
        ),
    )
    assert [backoff_delay(config, n) for n in range(1, 6)] == [1.0, 2.0, 4.0, 5.0, 5.0]
