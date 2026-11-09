from __future__ import annotations

import io
import re
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from backend.cli import EXIT_CODES_HELP, EXIT_ERROR, EXIT_OK, EXIT_PENDING, main
from backend.config import CONFIG
from backend.db.anchor_log import SqliteAnchorLog
from backend.db.case_repository import SqliteCaseRepository
from backend.db.custody_log import SqliteCustodyLog
from backend.evidence.tsa_client import TsaUnavailableError
from backend.models import TimestampStatus
from tests.fixtures.packets import syn_frame, write_timed_pcap

GEN_TIME = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)


def _beacon_pcap(tmp_path: Path) -> Path:
    packets = [
        (1_700_000_000.0 + i * 60, syn_frame("10.0.0.5", "203.0.113.7", 40000 + i, 443))
        for i in range(12)
    ]
    return write_timed_pcap(tmp_path / "beacon.pcap", packets)


def _run(store: Path, *argv: str, **kwargs) -> tuple[int, str]:
    out = io.StringIO()
    code = main(["--store", str(store), *argv], out=out, **kwargs)
    return code, out.getvalue()


def _case_id(output: str) -> str:
    return re.search(r"^Case\s+([0-9a-f]{32})$", output, re.M).group(1)


def _cases(store: Path) -> SqliteCaseRepository:
    return SqliteCaseRepository(store / "netforensics.sqlite")


def test_seal_prints_case_and_both_digests_and_stores_the_blob(tmp_path: Path):
    store = tmp_path / "store"
    code, output = _run(store, "seal", str(_beacon_pcap(tmp_path)))
    assert code == EXIT_OK
    sha256 = re.search(r"^SHA-256\s+([0-9a-f]{64})$", output, re.M).group(1)
    assert re.search(r"^BLAKE3\s+[0-9a-f]{64}$", output, re.M)
    assert "Timestamp  PENDING" in output
    assert (store / "blobs" / sha256).is_file()
    assert _cases(store).load(_case_id(output)).seal.sha256_hash == sha256


def test_seal_never_modifies_the_source_pcap(tmp_path: Path):
    pcap = _beacon_pcap(tmp_path)
    before = pcap.read_bytes()
    _run(tmp_path / "store", "seal", str(pcap))
    assert pcap.read_bytes() == before


def test_analyze_prints_each_finding_with_its_evidence(tmp_path: Path):
    code, output = _run(tmp_path / "store", "analyze", str(_beacon_pcap(tmp_path)))
    assert code == EXIT_OK
    assert "Findings   1" in output
    assert "[MEDIUM] c2_beacon: 10.0.0.5 -> 203.0.113.7" in output
    assert re.search(r"^  Evidence  .+", output, re.M)


def test_missing_file_is_one_clear_line_and_exit_1(tmp_path: Path, capsys):
    code, output = _run(tmp_path / "store", "seal", str(tmp_path / "nope.pcap"))
    assert code == EXIT_ERROR and output == ""
    assert capsys.readouterr().err == f"error: {tmp_path / 'nope.pcap'} is not a file.\n"


def test_non_pcap_is_refused_and_leaves_no_case_behind(tmp_path: Path, capsys):
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"definitely not a pcap file at all")
    store = tmp_path / "store"
    code, _ = _run(store, "analyze", str(junk))
    err = capsys.readouterr().err
    assert code == EXIT_ERROR and err.startswith("error: ") and err.count("\n") == 1
    assert not any((store / "staging").iterdir())
    assert _cases(store).pending_timestamp_case_ids() == ()


def test_oversize_pcap_is_refused(tmp_path: Path, capsys):
    tiny = replace(CONFIG, ingest=replace(CONFIG.ingest, max_upload_bytes=10))
    code, _ = _run(tmp_path / "store", "seal", str(_beacon_pcap(tmp_path)), config=tiny)
    assert code == EXIT_ERROR and "10-byte limit" in capsys.readouterr().err


def test_seal_makes_one_timestamp_attempt_when_a_timestamper_is_wired(tmp_path: Path):
    code, output = _run(tmp_path / "store", "seal", str(_beacon_pcap(tmp_path)),
                        timestamper=lambda _sha256: (b"token", GEN_TIME))
    assert code == EXIT_OK
    assert "Timestamp  GRANTED by https://freetsa.org/tsr at 2026-10-20T09:00:00+00:00" in output


def test_retry_without_a_timestamper_reports_pending_and_fakes_nothing(tmp_path: Path):
    store = tmp_path / "store"
    assert _run(store, "retry-timestamps")[0] == EXIT_OK
    _run(store, "seal", str(_beacon_pcap(tmp_path)))
    code, output = _run(store, "retry-timestamps")
    assert code == EXIT_PENDING
    assert output.startswith("1 case(s) PENDING. No TSA in use (offline)")
    assert len(_cases(store).pending_timestamp_case_ids()) == 1


def test_retry_grants_pending_seals(tmp_path: Path):
    store = tmp_path / "store"
    case_id = _case_id(_run(store, "seal", str(_beacon_pcap(tmp_path)))[1])
    code, output = _run(store, "retry-timestamps", timestamper=lambda _s: (b"token", GEN_TIME))
    assert code == EXIT_OK
    assert f"{case_id}  GRANTED" in output and "1 granted, 0 still pending" in output
    assert _cases(store).load(case_id).seal.timestamp_status is TimestampStatus.GRANTED


def test_retry_with_tsa_down_exits_2_and_keeps_seal_pending(tmp_path: Path):
    store = tmp_path / "store"
    case_id = _case_id(_run(store, "seal", str(_beacon_pcap(tmp_path)))[1])

    def unavailable(_sha256: str):
        raise TsaUnavailableError("TSA offline")

    one_try = replace(CONFIG, evidence=replace(CONFIG.evidence, tsa_retry_attempts=1))
    code, output = _run(store, "retry-timestamps", config=one_try, timestamper=unavailable)
    assert code == EXIT_PENDING
    assert f"{case_id}  STILL_PENDING" in output and "TSA offline" in output


def test_unknown_command_is_a_usage_error(tmp_path: Path):
    with pytest.raises(SystemExit) as exit_info:
        _run(tmp_path / "store", "frobnicate")
    assert exit_info.value.code == 2


def test_runs_as_a_module(tmp_path: Path):
    result = subprocess.run(
        [sys.executable, "-m", "backend.cli", "--store", str(tmp_path / "s"), "--offline",
         "seal", str(_beacon_pcap(tmp_path))],
        capture_output=True, text=True, cwd=Path(__file__).resolve().parents[1], check=False,
    )
    assert result.returncode == 0, result.stderr
    assert re.search(r"^SHA-256\s+[0-9a-f]{64}$", result.stdout, re.M)



def test_help_lists_every_exit_code(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--help"])
    assert exit_info.value.code == 0
    help_text = capsys.readouterr().out
    assert EXIT_CODES_HELP in help_text
    for code in (EXIT_OK, EXIT_ERROR, EXIT_PENDING):
        assert f"\n  {code}  " in help_text


def test_corrupt_database_is_one_clear_line_and_exit_1(tmp_path: Path, capsys):
    store = tmp_path / "store"
    store.mkdir()
    (store / "netforensics.sqlite").write_bytes(b"this is not a sqlite database" * 100)
    code, _ = _run(store, "retry-timestamps")
    err = capsys.readouterr().err
    assert code == EXIT_ERROR and err.startswith("error: ") and err.count("\n") == 1


# --------------------------------------------------------------------------- #
# verify / tamper-demo (#4, on top of #12)
# --------------------------------------------------------------------------- #

FAKE_TSA = {"timestamper": lambda _sha256: (b"token", GEN_TIME),
            "verify_token": lambda _token, _sha256: GEN_TIME}


def _sealed(tmp_path: Path, **tsa) -> tuple[Path, str]:
    store = tmp_path / "store"
    return store, _case_id(_run(store, "seal", str(_beacon_pcap(tmp_path)), **tsa)[1])


def _flip_stored_byte(store: Path, case_id: str) -> None:
    blob = store / "blobs" / _cases(store).load(case_id).seal.sha256_hash
    blob.chmod(0o644)
    data = bytearray(blob.read_bytes())
    data[40] ^= 0x01
    blob.write_bytes(bytes(data))


def test_seal_opens_an_anchored_custody_chain(tmp_path: Path):
    store, case_id = _sealed(tmp_path)
    entries = SqliteCustodyLog(store / "netforensics.sqlite").entries(case_id)
    assert [e.event_type for e in entries] == ["ingest", "analyze", "anchor"]
    anchors = SqliteAnchorLog(store / "netforensics.sqlite").anchors(case_id)
    assert [(a.head_index, a.timestamp_status) for a in anchors] == [(1, TimestampStatus.PENDING)]


def test_verify_untouched_case_with_a_tsa_exits_0(tmp_path: Path):
    store, case_id = _sealed(tmp_path, **FAKE_TSA)
    code, output = _run(store, "verify", case_id, **FAKE_TSA)
    assert code == EXIT_OK, output
    assert "Verdict    INTACT" in output and "[PASS] pcap_digests" in output
    assert re.search(r"^Anchor     entry 3, hash [0-9a-f]{64} \(GRANTED\)", output, re.M)


def test_verify_offline_case_is_incomplete_exit_2(tmp_path: Path):
    store, case_id = _sealed(tmp_path)
    code, output = _run(store, "verify", case_id)
    assert code == EXIT_PENDING
    assert "[NOT RUN] rfc3161_timestamp" in output and "Verdict    INCOMPLETE" in output


def test_verify_after_a_byte_flip_exits_1_with_sealed_vs_measured(tmp_path: Path):
    store, case_id = _sealed(tmp_path, **FAKE_TSA)
    sealed = _cases(store).load(case_id).seal.pcap_hash
    _flip_stored_byte(store, case_id)
    code, output = _run(store, "verify", case_id, **FAKE_TSA)
    assert code == EXIT_ERROR
    assert f"[FAIL] pcap_digests: The stored evidence no longer matches its seal: BLAKE3 sealed {sealed}, measured" in output
    assert "Verdict    ALTERED" in output


def test_verify_with_the_blob_gone_is_altered_not_a_crash(tmp_path: Path):
    store, case_id = _sealed(tmp_path)
    (store / "blobs" / _cases(store).load(case_id).seal.sha256_hash).unlink()
    code, output = _run(store, "verify", case_id)
    assert code == EXIT_ERROR and "is missing" in output


def test_verify_records_itself_and_reanchors(tmp_path: Path):
    store, case_id = _sealed(tmp_path)
    _run(store, "verify", case_id)
    entries = SqliteCustodyLog(store / "netforensics.sqlite").entries(case_id)
    assert [e.event_type for e in entries][3:] == ["verify", "anchor"]
    assert entries[3].payload["verdict"] == "incomplete"
    assert len(SqliteAnchorLog(store / "netforensics.sqlite").anchors(case_id)) == 2


@pytest.mark.parametrize("case_id", ["0" * 32, "../etc"])
def test_verify_unknown_case_is_one_error_line(tmp_path: Path, case_id: str, capsys):
    code, _ = _run(tmp_path / "store", "verify", case_id)
    err = capsys.readouterr().err
    assert code == EXIT_ERROR and err.startswith("error: ") and err.count("\n") == 1


def test_tamper_demo_catches_the_flip_offline_and_leaves_the_source_alone(tmp_path: Path):
    pcap = _beacon_pcap(tmp_path)
    before = pcap.read_bytes()
    code, output = _run(tmp_path / "unused", "--offline", "tamper-demo", str(pcap))
    assert code == EXIT_OK, output
    assert pcap.read_bytes() == before
    assert re.search(r"^verdict\s+INCOMPLETE\s+ALTERED$", output, re.M)
    assert re.search(r"^pcap_digests\s+PASS\s+FAIL$", output, re.M)
    assert "BLAKE3 sealed" in output and ", measured " in output
    scratch = re.search(r"^Throwaway store (\S+)", output, re.M).group(1)
    assert not Path(scratch).exists()
    assert not (tmp_path / "unused").exists()


def test_tamper_demo_with_a_tsa_goes_from_intact_to_altered(tmp_path: Path):
    code, output = _run(tmp_path / "unused", "tamper-demo", str(_beacon_pcap(tmp_path)), **FAKE_TSA)
    assert code == EXIT_OK
    assert re.search(r"^verdict\s+INTACT\s+ALTERED$", output, re.M)
