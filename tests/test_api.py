from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.config import Config, EvidenceConfig, IngestConfig
from backend.db.storage import Storage
from backend.evidence.tsa_client import TsaUnavailableError
from tests.fixtures.packets import syn_frame, write_timed_pcap


def _storage(root: Path) -> Storage:
    return Storage.open(
        EvidenceConfig(evidence_store_dir=str(root), db_path=str(root / "nf.sqlite"))
    )


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(_storage(tmp_path / "store")))


def _beacon_pcap_bytes(tmp_path: Path) -> bytes:
    packets = [
        (1_700_000_000.0 + i * 60, syn_frame("10.0.0.5", "203.0.113.7", 40000 + i, 443))
        for i in range(12)
    ]
    return write_timed_pcap(tmp_path / "beacon.pcap", packets).read_bytes()


def _upload(client: TestClient, name: str, data: bytes):
    return client.post("/api/cases", files={"file": (name, data, "application/octet-stream")})


def test_upload_returns_sealed_case_with_findings(client: TestClient, tmp_path: Path):
    response = _upload(client, "beacon.pcap", _beacon_pcap_bytes(tmp_path))
    assert response.status_code == 201
    body = response.json()
    assert body["seal"]["timestamp_status"] == "pending"
    assert body["seal"]["pcap_filename"] == "beacon.pcap"
    assert [f["detector"] for f in body["findings"]] == ["c2_beacon"]


def test_case_can_be_fetched_again_and_pdf_downloaded(client: TestClient, tmp_path: Path):
    case_id = _upload(client, "beacon.pcap", _beacon_pcap_bytes(tmp_path)).json()["case_id"]
    assert client.get(f"/api/cases/{case_id}").json()["case_id"] == case_id
    pdf = client.get(f"/api/cases/{case_id}/report.pdf")
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF")


def test_garbage_upload_is_400_and_leaves_no_case_behind(client: TestClient, tmp_path: Path):
    response = _upload(client, "x.pcap", b"definitely not a pcap file at all")
    assert response.status_code == 400
    staging = tmp_path / "store" / "staging"
    assert not staging.exists() or not any(staging.iterdir())
    assert not (tmp_path / "store" / "blobs").exists()


def test_oversize_upload_is_413(tmp_path: Path):
    config = Config(ingest=IngestConfig(max_upload_bytes=8))
    app = create_app(_storage(tmp_path / "store"), config)
    response = _upload(TestClient(app), "x.pcap", b"x" * 100)
    assert response.status_code == 413


def test_unknown_and_malformed_case_ids_are_404(client: TestClient):
    assert client.get(f"/api/cases/{'0' * 32}").status_code == 404
    assert client.get("/api/cases/not-a-valid-id").status_code == 404
    assert client.get(f"/api/cases/{'0' * 32}/report.pdf").status_code == 404


def test_upload_commits_pcap_to_its_content_address(client: TestClient, tmp_path: Path):
    data = _beacon_pcap_bytes(tmp_path)
    digest = _upload(client, "beacon.pcap", data).json()["seal"]["sha256_hash"]
    stored = tmp_path / "store" / "blobs" / digest
    assert stored.read_bytes() == data
    assert not any((tmp_path / "store" / "staging").iterdir())


def test_unknown_or_malformed_case_id_is_404(client: TestClient):
    assert client.get(f"/api/cases/{'b' * 32}").status_code == 404
    assert client.get("/api/cases/..%2Fetc").status_code == 404


def test_dot_dot_filename_is_accepted_safely(client: TestClient, tmp_path: Path):
    response = _upload(client, "..", _beacon_pcap_bytes(tmp_path))
    assert response.status_code == 201
    assert response.json()["seal"]["pcap_filename"] == "upload.pcap"
    assert not any((tmp_path / "store" / "staging").iterdir())


def test_reupload_over_corrupt_stored_blob_is_409(client: TestClient, tmp_path: Path):
    data = _beacon_pcap_bytes(tmp_path)
    digest = _upload(client, "beacon.pcap", data).json()["seal"]["sha256_hash"]
    blob = tmp_path / "store" / "blobs" / digest
    blob.chmod(0o644)
    blob.write_bytes(data[:-1] + bytes([data[-1] ^ 0xFF]))  # flip the last byte
    response = _upload(client, "beacon.pcap", data)
    assert response.status_code == 409
    assert "altered" in response.json()["detail"]
def _client_with_timestamper(tmp_path: Path, timestamper) -> TestClient:
    return TestClient(create_app(_storage(tmp_path / "store"), timestamper=timestamper))


def test_tsa_unavailable_at_ingest_still_stores_pending_case(tmp_path: Path):
    def unavailable(_sha256: str):
        raise TsaUnavailableError("network off")

    client = _client_with_timestamper(tmp_path, unavailable)
    response = _upload(client, "beacon.pcap", _beacon_pcap_bytes(tmp_path))
    assert response.status_code == 201
    assert response.json()["seal"]["timestamp_status"] == "pending"


def test_unexpected_timestamper_error_never_fails_the_upload(tmp_path: Path):
    def broken(_sha256: str):
        raise ValueError("bad token")

    client = _client_with_timestamper(tmp_path, broken)
    response = _upload(client, "beacon.pcap", _beacon_pcap_bytes(tmp_path))
    assert response.status_code == 201
    assert response.json()["seal"]["timestamp_status"] == "pending"


def test_tsa_reply_at_ingest_grants_the_seal(tmp_path: Path):
    gen_time = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
    client = _client_with_timestamper(tmp_path, lambda _sha256: (b"token", gen_time))
    seal = _upload(client, "beacon.pcap", _beacon_pcap_bytes(tmp_path)).json()["seal"]
    assert seal["timestamp_status"] == "granted"
    assert seal["timestamp_gen_time"] == gen_time.isoformat()


# --------------------------------------------------------------------------- #
# Verify and tamper test (#5)
# --------------------------------------------------------------------------- #

GEN = datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc)


def _granting_client(tmp_path: Path) -> tuple[TestClient, Storage]:
    """A fake TSA that grants everything, and a verifier that accepts its tokens."""
    storage = _storage(tmp_path / "store")
    app = create_app(storage, timestamper=lambda _sha: (b"token", GEN),
                     verify_token=lambda _token, _sha: GEN)
    return TestClient(app), storage


def _case(client: TestClient, tmp_path: Path) -> str:
    return _upload(client, "beacon.pcap", _beacon_pcap_bytes(tmp_path)).json()["case_id"]


def test_verify_returns_every_check_and_records_one_entry_plus_anchor(tmp_path: Path):
    client, storage = _granting_client(tmp_path)
    case_id = _case(client, tmp_path)
    before = len(storage.custody.entries(case_id))
    body = client.post(f"/api/cases/{case_id}/verify").json()
    assert body["verdict"] == "intact"
    assert [c["name"] for c in body["checks"]] == [
        "pcap_digests", "custody_chain", "seal_binding", "rfc3161_timestamp", "chain_head_anchor"]
    assert all(c["passed"] is True and c["evidence"] for c in body["checks"])
    assert body["recorded"] is True
    assert body["anchor"]["head_index"] == before and body["anchor"]["timestamp_status"] == "granted"
    events = [e.event_type for e in storage.custody.entries(case_id)][before:]
    assert events == ["verify", "anchor"]


def test_verify_with_pending_timestamps_is_incomplete_not_intact(client: TestClient, tmp_path: Path):
    body = client.post(f"/api/cases/{_case(client, tmp_path)}/verify").json()
    assert body["verdict"] == "incomplete"
    stamp = next(c for c in body["checks"] if c["name"] == "rfc3161_timestamp")
    assert stamp["passed"] is None


@pytest.mark.parametrize("path", ["verify", "tamper-test"])
@pytest.mark.parametrize("case_id", ["0" * 32, "not-a-case"])
def test_verify_and_tamper_test_of_unknown_case_are_404(client: TestClient, path, case_id):
    assert client.post(f"/api/cases/{case_id}/{path}").status_code == 404


def test_altered_case_is_reported_and_left_as_found(tmp_path: Path):
    client, storage = _granting_client(tmp_path)
    case_id = _case(client, tmp_path)
    blob = storage.evidence.path_for(storage.cases.load(case_id).seal.sha256_hash)
    blob.chmod(0o644)
    blob.write_bytes(blob.read_bytes() + b"\x00")
    entries = len(storage.custody.entries(case_id))
    body = client.post(f"/api/cases/{case_id}/verify").json()
    assert body["verdict"] == "altered" and body["recorded"] is False and body["anchor"] is None
    digests = next(c for c in body["checks"] if c["name"] == "pcap_digests")
    assert digests["passed"] is False and "sealed" in digests["evidence"]
    assert len(storage.custody.entries(case_id)) == entries


def test_tamper_test_flips_a_copy_and_never_touches_the_case(tmp_path: Path):
    client, storage = _granting_client(tmp_path)
    case_id = _case(client, tmp_path)
    blob = storage.evidence.path_for(storage.cases.load(case_id).seal.sha256_hash)
    stored, entries = blob.read_bytes(), storage.custody.entries(case_id)
    body = client.post(f"/api/cases/{case_id}/tamper-test").json()
    assert body["before"]["verdict"] == "intact" and body["after"]["verdict"] == "altered"
    assert body["flipped_offset"] == len(stored) // 2
    failed = [c["name"] for c in body["after"]["checks"] if c["passed"] is False]
    assert failed == ["pcap_digests"]
    assert blob.read_bytes() == stored and storage.custody.entries(case_id) == entries
    assert client.post(f"/api/cases/{case_id}/verify").json()["verdict"] == "intact"


def test_tamper_test_with_the_stored_file_gone_is_409(tmp_path: Path):
    client, storage = _granting_client(tmp_path)
    case_id = _case(client, tmp_path)
    storage.evidence.path_for(storage.cases.load(case_id).seal.sha256_hash).unlink()
    assert client.post(f"/api/cases/{case_id}/tamper-test").status_code == 409
