from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.config import Config, EvidenceConfig, IngestConfig
from backend.db.storage import Storage
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
