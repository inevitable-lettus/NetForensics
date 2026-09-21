from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.config import Config, IngestConfig
from backend.db.case_store import CaseStore
from tests.fixtures.packets import syn_frame, write_timed_pcap


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(CaseStore(tmp_path / "cases")))


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
    assert not any((tmp_path / "cases").iterdir())


def test_oversize_upload_is_413(tmp_path: Path):
    config = Config(ingest=IngestConfig(max_upload_bytes=8))
    app = create_app(CaseStore(tmp_path / "cases"), config)
    response = _upload(TestClient(app), "x.pcap", b"x" * 100)
    assert response.status_code == 413


def test_unknown_and_malformed_case_ids_are_404(client: TestClient):
    assert client.get(f"/api/cases/{'0' * 32}").status_code == 404
    assert client.get("/api/cases/not-a-valid-id").status_code == 404
    assert client.get(f"/api/cases/{'0' * 32}/report.pdf").status_code == 404
