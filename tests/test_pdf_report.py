from __future__ import annotations

from datetime import datetime, timezone

from backend.models import CaseRecord, Finding, SealRecord, Severity
from backend.report.pdf import build_case_pdf


def _seal() -> SealRecord:
    return SealRecord(
        pcap_filename="a<b>.pcap", pcap_size_bytes=10, hash_algorithm="blake3",
        pcap_hash="ab" * 32, sha256_hash="cd" * 32,
        received_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def test_pdf_is_valid_with_findings_and_markup_chars_escaped():
    finding = Finding(
        detector="c2_beacon", what="a -> b", why="regular <timing> & such",
        supporting_data={"cv": 0.03}, evidence="Host a contacted b every ~60s",
        severity=Severity.MEDIUM,
    )
    pdf = build_case_pdf(CaseRecord("a" * 32, _seal(), (finding,), 5))
    assert pdf.startswith(b"%PDF")


def test_pdf_builds_for_zero_findings():
    assert build_case_pdf(CaseRecord("a" * 32, _seal(), (), 0)).startswith(b"%PDF")
