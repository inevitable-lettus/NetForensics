"""Stage 4 (minimal) — render a `CaseRecord` to a PDF. Reads only the record; it
never re-parses the pcap. The full forensic report (custody chain, verification)
lands with the evidence layer.
"""

from __future__ import annotations

import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from backend.models import CaseRecord, Finding, SealRecord, TimestampStatus

_STYLES = getSampleStyleSheet()
_MONO = ParagraphStyle("mono", parent=_STYLES["BodyText"], fontName="Courier", fontSize=8)
_CELL = ParagraphStyle("cell", parent=_STYLES["BodyText"], fontSize=9, leading=11)
_TABLE_STYLE = TableStyle(
    [
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
    ]
)


def _text(value: object, style: ParagraphStyle = _CELL) -> Paragraph:
    return Paragraph(escape(str(value)), style)


def _key_value_table(rows: list[tuple[str, object]], mono_keys: frozenset[str] = frozenset()) -> Table:
    data = [
        [_text(key), _text(value, _MONO if key in mono_keys else _CELL)] for key, value in rows
    ]
    table = Table(data, colWidths=[42 * mm, 128 * mm])
    table.setStyle(_TABLE_STYLE)
    return table


def _timestamp_line(seal: SealRecord) -> str:
    if seal.timestamp_status is TimestampStatus.GRANTED:
        return f"GRANTED by {seal.tsa_url} (TSA clock {seal.timestamp_gen_time})"
    return "PENDING — no trusted timestamp has been obtained for this evidence yet"


def _seal_section(seal: SealRecord) -> list:
    rows = [
        ("Filename", seal.pcap_filename),
        ("Size (bytes)", seal.pcap_size_bytes),
        ("BLAKE3", seal.pcap_hash),
        ("SHA-256", seal.sha256_hash),
        ("Received at (UTC)", seal.received_at.isoformat()),
        ("RFC 3161 timestamp", _timestamp_line(seal)),
    ]
    return [
        Paragraph("Evidence seal", _STYLES["Heading2"]),
        _key_value_table(rows, mono_keys=frozenset({"BLAKE3", "SHA-256"})),
    ]


def _finding_section(number: int, finding: Finding) -> list:
    title = f"{number}. [{finding.severity.value.upper()}] {finding.detector} — {finding.what}"
    measurements = [(key, value) for key, value in finding.supporting_data.items()]
    return [
        Spacer(1, 6 * mm),
        Paragraph(escape(title), _STYLES["Heading3"]),
        _key_value_table([("Evidence", finding.evidence), ("Why", finding.why)]),
        Spacer(1, 2 * mm),
        _key_value_table(measurements),
    ]


def build_case_pdf(record: CaseRecord) -> bytes:
    """Return the report for `record` as PDF bytes."""
    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=A4, title=f"NetForensics case {record.case_id}",
        leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
    )
    story: list = [
        Paragraph("NetForensics — Analysis Report", _STYLES["Title"]),
        _key_value_table([("Case ID", record.case_id), ("Flows analysed", record.flow_count)]),
        Spacer(1, 4 * mm),
        *_seal_section(record.seal),
        Spacer(1, 6 * mm),
        Paragraph(f"Findings ({len(record.findings)})", _STYLES["Heading2"]),
    ]
    if not record.findings:
        story.append(Paragraph("No detector fired on this capture.", _STYLES["BodyText"]))
    for number, finding in enumerate(record.findings, start=1):
        story.extend(_finding_section(number, finding))
    document.build(story)
    return buffer.getvalue()
