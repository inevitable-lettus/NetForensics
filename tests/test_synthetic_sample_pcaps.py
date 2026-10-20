"""The synthetic sample captures must keep firing exactly the detector they are named for."""

from __future__ import annotations

import importlib.util
import random
from pathlib import Path

import pytest

from backend.pipeline import analyze_pcap
from tests.fixtures.packets import write_timed_pcap

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "make_synthetic_pcaps.py"
_spec = importlib.util.spec_from_file_location("make_synthetic_pcaps", _SCRIPT)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)

EXPECTED = {
    "synthetic-benign.pcap": set(),
    "synthetic-dns-exfil.pcap": {"dns_exfil"},
    "synthetic-c2-beacon.pcap": {"c2_beacon"},
    "synthetic-port-scan.pcap": {"port_scan"},
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_synthetic_capture_fires_only_its_detector(name: str, tmp_path: Path):
    build = _module.GENERATORS[name]
    pcap = write_timed_pcap(tmp_path / name, build(random.Random(name)))

    record = analyze_pcap("a" * 32, str(pcap))

    assert {finding.detector for finding in record.findings} == EXPECTED[name]
