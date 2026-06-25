"""Contract tests for the Detector base interface — proves the plug-in shape new
detectors must implement (Hard Rule 4), without any real detection logic yet."""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from backend.config import Config
from backend.detectors.base import Detector
from backend.models import Finding, Flow, Severity
from tests.fixtures.pcap_builder import make_flow


class _NoopDetector(Detector):
    """A trivial conforming detector used only to exercise the interface."""

    name = "noop"

    def run(self, flows: Sequence[Flow]) -> list[Finding]:
        return [
            Finding(
                detector=self.name,
                what=f"flow {f.five_tuple}",
                why="test stub",
                supporting_data={"count": f.features.packet_count},
                evidence="stub evidence",
                severity=Severity.INFO,
            )
            for f in flows
        ]


def test_base_detector_is_abstract() -> None:
    with pytest.raises(TypeError):
        Detector(Config())  # type: ignore[abstract]


def test_conforming_detector_runs(config: Config) -> None:
    detector = _NoopDetector(config)
    findings = detector.run([make_flow(), make_flow(src_ip="9.9.9.9")])
    assert len(findings) == 2
    assert all(f.detector == "noop" for f in findings)


def test_detector_reads_thresholds_from_config() -> None:
    custom = Config()
    detector = _NoopDetector(custom)
    # Detectors must source thresholds from config, never hard-code them.
    assert detector.config.dns_exfil.entropy_threshold == 4.2
