"""The shared evidence-sentence template (dev-notes question F, step 2). The detector
sentences are asserted word for word: they are what a reviewer reads."""

from __future__ import annotations

import pytest

from backend.config import CONFIG
from backend.detectors.c2_beacon import C2BeaconDetector
from backend.detectors.dns_exfil import DnsExfilDetector
from backend.detectors.evidence import Cutoff, Measurement, evidence_sentence
from backend.detectors.port_scan import PortScanDetector
from tests.fixtures.pcap_builder import dns_flow
from tests.test_c2_beacon import _flow as beacon_flow
from tests.test_port_scan import _flow as scan_flow


def test_template_order_is_subject_measurements_meaning():
    sentence = evidence_sentence(
        "Thing X",
        [Measurement("speed", 12.345, 10, Cutoff.AT_LEAST, "m/s", 1, "limit sign 10"),
         Measurement("wobble", 0.5, 0.1, Cutoff.AT_MOST)],
        "it is going too fast.",
    )
    assert sentence == ("Thing X: speed 12.3 m/s (cutoff: at least 10 m/s, met; limit sign 10); "
                        "wobble 0 (cutoff: at most 0.1, not met). Meaning: it is going too fast.")


@pytest.mark.parametrize(("value", "direction", "met"), [
    (10, Cutoff.AT_LEAST, True), (9.99, Cutoff.AT_LEAST, False),
    (10, Cutoff.AT_MOST, True), (10.01, Cutoff.AT_MOST, False),
])
def test_cutoff_is_inclusive_like_the_detectors(value, direction, met):
    assert Measurement("x", value, 10, direction).met is met


def test_evidence_needs_a_measurement():
    with pytest.raises(ValueError):
        evidence_sentence("x", [], "y")


def test_dns_sentence():
    flow = dns_flow("evil.example.com", ["a8f3k2j9d0s7f6g5h4j3k2l1m0n9b8v7c6x5z4"], 4.6, 300)
    (finding,) = DnsExfilDetector(CONFIG).run([flow])
    assert finding.evidence == (
        "DNS parent domain 'evil.example.com', longest subdomain "
        "'a8f3k2j9d0s7f6g5h4j3k2l1m0n9b8v7c6x5z4': Shannon entropy 4.60 bits/char "
        "(cutoff: at least 4.2 bits/char, met; benign baseline about 2.5); subdomain length "
        "38 chars (cutoff: at least 30 chars, met); queries per 60 s window 18000 (cutoff: at "
        "least 50, met; 300 queries in total). Meaning: the subdomains look random, and are "
        "long or frequent, as when data is smuggled out encoded in DNS queries."
    )


def test_beacon_sentence():
    offsets = [0, 60, 121, 179, 241, 301, 362, 419, 481, 541]
    (finding,) = C2BeaconDetector(CONFIG).run(
        [beacon_flow("10.0.0.5", "203.0.113.9", off) for off in offsets])
    assert finding.evidence == (
        "Host 10.0.0.5 to 203.0.113.9: connections 10 (cutoff: at least 10, met); coefficient "
        "of variation of the gaps 0.028 (cutoff: at most 0.1, met; mean gap 60.1 s, spread "
        "±1.7 s). Meaning: the connections arrive at machine-regular intervals, as an "
        "automated check-in (C2 beacon) does; people browsing are irregular."
    )


def test_port_scan_sentence_shows_which_axis_fired():
    flows = [scan_flow("10.0.0.5", "203.0.113.9", 1000 + i, i * 0.05) for i in range(105)]
    (finding,) = PortScanDetector(CONFIG).run(flows)
    assert finding.evidence == (
        "Source 10.0.0.5, busiest 10 s window: distinct destination ports 105 (cutoff: at "
        "least 100, met); distinct destination hosts 1 (cutoff: at least 10, not met). "
        "Meaning: one source tried far more ports or machines in a few seconds than normal "
        "use does, as a port scan (probing for open services) does."
    )
