"""Pipeline orchestrator — drives one pcap through Stage 1 (seal), Stage 2 (parse)
and Stage 3 (detect). Data flows one way; no stage reaches backwards. No HTTP and
no persistence here — callers (API, CLI) own those.
"""

from __future__ import annotations

from backend.config import CONFIG, Config
from backend.detectors.c2_beacon import C2BeaconDetector
from backend.detectors.dns_exfil import DnsExfilDetector
from backend.detectors.port_scan import PortScanDetector
from backend.evidence.seal import seal_pcap
from backend.models import CaseRecord, Finding, Flow, Severity
from backend.parse.dns_parser import parse_dns_flows
from backend.parse.flow_parser import parse_flows

_SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}


def _run_detectors(config: Config, dns_flows: list[Flow], flows: list[Flow]) -> list[Finding]:
    """DNS-exfil consumes the DNS aggregates; the connection-level detectors consume
    generic flows. Each detector still only sees the shape it was written for."""
    findings = DnsExfilDetector(config).run(dns_flows)
    for detector in (C2BeaconDetector(config), PortScanDetector(config)):
        findings.extend(detector.run(flows))
    return sorted(findings, key=lambda finding: _SEVERITY_ORDER[finding.severity])


def analyze_pcap(case_id: str, pcap_path: str, config: Config = CONFIG) -> CaseRecord:
    """Seal first — before any analysis touches the evidence — then parse and detect."""
    seal = seal_pcap(pcap_path)
    dns_flows = parse_dns_flows(pcap_path)
    flows = parse_flows(pcap_path)
    findings = _run_detectors(config, dns_flows, flows)
    return CaseRecord(
        case_id=case_id, seal=seal, findings=tuple(findings), flow_count=len(flows)
    )
