"""Port-scan / reconnaissance detector — flags a source whose connections fan
out across an implausible number of distinct ports or hosts within a short
time window (docs/logic.md §3).

Signal: fan-out count (distinct dst_port / distinct dst_ip) inside a sliding
window. Thresholds come from `Config.port_scan` — never hard-coded here.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from backend.config import PortScanConfig
from backend.detectors.base import Detector
from backend.models import Finding, Flow, Severity


def _group_by_src(flows: Sequence[Flow]) -> dict[str, list[Flow]]:
    """Bucket flows by src_ip only — a scan is defined by one source fanning
    out across many destinations, so destination is never part of the key."""
    groups: dict[str, list[Flow]] = {}
    for flow in flows:
        groups.setdefault(flow.src_ip, []).append(flow)
    return groups


def _max_fanout_in_window(flows: list[Flow], window_secs: int) -> tuple[int, int]:
    """Peak distinct dst_port / dst_ip count seen in any window_secs-wide
    sliding window over this source's flows. Two-pointer scan, O(n): each
    flow enters the window once (right pointer) and leaves at most once
    (left pointer), so total work is linear in the number of flows.

    Returns two independent maxima — port fan-out and host fan-out can peak
    at different moments in the trace (vertical vs. horizontal scan shapes),
    so tracking the max of a combined state would miss a pure case of either.
    """
    ordered = sorted(flows, key=lambda f: f.start_time)
    port_counts: Counter[int] = Counter()
    host_counts: Counter[str] = Counter()
    max_ports = 0
    max_hosts = 0
    left = 0
    for flow in ordered:
        port_counts[flow.dst_port] += 1
        host_counts[flow.dst_ip] += 1
        while (flow.start_time - ordered[left].start_time).total_seconds() > window_secs:
            expiring = ordered[left]
            port_counts[expiring.dst_port] -= 1
            if port_counts[expiring.dst_port] == 0:
                del port_counts[expiring.dst_port]
            host_counts[expiring.dst_ip] -= 1
            if host_counts[expiring.dst_ip] == 0:
                del host_counts[expiring.dst_ip]
            left += 1
        max_ports = max(max_ports, len(port_counts))
        max_hosts = max(max_hosts, len(host_counts))
    return max_ports, max_hosts


class PortScanDetector(Detector):
    name = "port_scan"

    def run(self, flows: Sequence[Flow]) -> list[Finding]:
        cfg = self.config.port_scan
        findings: list[Finding] = []
        for src_ip, group in _group_by_src(flows).items():
            finding = self._evaluate(src_ip, group, cfg)
            if finding is not None:
                findings.append(finding)
        return findings

    def _evaluate(
        self, src_ip: str, group: list[Flow], cfg: PortScanConfig
    ) -> Finding | None:
        """Either axis alone is enough to fire — a vertical scan won't touch
        many hosts, a horizontal scan won't touch many ports. Both axes
        exceeding their threshold corroborates the finding to HIGH."""
        max_ports, max_hosts = _max_fanout_in_window(group, cfg.window_secs)
        ports_hit = max_ports >= cfg.distinct_ports_threshold
        hosts_hit = max_hosts >= cfg.distinct_hosts_threshold
        if not (ports_hit or hosts_hit):
            return None
        severity = Severity.HIGH if (ports_hit and hosts_hit) else Severity.MEDIUM
        return self._build_finding(src_ip, group, max_ports, max_hosts, severity, cfg)

    def _build_finding(
        self,
        src_ip: str,
        group: list[Flow],
        max_ports: int,
        max_hosts: int,
        severity: Severity,
        cfg: PortScanConfig,
    ) -> Finding:
        evidence = (
            f"Source {src_ip} reached {max_ports} distinct destination ports "
            f"(threshold {cfg.distinct_ports_threshold}) and {max_hosts} distinct "
            f"destination hosts (threshold {cfg.distinct_hosts_threshold}) within a "
            f"{cfg.window_secs}s window — fan-out consistent with port-scan "
            f"reconnaissance."
        )
        return Finding(
            detector=self.name,
            what=f"Source {src_ip}",
            why=(
                "Connections fan out across far more distinct ports and/or hosts "
                "than normal use produces in this short a window — the signature "
                "of active reconnaissance."
            ),
            supporting_data={
                "src_ip": src_ip,
                "connection_count": len(group),
                "max_distinct_ports": max_ports,
                "distinct_ports_threshold": cfg.distinct_ports_threshold,
                "max_distinct_hosts": max_hosts,
                "distinct_hosts_threshold": cfg.distinct_hosts_threshold,
                "window_secs": cfg.window_secs,
            },
            evidence=evidence,
            severity=severity,
        )
