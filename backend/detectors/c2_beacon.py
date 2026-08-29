"""C2-beaconing detector — flags host/destination pairs whose connection timing
is too mechanically regular to be human-driven (docs/logic.md §2).

Signal: inter-arrival-time regularity, measured as coefficient of variation.
Thresholds come from `Config.c2_beacon` — never hard-coded here.
"""

from __future__ import annotations

import statistics
from collections.abc import Sequence

from backend.config import C2BeaconConfig
from backend.detectors.base import Detector
from backend.models import Finding, Flow, Severity


def _group_by_src_dst(flows: Sequence[Flow]) -> dict[tuple[str, str], list[Flow]]:
    """Bucket flows by (src_ip, dst_ip) — every connection between one host pair
    lands in the same group, regardless of destination port."""
    groups: dict[tuple[str, str], list[Flow]] = {}
    for flow in flows:
        groups.setdefault((flow.src_ip, flow.dst_ip), []).append(flow)
    return groups


def _inter_arrival_times(flows: list[Flow]) -> list[float]:
    """Gaps in seconds between consecutive connections, in chronological order.
    N flows produce N-1 gaps; 0 or 1 flow yields []."""
    timestamps = sorted(flow.start_time for flow in flows)
    return [
        (later - earlier).total_seconds()
        for earlier, later in zip(timestamps, timestamps[1:])
    ]


def _coefficient_of_variation(iats: Sequence[float]) -> float | None:
    """Ratio of sample stdev to mean — near 0 means robotically regular timing.

    None means "not computable / not meaningful": fewer than 2 gaps (sample
    stdev needs n-1 >= 1), or a zero mean (all connections at the same
    timestamp — a resolution artifact, not a real signal)."""
    if len(iats) < 2:
        return None
    mean = statistics.mean(iats)
    if mean == 0:
        return None
    return statistics.stdev(iats) / mean


class C2BeaconDetector(Detector):
    name = "c2_beacon"

    def run(self, flows: Sequence[Flow]) -> list[Finding]:
        cfg = self.config.c2_beacon
        allowlist = self.config.allowlists.beacon_dst_ips
        findings: list[Finding] = []
        for (src_ip, dst_ip), group in _group_by_src_dst(flows).items():
            if dst_ip in allowlist:
                continue
            finding = self._evaluate(src_ip, dst_ip, group, cfg)
            if finding is not None:
                findings.append(finding)
        return findings

    def _evaluate(
        self, src_ip: str, dst_ip: str, group: list[Flow], cfg: C2BeaconConfig
    ) -> Finding | None:
        """Enough connections is required before regularity means anything;
        then the timing itself must be more regular than the configured cutoff."""
        if len(group) < cfg.min_connections:
            return None
        iats = _inter_arrival_times(group)
        cv = _coefficient_of_variation(iats)
        if cv is None or cv > cfg.max_coefficient_of_variation:
            return None
        return self._build_finding(src_ip, dst_ip, group, iats, cv, cfg)

    def _build_finding(
        self,
        src_ip: str,
        dst_ip: str,
        group: list[Flow],
        iats: list[float],
        cv: float,
        cfg: C2BeaconConfig,
    ) -> Finding:
        mean = statistics.mean(iats)
        stdev = statistics.stdev(iats)
        evidence = (
            f"Host {src_ip} contacted {dst_ip} every ~{mean:.0f}s (±{stdev:.1f}s) "
            f"over {len(group)} connections (coefficient of variation {cv:.3f}, "
            f"threshold {cfg.max_coefficient_of_variation}) — robotic regularity "
            f"characteristic of C2 beaconing, not human traffic."
        )
        return Finding(
            detector=self.name,
            what=f"{src_ip} -> {dst_ip}",
            why=(
                "Connection timing is far more regular than human-driven traffic — "
                "consistent with an automated check-in/beacon."
            ),
            supporting_data={
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "connection_count": len(group),
                "mean_interval_secs": round(mean, 2),
                "stdev_interval_secs": round(stdev, 2),
                "coefficient_of_variation": round(cv, 4),
                "cv_threshold": cfg.max_coefficient_of_variation,
                "min_connections": cfg.min_connections,
            },
            evidence=evidence,
            severity=Severity.MEDIUM,
        )
