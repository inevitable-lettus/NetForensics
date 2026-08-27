"""DNS-exfiltration detector — flags subdomains whose randomness, length, and
query volume look like data encoded into DNS queries rather than real hostnames.

Signals (docs/logic.md §1): entropy (required) + at least one of length/rate
corroborating. Thresholds come from `Config.dns_exfil` — never hard-coded here.
"""

from __future__ import annotations

from collections.abc import Sequence

from backend.config import DnsExfilConfig
from backend.detectors.base import Detector
from backend.models import DnsFeatures, Finding, Flow, Severity


def _is_allowlisted(domain: str, allowlist: tuple[str, ...]) -> bool:
    """True if `domain` is, or is a subdomain of, an entry in `allowlist`.

    Suffix match anchored on a dot boundary — "evilcloudfront.net" must NOT
    match allowlist entry "cloudfront.net".
    """
    domain = domain.lower().rstrip(".")
    return any(domain == entry or domain.endswith("." + entry) for entry in allowlist)


def _query_rate(dns: DnsFeatures, flow: Flow, window_secs: int) -> float:
    """Queries per `window_secs`-second window, normalized from the flow's span.

    A flow with zero/negative duration (single-packet capture, clock quirk)
    can't be divided by — treat the raw count as the rate for that instant.
    """
    duration = (flow.end_time - flow.start_time).total_seconds()
    if duration <= 0:
        return float(dns.query_count)
    return dns.query_count / duration * window_secs


def _longest_subdomain(dns: DnsFeatures) -> str:
    """The subdomain label driving `max_subdomain_length` — named in evidence."""
    return max(dns.subdomains, key=len, default="")


class DnsExfilDetector(Detector):
    name = "dns_exfil"

    def run(self, flows: Sequence[Flow]) -> list[Finding]:
        cfg = self.config.dns_exfil
        allowlist = self.config.allowlists.dns_parent_domains
        findings: list[Finding] = []
        for flow in flows:
            dns = flow.features.dns
            if dns is None:
                continue
            if _is_allowlisted(dns.parent_domain, allowlist):
                continue
            finding = self._evaluate(flow, dns, cfg)
            if finding is not None:
                findings.append(finding)
        return findings

    def _evaluate(self, flow: Flow, dns: DnsFeatures, cfg: DnsExfilConfig) -> Finding | None:
        """Entropy is required; length or rate must corroborate it (see logic.md —
        length alone false-positives on real long CDN hostnames)."""
        if dns.max_subdomain_entropy < cfg.entropy_threshold:
            return None
        rate = _query_rate(dns, flow, cfg.query_rate_window_secs)
        length_hit = dns.max_subdomain_length >= cfg.subdomain_length_threshold
        rate_hit = rate >= cfg.query_rate_threshold
        if not (length_hit or rate_hit):
            return None
        severity = Severity.HIGH if (length_hit and rate_hit) else Severity.MEDIUM
        return self._build_finding(dns, rate, severity, cfg)

    def _build_finding(
        self, dns: DnsFeatures, rate: float, severity: Severity, cfg: DnsExfilConfig
    ) -> Finding:
        longest = _longest_subdomain(dns)
        evidence = (
            f"Subdomain {longest!r} of {dns.parent_domain!r} has Shannon entropy "
            f"{dns.max_subdomain_entropy:.2f} (benign baseline ~{cfg.benign_entropy_baseline}), "
            f"length {dns.max_subdomain_length} chars, with {dns.query_count} queries "
            f"in {cfg.query_rate_window_secs}s (~{rate:.0f}/window) — consistent with data "
            f"encoded into DNS queries."
        )
        return Finding(
            detector=self.name,
            what=f"DNS parent domain {dns.parent_domain}",
            why=(
                "Subdomain randomness exceeds the benign DNS baseline, corroborated by "
                "subdomain length and/or query volume — the signature of data encoded "
                "into DNS queries."
            ),
            supporting_data={
                "parent_domain": dns.parent_domain,
                "max_subdomain_entropy": round(dns.max_subdomain_entropy, 2),
                "benign_entropy_baseline": cfg.benign_entropy_baseline,
                "entropy_threshold": cfg.entropy_threshold,
                "max_subdomain_length": dns.max_subdomain_length,
                "subdomain_length_threshold": cfg.subdomain_length_threshold,
                "query_count": dns.query_count,
                "query_rate_per_window": round(rate, 2),
                "query_rate_threshold": cfg.query_rate_threshold,
                "window_secs": cfg.query_rate_window_secs,
            },
            evidence=evidence,
            severity=severity,
        )
