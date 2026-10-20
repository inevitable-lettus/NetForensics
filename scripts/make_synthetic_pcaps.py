"""Generate small deterministic synthetic captures, one per detector plus a benign
baseline, into sample-pcaps/. Licence-free (we author them), seeded, a few KB each.

Reuses the frame/pcap writers from tests/fixtures so there is one pcap writer in the
repo. Run from the repo root:  python scripts/make_synthetic_pcaps.py
"""

from __future__ import annotations

import random
import string
import sys
from pathlib import Path

import dpkt

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.fixtures.packets import syn_frame, udp_frame, write_timed_pcap  # noqa: E402

OUT_DIR = ROOT / "sample-pcaps"
START = 1_700_000_000.0  # fixed epoch so output bytes (and the seal hash) are stable
CLIENT, RESOLVER = "10.0.0.5", "10.0.0.2"


def _dns_query(qname: str) -> bytes:
    dns = dpkt.dns.DNS(op=dpkt.dns.DNS_QUERY, rd=1)
    dns.qd = [dpkt.dns.DNS.Q(name=qname, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN)]
    return udp_frame(CLIENT, RESOLVER, 40000, 53, bytes(dns))


def benign(rng: random.Random) -> list[tuple[float, bytes]]:
    """Ordinary lookups + irregular web connections: no detector should fire."""
    names = ["www.example.com", "mail.example.com", "cdn.example.org", "api.example.net"]
    packets = [(START + i * rng.uniform(5, 40), _dns_query(rng.choice(names))) for i in range(30)]
    clock = START
    for _ in range(25):
        clock += rng.uniform(1, 90)  # human-irregular gaps -> high CV
        packets.append((clock, syn_frame(CLIENT, "93.184.216.34", rng.randint(49152, 65000), 443)))
    return sorted(packets)


def dns_exfil(rng: random.Random) -> list[tuple[float, bytes]]:
    """120 queries in 60s to one parent, 40-char random-looking subdomains."""
    alphabet = string.ascii_lowercase + string.digits
    packets = []
    for i in range(120):
        label = "".join(rng.choice(alphabet) for _ in range(40))
        packets.append((START + i * 0.5, _dns_query(f"{label}.exfil.example")))
    return packets


def c2_beacon(rng: random.Random) -> list[tuple[float, bytes]]:
    """20 connections to one host every 60s with ~1s jitter (CV well under 0.1)."""
    return [
        (START + i * 60 + rng.uniform(-1, 1), syn_frame(CLIENT, "198.51.100.7", 50000 + i, 8443))
        for i in range(20)
    ]


def port_scan(rng: random.Random) -> list[tuple[float, bytes]]:
    """One source probes 200 distinct ports on one host within ~5 seconds. Probe gaps are
    jittered: a metronome-even scan also trips the C2 beacon detector (handoff risk #8)."""
    ports = rng.sample(range(1, 1025), 200)
    clock, packets = START, []
    for port in ports:
        clock += rng.uniform(0.001, 0.05)
        packets.append((clock, syn_frame(CLIENT, "10.0.0.9", 51000, port)))
    return packets


GENERATORS = {
    "synthetic-benign.pcap": benign,
    "synthetic-dns-exfil.pcap": dns_exfil,
    "synthetic-c2-beacon.pcap": c2_beacon,
    "synthetic-port-scan.pcap": port_scan,
}


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)
    for name, build in GENERATORS.items():
        path = write_timed_pcap(OUT_DIR / name, build(random.Random(name)))
        print(f"wrote {path.relative_to(ROOT)} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
