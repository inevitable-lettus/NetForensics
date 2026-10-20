"""Download the third-party sample captures listed in sample-pcaps/README.md into
sample-pcaps/ and verify each against a pinned SHA-256. Nothing third-party is
committed to the repo; this is how a fresh clone gets them.

Run from the repo root:  python scripts/fetch_sample_pcaps.py [name ...]
With no names, fetches every entry. Existing files with a matching hash are skipped.
"""

from __future__ import annotations

import hashlib
import http.client
import ssl
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent / "sample-pcaps"
CTU = "https://mcfp.felk.cvut.cz/publicDatasets"
DMACHARD = (
    "https://raw.githubusercontent.com/dmachard/datasets-malicious-dns/"
    "b8f90debd5d5eb7d75900bb59274b2040574de2d"
)


MAX_DOWNLOAD_BYTES = 16 * 1024 * 1024  # largest listed sample is ~10 MB


@dataclass(frozen=True)
class Sample:
    name: str
    url: str
    sha256: str
    # mcfp.felk.cvut.cz serves an incomplete certificate chain (missing intermediate),
    # so default verification fails there. The pinned SHA-256 is what authenticates
    # the bytes for those entries.
    verify_tls: bool = True


SAMPLES = (
    Sample("ctu-130-1-beacon.pcap",
           f"{CTU}/CTU-Malware-Capture-Botnet-130-1/2015-07-25_capture-win4.pcap",
           "e3939996ef1a7ee73d76447da8060d04c68b2f093f21b329dc510c009de739c6", False),
    Sample("ctu-120-1-hostscan.pcap",
           f"{CTU}/CTU-Malware-Capture-Botnet-120-1/2015-04-22_capture-win4.pcap",
           "f4ef1271ff201a7e8818b5870b775594622de2d71de9aacd9ac1b673eafaa94b", False),
    Sample("ctu-185-1-ssdp-falsepositive.pcap",
           f"{CTU}/CTU-Malware-Capture-Botnet-185-1/2016-09-09_win1.pcap",
           "83dcbcd521a63d5516345898c1f50b32310dd57b149f86c6089a147d06501ac0", False),
    Sample("ctu-103-nofindings.pcap",
           f"{CTU}/CTU-Malware-Capture-Botnet-103/2015-03-1_capture-win2.pcap",
           "06a0205e9758a0fdcd0916fe60d080e614788df30ff3c3d821f4d6ab4235eb5c", False),
    Sample("dns-dns2tcp.pcap", f"{DMACHARD}/dns2tcp.pcap",
           "41a50974baa28c7731ed67a460d4e9bd9c0a6231c4ee660b2ee2ce798ab439aa"),
    Sample("dns-dnsextrator.pcap", f"{DMACHARD}/dnsextrator.pcap",
           "ef30a9992a9a0c7562c11c5870848fa932c9633676a839d4ee2079e5c89da57d"),
    Sample("dns-sods.pcap", f"{DMACHARD}/sods.pcap",
           "68e5392dfbf7885eb3f5ed63a987cfe13a1056563f03a83b35c8c0ecf4f4b3b6"),
    Sample("dns-dnscat2.pcap", f"{DMACHARD}/dnscat2.pcap",
           "904817d65b4bc9949bbb969b5be504faa2c4c41b2041ec3e005b6ee25a20fd45"),
    Sample("dns-iodine.pcap", f"{DMACHARD}/iodine.pcap",
           "5d9eb84014c98b4f4b21374178172e45ecfa54c881c1e5a8bdfc719832f6ad8a"),
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _download_once(sample: Sample) -> bytes:
    context = ssl.create_default_context()
    if not sample.verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(sample.url, context=context, timeout=120) as response:
        data = response.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"{sample.name}: download exceeds {MAX_DOWNLOAD_BYTES:,} bytes")
    return data


def _download(sample: Sample, attempts: int = 3) -> bytes:
    """The CTU mirror occasionally cuts a long transfer short; retry a few times."""
    for attempt in range(1, attempts + 1):
        try:
            return _download_once(sample)
        except (OSError, http.client.HTTPException):
            if attempt == attempts:
                raise
    raise AssertionError("unreachable")


def fetch(sample: Sample) -> str:
    target = OUT_DIR / sample.name
    if target.exists() and _sha256(target.read_bytes()) == sample.sha256:
        return "ok (cached)"
    data = _download(sample)
    if _sha256(data) != sample.sha256:
        raise ValueError(f"{sample.name}: SHA-256 mismatch, refusing to write")
    target.write_bytes(data)
    return f"downloaded {len(data):,} bytes"


def main(names: list[str]) -> int:
    known = {sample.name for sample in SAMPLES}
    unknown = [name for name in names if name not in known]
    if unknown:
        print(f"unknown sample name(s): {', '.join(unknown)}")
        return 2
    wanted = [s for s in SAMPLES if not names or s.name in names]
    failures = 0
    for sample in wanted:
        try:
            print(f"{sample.name}: {fetch(sample)}")
        except (OSError, http.client.HTTPException, ValueError) as error:
            failures += 1
            print(f"{sample.name}: FAILED - {error}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
