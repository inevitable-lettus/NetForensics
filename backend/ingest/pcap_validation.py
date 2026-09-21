"""Upload boundary check — fail loudly on anything that is not a classic pcap,
before it is sealed or parsed (CLAUDE.md: validate inputs at boundaries)."""

from __future__ import annotations

from pathlib import Path

# libpcap magic numbers: little/big endian, microsecond and nanosecond variants.
_PCAP_MAGICS = frozenset(
    {
        bytes.fromhex("d4c3b2a1"),
        bytes.fromhex("a1b2c3d4"),
        bytes.fromhex("4d3cb2a1"),
        bytes.fromhex("a1b23c4d"),
    }
)
_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
_PCAP_GLOBAL_HEADER_BYTES = 24


class InvalidCaptureError(ValueError):
    """The uploaded file is not a capture this tool can analyse."""


def validate_pcap_file(path: Path) -> None:
    """Raise `InvalidCaptureError` unless `path` starts with a valid classic pcap
    global header. pcapng is recognised and rejected with a specific message."""
    with path.open("rb") as fh:
        header = fh.read(_PCAP_GLOBAL_HEADER_BYTES)
    if header[:4] == _PCAPNG_MAGIC:
        raise InvalidCaptureError(
            "pcapng captures are not supported yet; convert with `editcap -F pcap`."
        )
    if len(header) < _PCAP_GLOBAL_HEADER_BYTES or header[:4] not in _PCAP_MAGICS:
        raise InvalidCaptureError("File is not a libpcap capture (bad or missing header).")
