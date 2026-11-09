# Limits

What the tool accepts, and what it deliberately leaves out. Reasons are in
[Design](../design/index.md); false positives and weak spots are in
[Known limitations](../help/known-limitations.md).

## Input

| Limit | Value |
|---|---|
| File type | Classic libpcap `.pcap` (microsecond or nanosecond timestamps, either byte order). pcapng is refused with a hint to convert it (`editcap -F pcap`). |
| Size | 512 MiB. |
| Link and network layers | Ethernet, IPv4. |
| Transport | TCP and UDP. |

## Scope decisions

- **File-based only.** No live capture.
- **No TCP reassembly.** Anything split across packets is not rebuilt.
- **Metadata only.** No decryption; detectors use timing, plaintext DNS and connection counts.
- **No machine learning** in the detection core.
- **Three detectors today.** JA3 fingerprinting is designed, not built.
- **One timestamp authority**, with its certificate pinned. Revocation is not checked.

## Evidence layer

- A seal's timestamp can wait up to 5 seconds on a slow authority. Beyond that the case is
  stored `PENDING`.
- Entries added after the latest anchor are protected by the chain's links alone.
- `verify` exits 1 for both ALTERED and errors; standard error tells them apart.
- Running `verify` on an ALTERED case is not recorded in the chain.
- The chain and anchors cannot detect someone who can edit the database **and** discards
  every outside copy of the anchor.

## Claims

The output is **tamper-evident, designed toward admissibility**. It is not a legal opinion,
and it does not certify that a capture was complete or honest when it was taken.
