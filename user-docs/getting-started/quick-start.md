# Quick start

About five minutes. It uses small synthetic captures that the repository generates, so
you need no network and no downloads. Every command output on this page is checked by
CI against the real program.

!!! tip "`--offline`"
    The examples run with `--offline`, which never contacts the timestamp authority. Without
    it, the tool sends each seal to a public authority (freetsa.org) and the verdict can reach
    INTACT. [Why offline is the default here](../guide/verify.md#intact-altered-incomplete).

## 1. Generate sample captures

```bash
python scripts/make_synthetic_pcaps.py
```

This writes four deterministic captures into `sample-pcaps/`: `synthetic-benign.pcap`,
`synthetic-dns-exfil.pcap`, `synthetic-c2-beacon.pcap` and `synthetic-port-scan.pcap`.

## 2. Seal and analyze

```bash
python -m backend.cli --offline analyze sample-pcaps/synthetic-dns-exfil.pcap
```

```text
--8<-- "user-docs/examples/analyze-dns-exfil.txt"
```

What you are looking at:

- **Case** is the id of the stored case. You need it for `verify`.
- **BLAKE3** and **SHA-256** are the capture's fingerprints, taken before anything read it.
- **Timestamp PENDING** means no timestamp authority has signed the seal yet (here because
  of `--offline`). The tool never fakes a timestamp.
- The **finding** says what fired, why, and the measured values next to their cutoffs.

## 3. Verify

Replace `<case-id>` with the id printed above.

```bash
python -m backend.cli --offline verify <case-id>
```

```text
--8<-- "user-docs/examples/verify-offline.txt"
```

Five checks ran. Three passed. The two that need a timestamp authority say `NOT RUN`, so
the verdict is **INCOMPLETE** (exit code 2): nothing is wrong, but no outside clock vouches
for the seal yet. Run `retry-timestamps` once you are online and verify again to reach
INTACT.

## 4. Tamper and see it caught

```bash
python -m backend.cli --offline tamper-demo sample-pcaps/synthetic-dns-exfil.pcap
```

```text
--8<-- "user-docs/examples/tamper-demo.txt"
```

`tamper-demo` seals a copy in a throwaway store, flips one bit of the stored file and
verifies again. The `pcap_digests` check fails, naming the sealed and the measured value,
and the verdict becomes **ALTERED**. Your own capture is only read.

## Next

- [Your first investigation](first-investigation.md): use the findings, not just the demo.
- [User guide](../guide/index.md): one page per command.
