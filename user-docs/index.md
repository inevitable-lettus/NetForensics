---
title: NetForensics
hide:
  - navigation
---

# NetForensics

NetForensics reads a packet capture, runs four plain-rule detectors over it, and wraps
every result in an evidence layer. It tells you **what** looks suspicious, **why**, and
whether the capture is **still exactly the file that was sealed**.

```text
python -m backend.cli analyze capture.pcap     # seal, then find
python -m backend.cli verify <case-id>         # prove nothing changed
```

<div class="grid cards" markdown>

- **Start here**

    Install the tool, seal and analyze a capture, and watch it catch a tampered copy,
    in about five minutes.

    [Quick start](getting-started/quick-start.md)

- **Look things up**

    Every command, option and exit code, generated from the program itself.

    [Command-line reference](reference/cli.md)

- **Understand it**

    How a capture becomes a sealed case, what each detector measures, and what the
    evidence layer proves and does not prove.

    [Concepts](concepts/index.md)

- **Something went wrong**

    Errors, a pending timestamp, an ALTERED verdict.

    [Help](help/index.md)

</div>

## What it does

| Step | What happens | Where to read more |
|---|---|---|
| Seal | The capture is hashed (BLAKE3 and SHA-256) and sent to a trusted timestamp authority **before** anything reads its contents. | [The evidence layer](concepts/evidence-layer.md) |
| Detect | DNS exfiltration, C2 beaconing and port-scan rules run over the connections. Each finding states the measured value next to its cutoff. | [The detectors](concepts/detectors.md) |
| Record | Every event is appended to a hash-chained custody log, and the chain's head is timestamped. | [The evidence layer](concepts/evidence-layer.md) |
| Verify | One command re-checks the capture, the chain and the timestamps and gives a verdict: INTACT, ALTERED or INCOMPLETE. | [`verify`](guide/verify.md) |

## What it does not do

- **No machine learning.** Every detector is a rule you can read and re-compute by hand.
- **No claim of legal admissibility.** The output is tamper-evident and designed toward
  admissibility; whether a court accepts it is not something software can decide.
- **No live capture, no decryption.** It reads classic `.pcap` files and looks at metadata
  (timing, plaintext DNS, connection counts), not encrypted payloads.

See [Limits](reference/limits.md) and [Known limitations](help/known-limitations.md) for the
full list.

!!! note "Status"
    NetForensics is a personal learning project built in public increments. The command
    line is the supported interface. The repository also contains a web API and a React
    frontend; they are kept but are not part of v1 and are not documented here.
