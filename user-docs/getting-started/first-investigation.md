# Your first investigation

The quick start showed the mechanics. This page shows how to use them on a capture you
care about: find, understand, preserve, and be able to prove the capture was not changed.

## 1. Work on a copy you can name

Keep the original capture where it is. NetForensics only reads it and stores its own copy
inside the evidence store (`evidence_store/` by default; [layout](../reference/storage.md)).

Pick a store location on purpose. `--store` goes **before** the command:

```bash
python -m backend.cli --store ./case-2026-014 analyze capture.pcap
```

## 2. Seal and analyze online

Without `--offline`, the seal is sent to a timestamp authority while the capture is
ingested, so the time of sealing rests on an outside clock rather than your own.

```bash
python -m backend.cli --store ./case-2026-014 analyze capture.pcap
```

If the authority cannot be reached, the case is stored with a `PENDING` timestamp and the
command still succeeds. Retry later:

```bash
python -m backend.cli --store ./case-2026-014 retry-timestamps
```

## 3. Read each finding

Every finding has the same three parts: **what** was flagged, **why** it matters in plain
language, and the **evidence sentence** with measured values and cutoffs. Use these
questions:

- Is the value close to its cutoff? A beacon with a coefficient of variation of 0.099 against
  a cutoff of 0.1 deserves more doubt than one at 0.012.
- Is the traffic legitimate? Content-delivery networks produce high-entropy host names and
  software updaters beacon on a timer. [Known limitations](../help/known-limitations.md)
  lists the common false positives.
- Does a second detector agree? A port scan and a beacon from the same host tell a
  different story from either alone.

A detector firing is a lead for a human to check, never a verdict.

## 4. Verify and keep the anchor line

```bash
python -m backend.cli --store ./case-2026-014 verify <case-id>
```

`verify` prints the verdict and, unless the case is ALTERED, adds a `verify` entry to the
custody chain and timestamps the new chain head. It also prints a line starting `Anchor`.
**Copy that line somewhere other than this machine** (a ticket, an email to yourself). It
is the one thing that lets a later verification prove that nobody cut entries off the end
of the log and re-timestamped the shorter one. See
[the evidence layer](../concepts/evidence-layer.md#anchoring-the-chain-head).

## 5. Come back later

Run `verify` again whenever the case is used: before a report is written, before it is
handed over. INTACT means the stored capture still matches the seal and an independent
timestamp. ALTERED means at least one check failed; [what to do](../help/troubleshooting.md#the-verdict-is-altered).

## What the result is worth

INTACT shows the capture is **unchanged since it was sealed**. It does not show that the
capture was complete or honest when it was taken, and it does not make the output
admissible anywhere. State it that way.
