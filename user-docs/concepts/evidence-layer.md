# The evidence layer

This is the point of the project. Detecting suspicious traffic is common; showing a skeptical
third party that the evidence has not changed since it was captured is not.

## The seal

When a capture comes in, before anything parses it:

1. It is hashed with **BLAKE3** and **SHA-256** in one streaming pass. A hash is a short
   fingerprint of the exact bytes: change one bit and it changes completely.
2. The SHA-256 is sent to a **timestamp authority** (TSA), which signs "I saw this hash at
   time T" ([RFC 3161](https://www.rfc-editor.org/rfc/rfc3161)). The reply is a token nobody can back-date,
   including you.
3. The seal (hashes, size, file name, received time and token) is stored.

The result is the digital version of an evidence bag: *this is the exact data, as received,
at this time.*

### Timestamps that cannot be faked

A reply is stored only if it is granted, signed by the **pinned** authority certificate (not
merely any certificate the reply carries), valid at its own time, marked for time stamping,
covers exactly the sealed SHA-256, and echoes the random number the request carried. Anything
else is refused, not stored.

If the authority is unreachable, the seal is stored `PENDING` and
[`retry-timestamps`](../guide/retry-timestamps.md) asks again later. A pending seal is never
presented as stamped.

## The custody chain

Every event for a case (ingest, analysis, each finding, each verification) is appended to a
log. **Each entry stores the hash of the entry before it, and its own hash covers that.**
Changing, removing, inserting or reordering any entry breaks every link after it, and
verification reports the first entry where it breaks.

- An entry's hash is SHA-256 over a fixed label, a zero byte and the entry as compact,
  sorted-key JSON (without the hash field itself).
- Entry 0 links to a hash of the seal, so a chain cannot be moved onto other evidence.

A chain on its own has two limits: removing the **last** entries leaves a shorter chain that
is still valid, and someone who can write the database can rewrite an entry and recompute
everything after it. Anchoring addresses both.

## Anchoring the chain head

An **anchor** records "entry N had hash H" in a separate append-only table and asks the TSA to
sign H. Verification fails if an anchored entry is gone or has a different hash, if the token
does not verify, or if the chain says an anchor was made but its record was deleted.

What anchoring still cannot do: someone who can write the database can delete the anchor
rows *and* the tail together. Only a copy of the anchor kept elsewhere shows that, which is
why `verify` prints an `Anchor` line and asks you to keep it.

## Verification

`verify` runs five checks (all of them, every time) and reports a verdict:

| Check | What it compares |
|---|---|
| `pcap_digests` | The stored file's BLAKE3, SHA-256 and size against the seal. |
| `custody_chain` | Every entry hash and link, and entry 0 against the seal. |
| `seal_binding` | That entry 0 belongs to this seal. |
| `rfc3161_timestamp` | The stored token against the pinned authority certificate and the sealed hash. |
| `chain_head_anchor` | Each anchored head against the chain, and each anchor token. |

Any failed check gives **ALTERED**. Otherwise, any check that cannot run yet (a `PENDING`
timestamp or anchor) gives **INCOMPLETE**. Otherwise **INTACT**.

## Append-only storage

Cases live in SQLite with triggers that refuse every update and delete, and any insert whose
key already exists. The one allowed change is a seal's timestamp going from `PENDING` to
`GRANTED`, once, with a non-empty token. Captures are stored by their own SHA-256, read-only.
These stop mistakes in the program; the chain and the anchors are what catch someone editing
the files by hand. [Storage layout](../reference/storage.md).

## What this proves, and what it does not

| It shows | It does not show |
|---|---|
| The stored capture is byte-for-byte what was sealed. | That the capture was complete or honest when it was taken. |
| The seal existed at the time an independent authority signed it. | That the timestamp authority itself is trustworthy beyond its published certificate. |
| No entry was changed, removed or reordered, up to the latest anchor. | Anything about entries added after the latest anchor, beyond the chain's own links. |

The wording is deliberate: **tamper-evident, designed toward admissibility.** No claim of
legal admissibility is made.
