# verify

Re-check a stored case against its seal and custody chain, and report a verdict.

```bash
python -m backend.cli [--store DIR] [--offline] verify <case-id>
```

`verify` only reads the evidence. It never changes the stored capture or rewrites the
chain.

## The five checks

Every check always runs, so one failure never hides another.

| Check | Passes when |
|---|---|
| `pcap_digests` | The stored file still hashes to the sealed BLAKE3 and SHA-256, and has the sealed size. |
| `custody_chain` | Every entry recomputes to its stored hash and links to the one before it. |
| `seal_binding` | Entry 0 of the chain belongs to this seal. |
| `rfc3161_timestamp` | The stored timestamp token verifies against the pinned authority certificate and covers the sealed hash. |
| `chain_head_anchor` | Every timestamped chain head is still in the chain with the same hash and a valid token. |

Each line prints `[PASS]`, `[FAIL]` or `[NOT RUN]` and an evidence sentence that names the
values compared.

## INTACT, ALTERED, INCOMPLETE

| Verdict | Exit code | Meaning |
|---|---|---|
| INTACT | 0 | All checks passed. The capture matches its seal and an independent timestamp vouches for it. |
| ALTERED | 1 | At least one check failed. Read the `[FAIL]` lines. |
| INCOMPLETE | 2 | Nothing failed, but at least one check could not run yet because a timestamp is `PENDING`. |

INTACT means "matches the seal and an independent timestamp". It does not mean "admissible".

## Offline: INCOMPLETE

```text
--8<-- "user-docs/examples/verify-offline.txt"
```

The two timestamp checks are `NOT RUN` because the case was sealed offline. Run
[`retry-timestamps`](retry-timestamps.md) when the network is back, then verify again.

## Online: INTACT

With a live authority the same case ends like this (shortened; this output depends on a
public service, so it is not checked by CI):

```text
[PASS] pcap_digests: The stored file re-hashes to the sealed values: ...
[PASS] custody_chain: All 3 custody entries recompute to their stored hashes and each links ...
[PASS] seal_binding: Custody entry 0 is bound to this seal (genesis hash ...).
[PASS] rfc3161_timestamp: www.freetsa.org signed SHA-256 ... at <time> (its clock; this system logged receipt at <time>); ...
[PASS] chain_head_anchor: 1 anchor(s) match the chain; the latest, entry 1 (hash ...), was signed by the TSA at <time>, ...

Verdict    INTACT
Anchor     entry 3, hash ... (GRANTED); keep a copy outside this system: a later verify must still find this entry.
```

## The Anchor line

Unless the verdict is ALTERED, `verify` adds a `verify` entry to the chain and timestamps
the new head, then prints an `Anchor` line. **Keep a copy of that line somewhere other than
the machine that holds the case.** Without an outside copy, someone with write access to the
database could cut the newest entries and the anchor records together.
See [anchoring](../concepts/evidence-layer.md#anchoring-the-chain-head).

## An ALTERED case is left as found

When the verdict is ALTERED, `verify` writes nothing: no new entry, no new anchor. Adding an
entry could overwrite the very damage that needs to be seen, and would give a damaged chain
a fresh timestamp. The program says so on standard error. The cost: the fact that someone
ran `verify` on an ALTERED case is not in the chain, so note it yourself.

## Errors

An unknown case id, a missing store or a database error prints one `error:` line and exits
with code 1, the same code as ALTERED. Read standard error to tell them apart:

```text
--8<-- "user-docs/examples/verify-unknown-case.txt"
```
