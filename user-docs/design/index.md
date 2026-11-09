# Design decisions

The choices behind the tool, with the reason for each. Alternatives that were rejected are
named so the reasoning can be checked.

## Explainable rules, not a model

Every detector is a rule a person can re-compute: entropy, a coefficient of variation, a
count in a window. A model's output cannot be cross-examined; a number next to its cutoff
can. The cost is accuracy on adaptive attackers, which is stated in
[Known limitations](../help/known-limitations.md).

## Seal first

The capture is hashed and timestamped before any code reads its contents. A parser bug,
however bad, cannot change what was sealed, and the first thing in the chain of custody is the
evidence itself.

## Two hashes

BLAKE3 and SHA-256 are computed in one pass. SHA-256 is what the timestamp authority signs
and what a tool like `openssl ts -verify` understands; BLAKE3 is fast on large captures and
independent of SHA-256, so a weakness in one does not remove the other.

## A pinned timestamp certificate

The timestamp library used here trusts certificates carried *inside* a reply (up to version
1.0.8). A forged reply could therefore bring its own certificate. The tool pins the authority's
actual certificate and accepts only replies signed by it. The pin stays even though later
library versions fix the flaw. Cost: when the authority renews its certificate, older tokens
stop verifying until the pin is updated.

## Never fake a timestamp

An unreachable authority gives `PENDING` and a retry command, not a failure and not a
locally invented time. The verdict says INCOMPLETE until a real one arrives.

## A hash chain, then anchors

A chain of hashes makes edits, removals and reordering visible, but cannot show that the
**end** was cut, and has no secret. Options considered for closing that:

| Option | Verdict |
|---|---|
| Record the anchor only as a custody event | Rejected: it is cut off together with the tail it protects. |
| Print the head in the report only | Kept as a complement: the CLI prints the latest anchor. It needs a human to compare and proves nothing about *when*. |
| Sign the head with the tool's own key | Rejected: the key would sit next to the database it protects. |
| **Have the timestamp authority sign the head, in a separate append-only table** | **Chosen.** The head hash already covers the index and case id, so the authority signs it directly and `openssl ts -verify -digest <hash>` can re-check it. |

## A canonical form for chain hashes

Writer and checker must hash the same bytes. Entries are hashed as compact JSON with sorted
keys and raw UTF-8; decimal numbers are refused (stored as text such as `"4.2"`) because
their text form can differ between systems; there is no Unicode normalisation; a fixed label
(`custody-entry/v1`, `custody-genesis/v1`) keeps two uses of the hash from being confused.

## verify does not write to an ALTERED case

Writing a new entry to a damaged chain could overwrite the damage that needs to be seen, and
would give the damaged head a fresh timestamp. `verify` therefore leaves it exactly as found.

## Detector choices

- **DNS: entropy is required, length or rate must corroborate it.** Length alone
  false-positives on real long names on content networks.
- **Beacon: destination port is ignored.** A beacon that rotates ports is still one pair of hosts.
- **Beacon severity is always MEDIUM.** One signal and nothing to corroborate it.
- **Multicast and broadcast are skipped by CIDR range.** Discovery announcements are
  perfectly regular and harmless; the suppression is in configuration, not code.
- **Non-text DNS labels are measured as raw bytes.** Escaping a byte such as `0xE4` to four
  characters of text would lower the entropy and could hide a tunnel.

## Wording

The output is described as **tamper-evident, designed toward admissibility**. Tamper-evidence
can be demonstrated live; legal admissibility cannot be certified by software.

See [Worked math](worked-math.md) for the numbers behind the detector thresholds.
