# Known limitations

Where the rules are weak, what they can mistake, and what the evidence layer cannot do. Stating
them is part of the design.

## Detection

| Limitation | Detail |
|---|---|
| **Short encoded DNS labels are missed.** | Entropy per character is capped by the label length. A label must have about 19 characters to reach the 4.2 cutoff at all ([why](../design/worked-math.md#shannon-entropy)). A tunnel that uses short labels can pass unnoticed. |
| **Adaptive beacons evade the timing rule.** | An operator who adds random delay pushes the coefficient of variation above 0.1 ([worked example](../design/worked-math.md#jitter-large-enough-to-evade)). The rule catches the common case, not an adversary who knows it. |
| **A perfectly paced scan also looks like a beacon.** | Evenly spaced probes have a CV near 0, so `c2_beacon` may fire as well as `port_scan`. It is a true property of the rule, and can confuse a demo capture. |
| **Legitimate regularity looks like a beacon.** | Heartbeats and keep-alives are regular on purpose. The beacon allowlist and the multicast skip cover the known cases; others will need a human. |
| **Content networks look like tunnels.** | Long random-looking host names exist legitimately. Four parent domains are allowlisted; expect more false positives elsewhere. |
| **Thresholds are untuned.** | Most cutoffs are *proposed* starting values, [listed here](../reference/configuration.md). |
| **Encrypted traffic is opaque.** | Only metadata is analysed. Payloads are never read. |
| **Three of four detectors.** | JA3 fingerprinting is not built. |

## Parsing

- Classic pcap, Ethernet, IPv4, TCP and UDP only; no IPv6, no pcapng.
- No TCP reassembly: a message split across packets is not rebuilt.
- A UDP conversation reusing one 5-tuple is one flow however long it lasts.

## Evidence layer

| Limitation | Detail |
|---|---|
| **One timestamp authority, pinned.** | A renewed authority certificate invalidates older tokens until the pin is updated. Revocation is not checked. |
| **Entries after the latest anchor.** | They are protected by the chain's links only. `verify` says how many. |
| **Database write access.** | Someone who can edit the database file can drop its triggers, and can cut entries together with the anchor rows. Only a copy of the anchor kept elsewhere shows that. |
| **ALTERED is not recorded.** | `verify` leaves an ALTERED case untouched, so the fact that it was run is not in the chain. |
| **Exit code 1 is shared.** | Both ALTERED and errors. Read standard error. |
| **Slow authority.** | A seal can wait up to 5 seconds before falling back to `PENDING`. |
| **Not a legal opinion.** | See the [FAQ](faq.md#is-the-output-court-admissible). |
