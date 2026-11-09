# The detectors

Three detectors ship. A fourth, JA3 fingerprinting, is designed but not built.
Cutoffs below are the defaults in [Configuration](../reference/configuration.md); most are
starting values, not tuned against real traffic.

Every finding states **what** was flagged, **why** it matters, and the **measured values
next to their cutoffs**. There are no confidence scores.

## DNS exfiltration

Data can be smuggled out inside DNS lookups by encoding it into the subdomain
(`5kncyj8u….exfil.example`). Encoded data looks random; ordinary names do not.

- **Measures:** the Shannon entropy of the subdomains under one parent domain, the longest
  subdomain, and the query rate to that parent.
- **Fires when:** the highest subdomain entropy is at least **4.2 bits per character**
  (ordinary names sit near 2.5) **and** either a subdomain is at least **30 characters** or
  the rate is at least **50 queries per 60 seconds**. Entropy alone is not enough: long
  random-looking names exist on legitimate content networks.
- **Severity:** HIGH if both the length and the rate corroborate, otherwise MEDIUM.
- **Suppressed:** parent domains on an allowlist (`cloudfront.net`, `akamaihd.net`,
  `googleusercontent.com`, `amazonaws.com`), matched on a dot boundary so
  `evilcloudfront.net` is not exempt.

## C2 beaconing

Malware often checks in with its controller at near-fixed intervals.

- **Measures:** for each pair of hosts (the destination port is ignored, so a beacon that
  rotates ports is still caught), the gaps between consecutive connections and their
  **coefficient of variation** (CV): the standard deviation of the gaps divided by their mean.
  A CV near 0 means machine-regular; people browsing give a CV well above 1.
- **Fires when:** at least **10 connections** and a CV of at most **0.1**.
- **Severity:** always MEDIUM. There is one signal and nothing to corroborate it with.
- **Suppressed:** multicast and broadcast destinations (such as the discovery announcements
  sent to `239.255.255.250` on a fixed timer), and any destination on the beacon allowlist.
- **Skipped:** a group whose gaps are all zero, which is a clock-resolution artifact.

## Port scan

A host probing many ports or many machines in a short time is doing reconnaissance.

- **Measures:** the busiest sliding window of **10 seconds** for each source: how many distinct
  destination ports and how many distinct destination hosts it touched.
- **Fires when:** at least **100 distinct ports** or at least **10 distinct hosts** in that window.
- **Severity:** HIGH if both cutoffs are met, otherwise MEDIUM.

## JA3 fingerprinting (planned)

Match the TLS handshake fingerprint of a client against a published malware blocklist. The
design is approved and not built; it is not part of the current tool.

## Reading the numbers yourself

Every evidence sentence gives enough to re-compute the result. [Worked math](../design/worked-math.md)
walks through entropy and the coefficient of variation by hand.
