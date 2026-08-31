# Core Logic

The *business rules* of NetForensics: how the evidence-integrity layer works and exactly
what each detector measures, its threshold, and the human-readable evidence it must
emit. For system structure see [`architecture.md`](architecture.md).

> Thresholds marked **(proposed / to confirm)** are starting values to tune against real
> pcaps. Values stated in the source proposal (e.g. entropy baselines) are kept as-is.

## Explainability contract (applies to every finding)

Every detector finding MUST carry three things:

1. **What** — the entity flagged (domain, host pair, source IP, fingerprint).
2. **Why it is suspicious** — plain language a magistrate can follow.
3. **Supporting data** — the measured number(s) and the benign baseline they exceed.

No confidence scores. No "the model says malicious." If a finding cannot state its
evidence in human terms, it does not ship (Hard Rule 1 & 2 in [`../CLAUDE.md`](../CLAUDE.md)).

---

## Evidence-integrity layer (Stages 1 & 4) — the differentiator

This is the real product. Make tamper-evidence *genuine*, not cosmetic.

### Seal (Stage 1, before any analysis)
- **Hash** the entire `.pcap` with **BLAKE3** on ingest.
- Record the hash together with an **RFC 3161 trusted timestamp** from a Timestamp
  Authority, plus the received-at time.
- This establishes the foundational evidentiary fact: *"this is the exact evidence,
  unaltered, as received at this time."* — the digital equivalent of sealing and signing
  an evidence bag.

### Append-only custody log (Stage 4)
- Every event (ingest, parse, each finding, report export) is appended as an entry.
- **Each entry references the prior entry** (e.g. includes the previous entry's hash) so
  the log is a tamper-evident chain — you cannot alter or remove an entry without
  breaking every subsequent link. **(mechanism proposed / to confirm: hash-chained entries)**
- The log is append-only: no in-place edits, no deletes.

### Integrity verification (the headline flow)
1. Re-hash the stored pcap with BLAKE3.
2. Compare against the sealed hash from Stage 1.
3. **Match** → chain intact, evidence provably unaltered.
   **Mismatch** → flag "evidence altered / chain of custody broken."

> **Live proof:** seal a pcap → analyze → then flip one byte and re-verify → the tool
> declares the evidence tampered. This 10-second demonstration is the whole point of the
> evidence-integrity layer.

### Honest framing
Prefer "evidentiary integrity / tamper-evident chain of custody **designed toward**
admissibility standards" over a flat "court-admissible" claim — you can prove
tamper-evidence live; you cannot certify legal admissibility in a weekend. See open risk
in [`handoff.md`](handoff.md).

---

## The four detectors

Each is a transparent rule, not a model.

### 1. DNS exfiltration / tunneling
- **Method:** Shannon entropy of DNS subdomains + subdomain length + query rate to a
  single parent domain.
- **Signal:** Encoded/exfiltrated data has high randomness → high entropy; tunneling
  shows long subdomains and a high query rate to one parent.
- **Threshold / baseline:** Benign domains sit near **entropy ~2.5**; encoded data
  reaches **~4.2+**. Length and query-rate thresholds **(proposed / to confirm)**.
- **Evidence string (example):** *"Subdomain `<x>` of `<parent>` has Shannon entropy
  4.2 (benign baseline ~2.5), with 312 queries in 60s — consistent with encoded data
  exfiltrated over DNS."*

### 2. C2 beaconing
- **Method:** Group connections by `(src_ip, dst_ip)` — destination port ignored, so a
  beacon that rotates ports is still caught. Within a group, compute inter-arrival
  times (gaps between consecutive connections, chronologically sorted), then the
  **coefficient of variation**: `sample_stdev(IATs) / mean(IATs)`. Sample (not
  population) stdev, since we're estimating regularity from a limited observation
  window, not the host's full lifetime behavior.
- **Signal:** Malware beacons at near-fixed intervals (CV near 0); humans do not
  produce robotically regular check-ins (CV typically well above 1).
- **Threshold / baseline:** Fires when `connection_count >= min_connections` (10,
  **proposed**) **and** `CV <= max_coefficient_of_variation` (0.1, **proposed**) — both
  in `Config.c2_beacon`. Below `min_connections`, regularity isn't statistically
  meaningful yet, so the group is skipped before any CV math runs.
- **Edge cases (decided):** A group with a zero-mean IAT (all connections landed at the
  identical timestamp — a pcap timestamp-resolution artifact, not a real signal) is
  treated as **not computable** and skipped, not flagged. `dst_ip` allowlist
  (`Allowlists.beacon_dst_ips`) checked before any stats work, for known-legitimate
  heartbeats.
- **Severity:** Always `MEDIUM` — **open decision**. Unlike DNS-exfil (entropy +
  length/rate corroboration → HIGH), this detector has one signal (CV), so there is no
  second axis to corroborate against without inventing an unconfigured cutoff.
  Candidate second axis if a HIGH tier is wanted: connection count well above
  `min_connections` strengthens the statistical claim — would need its own named
  config field, not a hardcoded fraction.
- **Known limitation:** Adaptive C2 (e.g. operator-tunable jitter) can push CV above
  the threshold deliberately to evade this exact check — this catches the common case
  honestly, not adaptive adversaries. The evidence string states exact numbers so a
  human analyst can still judge borderline cases.
- **Evidence string (example):** *"Host `<src>` contacted `<dst>` every ~60s (±2s) over
  45 connections (coefficient of variation 0.033, threshold 0.1) — robotic regularity
  characteristic of C2 beaconing, not human traffic."*

### 3. Port scan / reconnaissance
- **Method:** Fan-out analysis — one source touching many ports/hosts within a time
  window.
- **Signal:** A single source contacting a large spread of destinations/ports fast is a
  directly countable recon signal.
- **Threshold / baseline:** Distinct ports/hosts contacted by one source in a window
  exceeds a cutoff **(proposed / to confirm)**.
- **Evidence string (example):** *"Source `<src>` contacted 850 distinct ports across 12
  hosts in 8s — fan-out consistent with a port scan."*

### 4. JA3 fingerprinting
- **Method:** Compute the **JA3** fingerprint of the TLS handshake; match against the
  **abuse.ch SSLBL** blocklist.
- **Signal:** C2 clients typically do not randomise their handshakes, so a JA3 match to a
  known-malware fingerprint is valid.
- **Threshold / baseline:** Exact match against the SSLBL feed (binary).
- **Evidence string (example):** *"TLS client from `<src>` has JA3 `<hash>`, matching
  abuse.ch SSLBL entry for malware family `<family>`."*
- **JA3 caveat:** JA3 is unreliable for *general browser* fingerprinting (modern browsers
  randomise handshake order) but remains valid against a *malware blocklist*. **JA4** is
  the forward-looking successor and a natural upgrade path — not implemented now.

---

## False positives — known sources & mitigations

| Source of FP | Why | Mitigation |
|---|---|---|
| CDNs / cloud domains | Legitimately high-entropy hostnames | Allowlist of known-good parent domains |
| Heartbeats / keep-alives | Legitimately regular timing | Allowlist + tunable regularity threshold |
| Any borderline finding | — | Every alert shows its evidence so a human analyst can dismiss it. **The human stays in the loop.** |

Thresholds are tunable, not hard-coded magic — tune against real captures.

---

## Non-goals / scope cuts (deliberate)

- **No live capture** — file-based (`.pcap`) only.
- **No TCP reassembly.**
- **No ML / no LLM** in the detection core (admissibility — Hard Rule 1).
- **No payload decryption** — metadata-only analysis (timing, plaintext-DNS entropy,
  handshake fingerprints). We scope what we cannot see rather than overclaim.
- **JA3** used only against the malware blocklist, never for general fingerprinting.
- Detection coverage is bounded to these **four patterns** — pitched honestly as a
  focused, reliable tool, not an all-seeing one.
