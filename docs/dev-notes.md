# Dev Notes

Plain-language notes for the human who owns this project. Each section is short: what it
does, the key idea, one worked example with real numbers, and its limits.

**Standing rules.** Every PR that builds something adds or updates its section here, and
each section stays brief and simple (about 40 lines at most, no long background). See
[`../CLAUDE.md`](../CLAUDE.md) "Dev notes". Design rules live in [`logic.md`](logic.md),
structure in [`architecture.md`](architecture.md). Where this file and the code disagree,
the code wins, so say so in a PR. Worked-example numbers were computed with the project's
own code or plain arithmetic.

## Index

1. [The pipeline: upload to report](#1-the-pipeline-upload-to-report)
2. [Flows: how packets become connections](#2-flows-how-packets-become-connections)
3. [DNS exfiltration detector](#3-dns-exfiltration-detector)
4. [C2 beaconing detector](#4-c2-beaconing-detector)
5. [Port-scan detector](#5-port-scan-detector)
6. [The seal: hashing the evidence](#6-the-seal-hashing-the-evidence)
7. [Current thresholds and what they mean](#7-current-thresholds-and-what-they-mean)
8. [Evidence storage: SQLite and content-addressed files](#8-evidence-storage-sqlite-and-content-addressed-files)
9. [Trusted-timestamp transport and retry](#9-trusted-timestamp-transport-and-retry)
10. [Custody hash chain](#10-custody-hash-chain)
11. [The command-line tool](#11-the-command-line-tool)
12. [Not built yet](#12-not-built-yet)
13. [JA3 fingerprinting (approved design, not built)](#13-ja3-fingerprinting-approved-design-not-built)
14. [Decisions log](#14-decisions-log)

## Words used throughout

| Term | One-line meaning |
|---|---|
| pcap | A file of packets recorded off a network (a "packet capture"). |
| Packet | One small chunk of data sent over a network. |
| IP address / port | A machine's address (`10.0.0.5`) / a number (0-65535) picking the program on it. Web is usually 443, DNS is 53. |
| TCP / UDP | TCP sets up a connection first (a "handshake"); UDP just sends. |
| DNS | The internet's phone book: turns `example.com` into an IP address. |
| Finding | One thing a detector reports, with the numbers that triggered it. |
| Severity | `HIGH` or `MEDIUM` (`LOW`, `INFO` exist but are unused). A rule label, not a score. |
| Hash | Any data in, a fixed-length fingerprint out. Same input, same fingerprint; change one byte and it changes completely. |

---

## 1. The pipeline: upload to report

**What it does.** Takes one `.pcap` and produces a case: a sealed record of the file plus
a list of findings, viewable as JSON and as a PDF.

**Steps.**
1. **Upload** (`POST /api/cases`, or the CLI, section 11; both use `backend/intake.py`). Written to disk in 1 MiB chunks; over 512 MiB gets HTTP 413.
2. **Validate** (`ingest/pcap_validation.py`). The first 4 bytes are a "magic number" naming
   the file type. pcapng and anything else are refused (HTTP 400), so bad input never
   reaches the detectors.
3. **Seal** (`evidence/seal.py`). Hash the file first, so the fingerprint is of the file as
   received (section 6).
4. **Parse** (`parse/`). Two `dpkt` passes: DNS summaries (section 3), flows (section 2).
5. **Detect** (`detectors/`). DNS exfiltration reads the DNS summaries; C2 beaconing and
   port scan read the flows.
6. **Package.** Findings sorted most severe first, bundled with the seal into a `CaseRecord`.
7. **Save.** The pcap moves from `evidence_store/staging/<case id>/` to
   `evidence_store/blobs/<sha256>` (read-only, re-hashed on the way in); case, seal and
   findings go into SQLite (section 8). The case id is 32 random hex characters, checked
   on every read, so `../x` cannot reach other folders.
8. **Report.** `GET /api/cases/<id>/report.pdf` renders the saved record only; it never
   re-reads the pcap.

**Key ideas.** Data flows one way: parsing never touches storage, detectors never touch
HTTP, the PDF never re-parses. And no machine learning: each detector is a fixed rule with
a number you can check by hand ("4.4 where normal is 2.5" can be defended; "the model
flagged it" cannot).

**Limits.**
- The pcap is read twice (DNS, then flows). Fine for small captures.
- Classic pcap, Ethernet, IPv4, TCP and UDP only. No pcapng, IPv6 or live capture.
- The database refuses edits through normal SQL, but someone with write access to the file
  can still change it. The custody chain plus a timestamped head covers that (sections 10, 12).
- The PDF is minimal.

---

## 2. Flows: how packets become connections

**What it does.** Turns thousands of packets into one record per conversation (a *flow*),
because the detectors reason about conversations.

**Steps.**
1. Decode each packet with `dpkt`; skip anything that is not Ethernet + IPv4 + TCP/UDP.
2. Give each packet a direction-independent key: both endpoints (IP and port) plus
   TCP/UDP, sorted. A packet and its reply get the same key, so they share a flow.
3. The first packet for a key starts a flow; later ones add to its packet count, byte
   count and end time.
4. A TCP SYN (SYN flag set, ACK not set) on a key with an open flow closes it and starts a
   new one, so a client reconnecting from the same port becomes two connections.
5. `src_ip` is whoever sent the first packet (the initiator).

**Example: why orientation matters.** Machine S scans machine T on 3 ports and T replies on
each. If replies were their own flows, T would also look like it contacted S on 3 ports and
a scan detector could blame the victim. Folding both directions into the initiator's flow
makes only S the source.

**Limits.**
- A UDP conversation reusing the same endpoints stays one flow forever (no idle timeout).
- If a capture starts mid-conversation, the first packet may be a reply and the initiator
  is guessed wrong.
- `inter_arrival_times` is left empty; the C2 detector computes gaps itself.

---

## 3. DNS exfiltration detector

**What it does.** Flags a host that seems to smuggle data out inside DNS lookups.

**The idea.** Firewalls usually allow DNS, so malware encodes data into the name it looks
up (`onswg4tf.evil.example`) and the attacker's DNS server reads it back. Encoded data looks
random, long and frequent. In `a8f3k.evil.example` the *parent domain* is the last two
labels and the *subdomain* is the rest.

**Steps** (`parse/dns_parser.py`, `detectors/dns_exfil.py`).
1. Collect DNS questions to UDP port 53; group by (source IP, parent domain). Per group:
   highest subdomain entropy, longest subdomain, query count.
2. Skip allowlisted parents (`cloudfront.net`, `akamaihd.net`, `googleusercontent.com`,
   `amazonaws.com`), matched on a dot, so `evilcloudfront.net` is not skipped.
3. **Entropy is required:** under 4.2, no finding.
4. Supporting signals: longest subdomain at least 30 characters; at least 50 queries per
   60 s. `HIGH` if both, `MEDIUM` if one. Length alone never fires.

**Key idea: Shannon entropy** (`parse/entropy.py`). Bits per character of unpredictability:
for each distinct character take its share `p` of the string and add `-p × log2(p)`. One
repeated letter scores 0; all-different characters score `log2(length)`, the maximum.

**Example 1: `google`** (g×2, o×2, l×1, e×1): 0.5283 + 0.5283 + 0.4308 + 0.4308 = **1.918**.
Also `www` = 0.0, `aaaaaaaa` = 0.0, `abcdefgh` = 3.0 = `log2(8)`.

**Example 2: an encoded blob.** The made-up text `ssn=123-45-6789;card=4111` in base32,
lowercased, is the 40-character subdomain `onzw4pjrgizs2nbvfu3doobzhnrwc4tehu2dcmjr`:
23 distinct characters, entropy **4.396** (maximum for 40 is `log2(40)` = 5.32), above 4.2 and
far above the ~2.5 benign level.

**Example 3: the rate.** Rate = `count ÷ seconds spanned × 60` (a zero span uses the raw
count). The blob in 200 queries over 30 s: entropy 4.396 passes, length 40 ≥ 30 hits, rate
200 ÷ 30 × 60 = 400 ≥ 50 hits, so `HIGH`: "Subdomain 'onzw4p…' of 'evil.example' has Shannon
entropy 4.40 (benign baseline ~2.5), length 40 chars, with 200 queries in 60s (~400/window) —
consistent with data encoded into DNS queries."

**Names with non-text bytes (fix for #16).** A DNS label can hold any byte, but the `dpkt`
library only accepts valid UTF-8 text and used to crash the whole run on a bad byte. Now
`_questions_lossless` re-reads the name by hand and writes each bad byte as `\xNN`
(`0xE4` becomes `\xe4`), so the label stays visible to the detector.
*Example:* the 4 bytes `E4 E5 E6 E7` become the 16 characters `\xe4\xe5\xe6\xe7`; entropy
of the escaped text is 2.5 (counts 4, 4, 4, 1, 1, 1, 1 of 16).
*Limit:* escaping makes names look longer and **less random** than they are. In
`dns-iodine.pcap` the longest label is 55 raw bytes but 193 characters, with entropy 3.43
escaped versus 5.74 per raw byte. So this can only cause a miss, never a false alarm.
Measuring raw bytes instead is tracked in issue #32.

**Limits.**
- Short names never reach 4.2: entropy tops out at `log2(length)`, and `log2(19)` = 4.25, so
  a subdomain needs 19+ characters. Our 20-character `nbswy3dpeb3w64tmmqqq` scores 3.684 and
  is missed.
- Entropy covers the whole subdomain, dots included. The parent is the last two labels, so
  `foo.co.uk` reads as `co.uk` (no public-suffix list).
- UDP port 53 only; a tunnel with few, short queries stays under every limit.
- A CDN not on the allowlist can false-alarm; a human reviews every finding.

---

## 4. C2 beaconing detector

**What it does.** Flags a machine that contacts another at suspiciously even intervals,
as malware does when it "phones home" to a command-and-control (C2) server.

**The idea.** Software on a timer connects every N seconds; people act in bursts and pauses.
So measure how regular the gaps are.

**Key ideas.** *Inter-arrival time (IAT)*: the gap between one connection and the next (N
connections give N-1 gaps). *Standard deviation*: the typical distance of a gap from the
mean (sample version: squared distances summed, divided by count - 1, square-rooted).
*Coefficient of variation (CV)*: standard deviation ÷ mean, so a 60 s beacon wobbling 2 s
and a 10-minute beacon wobbling 20 s both score about 0.03. Near 0 is robotic.

**Steps** (`detectors/c2_beacon.py`).
1. Group flows by (source IP, destination IP); the destination port is ignored so a
   beacon that changes ports is still caught.
2. Skip allowlisted destinations: exact IPs and address ranges (multicast and broadcast by
   default, see Limits).
3. Need at least 10 connections, else stop.
4. Sort the start times and take the gaps.
5. Compute CV; if the mean is 0 or there are fewer than 2 gaps it is not computable and
   the group is skipped, not flagged.
6. CV of 0.1 or less is a finding, always `MEDIUM`.

**Example: a beacon.** Gaps `60, 61, 59, 60, 62, 58, 60, 61, 59`: mean 540 ÷ 9 = **60**;
squared distances 0, 1, 1, 0, 4, 4, 0, 1, 1 sum to 12; variance 12 ÷ 8 = 1.5; standard
deviation √1.5 = **1.2247**; CV = 1.2247 ÷ 60 = **0.0204**, under 0.1, so it fires.

**Example: a human.** Gaps `3, 45, 2, 120, 8, 300, 15, 1, 60`: mean 61.56 (close to the
beacon's 60), standard deviation 97.61, CV = **1.586**. Same average, different shape; no
finding.

The finding reads: "Host A contacted B every ~60s (±1.2s) over 10 connections
(coefficient of variation 0.020, threshold 0.1) — robotic regularity characteristic of C2
beaconing, not human traffic."

**Limits.**
- Malware that adds random jitter to its timer can push CV above 0.1 on purpose.
- One signal, nothing to corroborate it, so severity is always `MEDIUM`.
- Legitimate automation (update checks, monitoring, NTP) is regular too; the allowlist is
  the tool for that.
- **Multicast is skipped on purpose (issue #17).** Devices announce themselves on a timer
  to shared addresses: SSDP sends to `239.255.255.250` every 120 s (CV 0.000), which once
  looked like a beacon (`ctu-185-1`). Destinations inside `Allowlists.beacon_dst_cidrs`
  are skipped, default `224.0.0.0/4` (all multicast; CIDR = an address block) and
  `255.255.255.255/32` (broadcast). 22 connections 120 s apart to `239.255.255.250`: no
  finding; the same timing to `203.0.113.9`: a finding. Skips are logged at INFO. Blind
  spot: C2 hidden in multicast would be missed. A configured list replaces the default.
- A scan with evenly spaced probes also has CV near 0 and trips this detector.
- Slow beacons in a short capture never reach 10 connections.

---

## 5. Port-scan detector

**What it does.** Flags one machine that touches an unusually large number of ports or
hosts in a short time, as a scanner hunting for open doors does.

**The idea.** Normal use touches few destinations. A *vertical* scan knocks on hundreds of
ports on one target; a *horizontal* scan hits one port on many machines. Count distinct
destinations in a sliding time window.

**Steps** (`detectors/port_scan.py`).
1. Group flows by source IP and sort by start time.
2. Slide a 10-second window: add each new flow, then drop flows from the left that are
   more than 10 s older than it. Counters track distinct destination ports and hosts.
3. Remember the highest port count and highest host count at any moment (tracked
   separately, since they can peak at different times).
4. Fire if ports ≥ 100 **or** hosts ≥ 10; `HIGH` if both, `MEDIUM` if one.

**Example: the window moving.**

| Time (s) | Port | Host |
|---|---|---|
| 0 | 22 | A |
| 2 | 80 | A |
| 4 | 443 | B |
| 11 | 8080 | A |

At t=4 the window holds 3 flows: ports 22, 80, 443 = 3, hosts A, B = 2. At t=11 the t=0
flow is 11 s old and dropped; t=2 is 9 s old and stays. Now ports 80, 443, 8080 = 3, hosts
A, B = 2. Peak 3 ports and 2 hosts, far under 100 and 10: no finding. A scanner touching
850 ports in 8 seconds would reach 850 and fire `MEDIUM`, or `HIGH` if it also hit 10+
hosts.

**Limits.**
- 100 ports and 10 hosts are proposed values, not tuned on real traffic.
- A slow scan (one port a minute) never fills a 10 s window.
- A busy legitimate machine (load balancer, crawler) can false-alarm.
- Scans spread across many source addresses look like many small sources.
- It counts attempts seen in the capture, not whether the scan succeeded.

---

## 6. The seal: hashing the evidence

**What it does.** Records a fingerprint of the uploaded pcap at the moment it arrives, so
anyone can later prove the file has not changed since.

**Key idea: a hash.** SHA-256 turns any data into 64 hex characters. You cannot work back
from the fingerprint, and in practice you cannot craft a second file with the same one.

**Example.** Real SHA-256 of the 12-byte text `NetForensics` vs `NetForensicS` (last letter
capitalised):

| Input | SHA-256 |
|---|---|
| `NetForensics` | `bff919082f1b3d4c1d5ab0f296b19bc3667244834c46e1c0cb9e236ea26c4e9a` |
| `NetForensicS` | `bcf28f3b2b82a0859a2e99d2ecdad33ec0482b01fd20e7efddca897ec67374fe` |

One letter changed, nothing in common. BLAKE3 behaves the same way (`NetForensics` gives
`0f342397e9221289626886c668929dfbeffc89f683ce12573281a4def777152f`). That is why flipping one
byte of a sealed pcap is detectable.

**Steps** (`evidence/seal.py`).
1. Note the time received in UTC, *before* hashing, because custody begins when handling
   begins.
2. Read the file once in 1 MiB chunks, feeding both BLAKE3 and SHA-256, so memory stays flat.
3. Store a `SealRecord`: filename, size, both hashes, received-at time, timestamp status
   `PENDING`.

**Why two hashes.** BLAKE3 is the fast primary fingerprint. SHA-256 is what an RFC 3161
timestamp authority signs and what `openssl` and most courts recognise, so the timestamp step
needs no conversion. Sealing is pure hashing and cannot fail because the internet is down;
the trusted timestamp (proving *when*) comes later, and until then the status is `PENDING`.

**Limits.**
- A hash proves the file is unchanged **since sealing**, not that it was genuine or complete
  when captured.
- With no trusted timestamp yet, "received at" is our own clock and proves nothing to a third
  party.
- The append-only database blocks edits through normal SQL but not someone with write access
  to the file; the custody chain and its timestamped head close that gap (sections 10, 12).
- Hash-checking on re-open (verification) is not built; today the seal is only written.

---

## 7. Current thresholds and what they mean

All live in `backend/config.py`, the single place numbers live. "Proposed" means a starting
guess to tune on real captures; only the entropy values came from the original proposal.

| Setting | Value | What it means |
|---|---|---|
| `benign_entropy_baseline` | 2.5 | Typical entropy of normal subdomains; shown in evidence, not used to decide. |
| `entropy_threshold` | 4.2 | DNS entropy required before a finding; needs 19+ characters to be reachable. |
| `subdomain_length_threshold` | 30 (proposed) | Longest subdomain of at least 30 characters is a supporting signal. |
| `query_rate_threshold` / `query_rate_window_secs` | 50 (proposed) / 60 | At least 50 queries per window to one parent domain is a supporting signal. |
| `min_connections` | 10 (proposed) | Connections a host pair needs before beaconing is judged. |
| `max_coefficient_of_variation` | 0.1 (proposed) | CV at or below this counts as robotic. |
| `distinct_ports_threshold` / `distinct_hosts_threshold` / `window_secs` | 100 / 10 / 10 (proposed) | Port-scan: distinct ports or hosts within the window. |
| `dns_parent_domains` allowlist | `cloudfront.net`, `akamaihd.net`, `googleusercontent.com`, `amazonaws.com` | Skipped by the DNS detector; they legitimately look random. |
| `beacon_dst_ips` allowlist | empty | Destination IPs skipped by the beacon detector. |
| `beacon_dst_cidrs` allowlist | `224.0.0.0/4`, `255.255.255.255/32` | Address ranges (CIDR) skipped by the beacon detector: multicast and broadcast discovery traffic. |
| `max_upload_bytes` | 512 MiB (proposed) | Larger uploads are rejected. |
| `upload_chunk_bytes` / `hash_chunk_bytes` | 1 MiB | Streaming size; keeps memory flat. |
| `hash_algorithm` | blake3 | Primary seal hash. |
| `tsa_url` | `https://freetsa.org/tsr` | Free timestamp authority (transport built, section 9; token checking not built). |
| `tsa_timeout_secs` | 5 | Total deadline for one request, then it counts as unavailable. |
| `tsa_max_reply_bytes` | 64 KiB | Larger replies are refused (real ones are a few KB). |
| `tsa_retry_attempts` / `tsa_retry_backoff_secs` / `tsa_retry_backoff_max_secs` | 3 / 2s / 30s | Retries per PENDING case, waiting 2s, 4s, … up to 30s. |
| `tsa_batch_stop_after_unavailable` | 3 | Cases in a row finding the TSA down before the rest of the run is skipped. |
| `allow_offline_fallback` | true | If the TSA is unreachable the seal stays `PENDING` and is retried; a timestamp is never faked. |
| `evidence_store_dir` / `db_path` | `evidence_store`, `evidence_store/netforensics.sqlite` | Where blobs and the database live (git-ignored). |

A threshold is a judgment call, not a fact. Every finding prints the measured value next
to the cutoff, so a reviewer can disagree with the cutoff and still see the data.

---

## 8. Evidence storage: SQLite and content-addressed files

_Issue #2, PR #13._

**What it does.** Keeps every case on disk so nothing about it can be quietly changed: the
case, seal, findings, custody log and the uploaded pcap.

**Key ideas.** *SQLite*: a database in one file. *Trigger*: a rule inside the database that
runs before a change; ours cancel it. *Append-only*: rows can be added, never edited or
deleted. *Content-addressed*: a file is stored under its own fingerprint, so the name proves
what the content must be.

**Steps.**
1. The upload is streamed into `evidence_store/staging/<case_id>/` and size-capped, then
   sealed and analysed.
2. The store re-computes the staged file's SHA-256 and refuses if it does not equal the name
   it is about to be stored under.
3. The file is linked to `evidence_store/blobs/<sha256>` and made read-only. If that blob
   already exists (same evidence twice), the existing one is re-hashed first and the store
   refuses loudly if it was altered.
4. Case, seal and findings go into SQLite in one transaction (all or nothing).
5. Triggers refuse every UPDATE and DELETE, and any INSERT whose key already exists (this
   closes `INSERT OR REPLACE`, which would delete and rewrite a row without firing the
   delete trigger). The one allowed change: a seal's timestamp going from PENDING to
   GRANTED once, with a non-empty token.

**Example.** The 10 bytes `pcap-bytes` have SHA-256 `ee93…` and are stored at `blobs/ee93…`.
Someone edits the file to `Pcap-bytes`; its SHA-256 is now completely different, so
`hash_file(blob).sha256_hex != blob.name`, and re-uploading the original bytes gets HTTP 409
"the stored copy was altered" instead of silently trusting the old file.

**Limits.**
- Triggers stop mistakes in *our code*. Someone who can write the `.sqlite` file can drop a
  trigger or edit bytes; the custody chain (#10) and anchoring its head with a trusted
  timestamp (#12) catch that.
- The custody log here only checks entries arrive in order (0, 1, 2…), not the hash links,
  so a broken link stays visible instead of hidden.

---

## 9. Trusted-timestamp transport and retry

_Issue #3, PR #14._

**What it does.** Sends the seal's fingerprint to an outside Timestamp Authority and stores
the signed reply, without a slow or missing connection ever breaking an upload or producing
a fake timestamp.

**Key ideas.** *RFC 3161*: the standard for trusted timestamps; a *TSA* (we use freetsa.org)
signs "I saw this hash at time T" and returns a *token*. As a third party, it cannot be
back-dated by us. *PENDING / GRANTED*: waiting for a token / holding one. *Exponential
backoff*: waiting longer after each failure. *Circuit breaker*: after several failures in a
row, stop for now.

**Steps.**
1. `request_timestamp` POSTs the request to the TSA in a background worker; the caller waits
   at most `tsa_timeout_secs` in total and reads the reply under a 64 KiB cap. Timeout,
   connection or DNS failure, non-200 status, or an oversized or empty reply raises
   `TsaUnavailableError`. It never retries itself.
2. On upload the API makes **one** attempt; on failure the case is still stored with the seal
   PENDING. The upload never fails because of the TSA.
3. `retry_all_pending` walks every PENDING case with up to `tsa_retry_attempts` tries and
   backoff. A token is stored through the database's one-time PENDING → GRANTED rule; a
   lost race is "already granted", an empty token is refused.
4. After `tsa_batch_stop_after_unavailable` cases in a row find the TSA down, the rest of
   the run is skipped and left PENDING.

**Example: backoff and breaker.** 3 attempts, base 2s, cap 30s: wait min(2·2⁰, 30) = 2s after
failure 1, min(2·2¹, 30) = 4s after failure 2, none after attempt 3. One case costs at most
2 + 4 = 6s of waiting plus 3 deadlines (3 × 5s = 15s), about 21s. With the TSA down and 100
PENDING cases, the breaker stops after 3 cases (~63s) instead of ~35 minutes.

**Example: the total deadline.** httpx's timeout counts per network read, so a server
dripping 1 byte every 0.5s would never trip a 5s read timeout. Running the whole request in
a worker with one total deadline fixes it: with `tsa_timeout_secs = 2`, Pam's body-drip test
stops at 2.0s instead of 49.9s, and her header-drip test at 2.0s instead of running past 70s.

**Limits.**
- This code moves bytes; it does **not** check the token (signature, certificate chain, that
  it covers *our* hash, its time). That is `timestamp.py` (#11) and `verify.py` (#12); until
  #11 lands no timestamper is wired in and every seal stays PENDING.
- HTTP redirects are not followed (a 307 counts as "unavailable"): the TSA URL is fixed
  configuration.

---

## 10. Custody hash chain

_Issue #10, PR #19 (core; human review)._

**What it does.** Turns the custody log (ingest, parse, each finding, report…) into a chain
where changing, removing, inserting or reordering any entry is detectable, and reports the
first entry where it breaks and why.

**Key ideas.** *Hash chain*: each entry stores the previous entry's hash and its own hash
covers that, so entries are linked. *Genesis*: entry 0 links to a hash of the evidence seal
instead of an earlier entry. *Canonical form*: one agreed way to turn an entry into bytes, so
writer and checker hash the same thing. *Domain separation*: a fixed label in front
(`custody-entry/v1` vs `custody-genesis/v1`) so two uses of the hash can never be confused.

**Steps.**
1. Genesis: hash the seal's BLAKE3 and SHA-256 digests, size, filename and received-at time
   → `G`. Entry 0's `prev_hash` is `G`.
2. Each new entry gets `index = previous + 1` and `prev_hash = previous entry's hash`.
3. An entry's hash = SHA-256 of the label, a zero byte, then the entry as compact JSON with
   sorted keys (every field except the hash). Times are UTC with 6 decimal places; decimal
   numbers are refused (store `"4.2"` as text).
4. To verify, walk from entry 0: right index and case? Does `prev_hash` equal `G` (entry 0) or
   the previous hash? Does recomputing give the stored hash? The first "no" is reported with
   its index and the two hashes.

**Example** (first 12 hex chars; test seal `capture.pcap`, 1234 bytes, received 2026-10-20
12:00:00 UTC).
- `G` = `f3504c93b047…`
- Entry 0 "Sealed capture.pcap": `prev_hash = f3504c93b047…`, hash `3c7536eb3105…`
- Entry 1 "C2 beacon 10.0.0.5 → 203.0.113.7": `prev_hash = 3c7536eb3105…`, hash `8f9bdacece85…`

Someone edits entry 0's text to "Sealed other.pcap": recomputing gives `bd2c71d847e2…`, not the
stored `3c7536eb3105…` → "entry 0 was altered". If they also overwrite the stored hash with
`bd2c71d847e2…`, entry 1's `prev_hash` no longer matches → "entry 1 does not link to entry 0".
To hide the edit they must rewrite every later entry too. `G` can be reproduced with
`printf | shasum -a 256` (exact command in PR #19).

**Limits.**
- Deleting the **last** entries leaves a shorter chain that is still valid.
- There is no secret: someone with database write access can rewrite an entry and recompute
  every later hash, and it verifies.
- Both are closed by #12: an outside TSA signs the newest entry's hash, so a shorter or
  recomputed chain no longer matches what was signed.

---

## 11. The command-line tool

_Issue #4, part 1 (`seal`, `analyze`, `retry-timestamps`)._

**What it does.** Runs the evidence layer from a terminal, no web app:
`python -m backend.cli [--store DIR] <command>` (`--store DIR` keeps blobs and database
under `DIR` instead of `evidence_store/`).
- `seal <pcap>` / `analyze <pcap>`: the same intake as a web upload (`backend/intake.py`):
  copy the file into staging (your original is only read), check it is a pcap, seal,
  analyse, store. `seal` prints the case id, both hashes and the timestamp status;
  `analyze` also prints every finding with its evidence line. Both analyse, because a
  stored case cannot get findings added later.
- `retry-timestamps`: retries PENDING seals (section 9).
- `verify`, `tamper-demo`: listed, but say "not built yet" until #12.

**Key concept: the exit code**, a number a program returns when it ends, read by scripts
instead of the text. 0 = success, 1 = error (one `error:` line), 2 = seals still PENDING
after `retry-timestamps` (or a mistyped command), 3 = not built yet. `verify` will use
0 = INTACT, 1 = ALTERED, 2 = INCOMPLETE. `--help` prints this table.

**Example.** `analyze` on the 12-packet test capture (one connection every 60 s):

```
File       beacon.pcap (864 bytes)
SHA-256    e21071f3b192d0eee832c401d44ad446ef7e47e2c62748f7ed53c4a1d5c7f76f
Timestamp  PENDING (retry later: python -m backend.cli retry-timestamps)
Flows      12
[MEDIUM] c2_beacon: 10.0.0.5 -> 203.0.113.7
```

12 packets with different source ports make 12 flows; the gaps are all 60 s, so their
spread is 0 and the coefficient of variation is 0 ÷ 60 = 0.000, under the 0.1 cutoff
(section 4). Exit code 0.

**Limits.** No `verify` / `tamper-demo` yet (needs #12). The CLI passes no timestamper yet,
so seals stay PENDING from the CLI. Same 512 MiB limit as uploads. No custody entry is
written at intake yet. Plain text only, no colour.

---

## 12. Not built yet

Listed so nobody mistakes a plan for a feature. Each gets its own section above when it
lands.

- **Custody log wired into uploads:** the chain logic exists (section 10) but the API does
  not append entries yet.
- **RFC 3161 token building and checking:** transport and retry are built (section 9);
  building the request and checking the token is #11, so seals stay `PENDING` until then.
- **Case verification and the tamper demo:** re-hash the stored file, compare to the seal,
  walk the chain. The 10-second flip-one-byte demonstration. The CLI already lists
  `verify` and `tamper-demo` (section 11).
- **JA3 fingerprinting (4th detector):** deferred; approved design in section 13.

---

## 13. JA3 fingerprinting (approved design, not built)

_Human approved the design on 2026-10-22. Built one function at a time, each reviewed
before the next. No JA3 code exists yet._

**What it does.** Gives each program that opens a TLS (HTTPS encryption) connection a short
ID and flags IDs found on a malware list. Nothing is decrypted.

**Key concept.** A TLS connection starts with a plain-text *ClientHello* listing what the
program supports: version, encryption recipes (*cipher suites*), optional features
(*extensions*), *curves* and *point formats*. That list comes from the program's TLS
library, so it works like handwriting. JA3 joins the five fields as decimal numbers in wire
order (`-` inside a field, `,` between fields) and takes the MD5 (text in, fixed 32-hex-digit
label out). *GREASE* values (`0x0a0a`, `0x1a1a` ... `0xfafa`) are random fillers that
modern clients vary per connection, so they are dropped first.

**Worked example.**

| Field | On the wire | After dropping GREASE |
|---|---|---|
| Version | 771 | 771 |
| Ciphers | 2570, 4865, 4866, 49195 | 4865-4866-49195 |
| Extensions | 2570, 0, 23, 65281, 10, 11 | 0-23-65281-10-11 |
| Curves | 6682, 29, 23, 24 | 29-23-24 |
| Point formats | 0 | 0 |

String `771,4865-4866-49195,0-23-65281-10-11,29-23-24,0` has MD5
`d513a2c384da97e772fef72dfe6d8276` (computed with Python `hashlib`).

**Decisions (2026-10-22).** Parse with `dpkt`, no `tshark`. Match against the abuse.ch
SSLBL list as a local file; the detector never uses the network. Severity always `MEDIUM`;
the evidence states the list's age, and the evidence layer records its hash and download date.

**Limits.**
- The SSLBL JA3 list was last updated 2021-08-03 (under 100 entries) and its own site warns
  of false alarms. A match is a lead, not proof.
- Programs can share an ID; malware can copy a browser's. Chrome shuffles extension order
  (since about 2023); JA4, which sorts them, is the successor, not in scope.
- ClientHellos split over several TCP packets are missed (no TCP reassembly); QUIC is invisible.

---

## 14. Decisions log

The human approved every recommendation in the former "Open questions" section on
2026-10-22. Recorded here as a log; background lives in the linked PRs and sections.

| Q | Topic | Decision (all: "Approved: recommendation (2026-10-22)") |
|---|---|---|
| A | Custody chain, PR #19 | Option 1: approve all five choices and merge #19. The choices: SHA-256 for the chain (pinned in code, not config); hash a canonical JSON form of each entry; refuse floats (store `"4.2"` as text); no Unicode normalisation; an empty log counts as broken. Pam's hard test: 9,218 random corruptions, all caught at the exact entry. Fixes landed at `e602d8d` (169 tests): algorithm and tags pinned in code, nesting depth capped at 32, a seal time with no timezone reported as a break. |
| B | DNS non-text bytes, PR #18 | Option 3: keep escaping now (`0xE4` becomes `\xe4`), switch to raw bytes as a follow-up. On `dns-iodine.pcap` the longest label is 55 bytes raw but 193 characters escaped, and entropy 5.74 raw vs 3.43 escaped, so errors lean toward missing a tunnel. It still fires HIGH (another label reaches 4.81). |
| C | JA3, section 13 | (1) Use the 2021 SSLBL list and state its age in every finding. (2) dpkt only, plus a one-time comparison with Wireshark on your own browser capture. (3) Accept missing split ClientHellos; no TCP reassembly. (4) Always MEDIUM. (5) Seal the blocklist's hash and download date with the case. |
| D | Threshold tuning | Option 2: tune later, in Phase 4, then record reasons in `logic.md` and here. Known weak spots: DNS needs 19+ characters; a paced scan also trips the beacon detector; jitter evades beacons (gaps `60, 63, 57, 66, 54, 61, 59, 64, 56` give CV 0.066 and fire; gaps `42, 78, 51, 66, 45, 72, 58, 63, 84, 55` give CV 0.226 and do not). |
| E | SSDP false positive, issue #17 | Option 2: a CIDR allowlist in config, defaulting to multicast and broadcast (`224.0.0.0/4` covers `239.255.255.250`); suppressed traffic is recorded, not silently dropped. Acceptance: `ctu-185-1` (192.168.1.2 to 239.255.255.250 every 120 s, CV 0.000) stops firing; `ctu-130-1` (6,949 connections about every 9 s, CV 0.020) still fires; a unit test shows even-timed traffic to multicast is skipped and to a normal address fires. |
| F | Evidence wording | Option 1, in two steps. Step 1, docs only: replace "court-admissible" with "tamper-evident, designed toward admissibility" (done; handoff risk #3 closed). Step 2, core code: one fixed sentence template (what was measured, the value, the cutoff, the plain-language meaning). |
| G | How to build next pieces | Recommendation approved: option 1 for D, E and F (Jim builds, explains before each change, you approve each PR before merge); option 2 (line-by-line pairing) for the JA3 build. Core PRs merge only after human approval, relayed via god. |
| H | Start #11 while #19 is under review? | Option 2: Jim may write #11 now; you review one PR at a time, #19 first. |
| I | Anchoring the chain head, issue #12 | Information only, no decision. A chain cannot show that the last entries were cut off (delete entries 8 and 9 of 10 and the remaining 8 still verify). The fix is to have a TSA sign the head and keep the signed copy outside the database. Jim will recommend options when he reaches #12. |
