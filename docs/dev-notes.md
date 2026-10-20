# Dev Notes

Written for the human who owns this project, not for a machine. Each section covers one
piece of what is built: what it does, how it works step by step, the concepts it leans
on (explained in plain language), a worked example with real numbers, and its limits.

**Standing rule (2026-10-20):** every PR that builds something adds or updates its section
here. See [`../CLAUDE.md`](../CLAUDE.md) "Dev notes". Design rules live in
[`logic.md`](logic.md) and structure in [`architecture.md`](architecture.md); this file is
the explanation layer on top of them. Where this file and the code disagree, the code
wins, so say so in a PR.

Numbers in the worked examples were computed with the project's own code (or plain
arithmetic shown in the text), not estimated.

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
10. [The command-line tool](#10-the-command-line-tool)
11. [Not built yet](#11-not-built-yet)
12. [JA3 fingerprinting (proposed)](#12-ja3-fingerprinting-proposed)
13. [Open questions for Garv](#13-open-questions-for-garv)

## Words used throughout

| Term | One-line meaning |
|---|---|
| pcap | A file holding packets recorded off a network (a "packet capture"). |
| Packet | One small chunk of data sent over a network, with source and destination addresses. |
| IP address | The network address of a machine, such as `10.0.0.5`. |
| Port | A number (0-65535) that picks which program on a machine a packet is for. Web is usually 443, DNS is 53. |
| TCP / UDP | Two ways of sending packets. TCP sets up a connection first (a "handshake"); UDP just sends. |
| DNS | The internet's phone book: turns names like `example.com` into IP addresses. |
| Finding | One thing a detector reports, with the numbers that triggered it. |
| Severity | `HIGH` or `MEDIUM` (also `LOW`, `INFO`, unused so far). A rule label, not a score. |

---

## 1. The pipeline: upload to report

**What it does.** Takes one `.pcap` file from a user and produces a case: a sealed record
of the file plus a list of findings, viewable as JSON and as a PDF.

**How it works, step by step.**

1. **Upload** (`POST /api/cases`, `backend/api/app.py`, or `python -m backend.cli analyze`,
   section 10; both go through `backend/intake.py`). The file is written to disk in
   1 MiB chunks, never held whole in memory. If it passes 512 MiB the upload is cut off and
   the user gets HTTP 413 ("too large").
2. **Validate** (`backend/ingest/pcap_validation.py`). The first 4 bytes of a pcap file are
   a fixed "magic number" that says what kind of file it is. We check those. A newer format
   called pcapng is recognised and refused with a specific message; anything else that is
   not a pcap is refused too (HTTP 400). Refusing early means bad input never reaches the
   evidence or the detectors.
3. **Seal** (`backend/evidence/seal.py`). Before anything reads the packets, the file is
   hashed (section 6). This is deliberately first: the fingerprint describes the file
   exactly as received.
4. **Parse** (`backend/parse/`). Two passes over the file with the `dpkt` library: one
   builds DNS summaries (section 3), one builds connection records, called flows
   (section 2).
5. **Detect** (`backend/detectors/`). Three detectors run: DNS exfiltration reads the DNS
   summaries; C2 beaconing and port scan read the flows. Each returns findings.
6. **Sort and package.** Findings are sorted most severe first and bundled with the seal
   into a `CaseRecord`.
7. **Save.** The pcap moves from `evidence_store/staging/<case id>/` to
   `evidence_store/blobs/<sha256>` (read-only, re-hashed on the way in), and the case,
   seal and findings go into the append-only SQLite database (section 8). The case id
   is a random 32-character hex string and is checked against that exact pattern on
   every read, so a crafted id like `../x` cannot reach other folders.
8. **Report.** `GET /api/cases/<id>/report.pdf` renders the saved record to a PDF. It reads
   only the record and never re-reads the pcap.

**Concepts.**
- *Data flows one way.* Each stage only receives what the one before produced. Parsing
  never touches storage; detectors never touch HTTP; the PDF never re-parses. This keeps
  each part easy to test and easy to explain.
- *No machine learning.* Every detector is a fixed rule with a number you can check by
  hand. That is a deliberate choice for evidence: "this value is 4.4 where normal is 2.5"
  can be defended; "the model flagged it" cannot.

**Limits.**
- The pcap is read twice (once for DNS, once for flows). Fine for small captures; worth
  merging into one pass if big captures matter.
- Only classic pcap, Ethernet, IPv4, TCP and UDP. No pcapng, no IPv6, no live capture.
- The database refuses edits made through normal SQL, but someone with write access to
  the database file can still change it. Proving nothing changed needs the custody
  chain and its timestamped head (section 11).
- The PDF is minimal; it will grow once the custody chain exists.

---

## 2. Flows: how packets become connections

**What it does.** Turns thousands of individual packets into one record per conversation
(a *flow*), because the detectors reason about conversations, not packets.

**How it works.**

1. Every packet is decoded (`dpkt`). Anything that is not Ethernet + IPv4 + TCP or UDP is
   skipped quietly, since real captures are full of noise.
2. Each packet gets a **direction-independent key**: its two endpoints (IP and port each)
   plus TCP/UDP, sorted. A packet from A to B and the reply from B to A produce the same
   key, so both land in the same flow.
3. The first packet seen for a key starts a flow. Later packets with that key add to its
   packet count and byte count and move its end time forward.
4. **Splitting TCP flows:** if a packet is a TCP "SYN" (the opening move of a new
   handshake: SYN flag set, ACK flag not set) and a flow with that key is already open, the
   old flow is closed and a new one starts. This is how a client that reconnects from the
   same port becomes two connections, not one.
5. **Who is the source?** The flow's `src_ip` is whoever sent the *first* packet (the
   initiator). Replies do not count as new flows.

**Why orientation matters, with an example.** Machine S scans machine T on 3 ports. T
replies on each. If replies became their own flows, T would also look like it contacted S
on 3 different ports, and a scan detector could blame the victim. Because both directions
fold into the initiator's flow, only S is the source.

**Limits.**
- UDP has no handshake, so a UDP conversation that reuses the same endpoints stays a single
  flow forever (no idle timeout).
- If a capture begins mid-conversation, the first packet seen might be a reply, and the
  initiator will be guessed wrong.
- The flow parser leaves `inter_arrival_times` empty; the C2 detector computes gaps itself
  from flow start times.

---

## 3. DNS exfiltration detector

**What it does.** Flags a host that appears to be smuggling data out inside DNS lookups.

**The idea.** DNS lookups are usually allowed through firewalls. A malicious program can
hide data in the lookup name itself: to send the text `secret`, it encodes it into letters
and looks up `onswg4tf.evil.example`. The attacker's DNS server for `evil.example` reads
the name and recovers the data. Encoded data looks random, and it tends to be long and
frequent. Those three traits are what we measure.

**Parts of a name.** In `a8f3k.evil.example`, the *parent domain* is the last two labels
(`evil.example`) and the *subdomain* is the rest (`a8f3k`).

**How it works, step by step** (`parse/dns_parser.py`, `detectors/dns_exfil.py`).

1. Collect every DNS question sent to UDP port 53.
2. Group by (source IP, parent domain): one host's lookups against one parent domain.
3. For each group compute: the highest *Shannon entropy* of any subdomain, the longest
   subdomain length, and the number of queries. Lookups with no subdomain (just
   `evil.example`) count as queries but are left out of the entropy and length numbers.
4. Skip any group whose parent domain is on the allowlist (CDN and cloud names that
   legitimately look random: `cloudfront.net`, `akamaihd.net`, `googleusercontent.com`,
   `amazonaws.com`). The match is anchored on a dot, so `evilcloudfront.net` is **not**
   treated as `cloudfront.net`.
5. **Entropy is required.** If the top entropy is under 4.2, stop. No finding.
6. Compute the query rate (below). Then check two supporting signals:
   *length* (longest subdomain at least 30 characters) and *rate* (at least 50 queries per
   60 seconds).
7. Entropy plus at least one of the two = a finding. `HIGH` if **both** support it,
   `MEDIUM` if only one does. Length alone never fires, because real CDN hostnames can be
   long.

**Concept: Shannon entropy** (`parse/entropy.py`). A measure, in "bits per character", of
how unpredictable a string's characters are. The formula: for each distinct character,
take its share `p` of the string, then add up `-p × log2(p)`. (`log2(p)` answers "2 to what
power gives p?". For p = 1/2 it is -1, so a character that is half the string contributes
0.5 bits.) A string of one repeated letter scores 0. A string where every character is
different scores `log2(length)`, which is the maximum possible.

**Worked example 1: why `google` scores low.** `google` has 6 characters: g ×2, o ×2,
l ×1, e ×1.

| Character | Count | p = count/6 | -p × log2(p) |
|---|---|---|---|
| g | 2 | 0.3333 | 0.5283 |
| o | 2 | 0.3333 | 0.5283 |
| l | 1 | 0.1667 | 0.4308 |
| e | 1 | 0.1667 | 0.4308 |
| **Total** | | | **1.918** |

Repeated letters make it predictable, so it scores about 1.9. Other values from the code:
`www` = 0.0, `aaaaaaaa` = 0.0, `abcdefgh` (8 different letters) = 3.0 = `log2(8)`.

**Worked example 2: an encoded blob scores high.** Encoding the made-up text
`ssn=123-45-6789;card=4111` in base32 (an encoding that turns bytes into the letters a-z
and digits 2-7) and lowercasing gives this 40-character subdomain:

`onzw4pjrgizs2nbvfu3doobzhnrwc4tehu2dcmjr`

It has 23 distinct characters, none appearing more than 3 times. Its entropy is **4.396**
(the maximum possible for 40 characters would be `log2(40)` = 5.32). That is above the
4.2 threshold and far above the ~2.5 the project treats as the benign level.

**Worked example 3: the rate.** The rate is the query count scaled to a 60-second window:
`count ÷ seconds the group spans × 60`. If 200 queries span 30 seconds, rate =
200 ÷ 30 × 60 = 400 per window, well over 50. If the group spans zero seconds (one query,
or identical timestamps) the raw count is used as the rate instead, since you cannot divide
by zero. So the blob above, seen in 200 queries over 30 s, gets entropy 4.396 (pass), length
40 ≥ 30 (hit), rate 400 ≥ 50 (hit): both support it, so `HIGH`.

**What the investigator sees.** The finding carries a sentence such as: "Subdomain
'onzw4p…' of 'evil.example' has Shannon entropy 4.40 (benign baseline ~2.5), length 40
chars, with 200 queries in 60s (~400/window) — consistent with data encoded into DNS
queries." The same numbers are stored next to their thresholds.

**Limits.**
- **Short names can never reach 4.2.** Entropy tops out at `log2(length)`, and
  `log2(19)` = 4.25, so a subdomain needs at least 19 characters to *possibly* score over
  4.2. Our 20-character base32 sample `nbswy3dpeb3w64tmmqqq` scores only 3.684 and would be
  missed. Real encoders that use short labels slip through. Tune against real captures.
- The entropy is measured over the whole subdomain text, dots included, not per label.
- The parent-domain split takes the last two labels, so `foo.co.uk` is read as parent
  `co.uk`. No public-suffix list yet.
- UDP port 53 only; DNS over TCP and DNS-over-HTTPS are out of scope.
- A DNS tunnel that sends few, short queries stays under every limit.
- A CDN not on the allowlist can false-alarm; the human reviews every finding.

---

## 4. C2 beaconing detector

**What it does.** Flags a machine that contacts another machine at suspiciously even
intervals, as malware does when it "phones home" to a command-and-control (C2) server to
ask for instructions.

**The idea.** Software on a timer connects every N seconds. People do not behave like that:
a person's activity comes in bursts and pauses. So we measure how *regular* the gaps are.

**Concepts, in the order the detector uses them.**
- **Inter-arrival time (IAT):** the gap in seconds between one connection and the next.
  With N connections there are N-1 gaps.
- **Mean:** the average gap (sum of gaps ÷ count).
- **Standard deviation:** roughly the typical distance of a gap from the mean. Small means
  gaps are all close to the mean. The code uses the *sample* version: square each gap's
  distance from the mean, add them up, divide by (count - 1), take the square root. It
  divides by one less because we only observed part of the machine's behaviour, not its
  whole life.
- **Coefficient of variation (CV):** standard deviation ÷ mean. Dividing by the mean makes
  the result comparable across beacon speeds: a 60-second beacon wobbling by 2 s and a
  10-minute beacon wobbling by 20 s have the same CV (about 0.03). A CV near 0 is robotic.

**How it works, step by step** (`detectors/c2_beacon.py`).

1. Group flows by (source IP, destination IP). The destination *port* is ignored on purpose,
   so a beacon that changes ports is still caught.
2. Skip any destination on the allowlist (known-good heartbeats; empty for now).
3. Need at least 10 connections in the group, otherwise stop: with fewer, "regular" is not
   meaningful.
4. Sort the connection start times, take the gaps between neighbours.
5. Compute CV. If every connection has the same timestamp (mean 0) or there are fewer than
   2 gaps, CV is "not computable" and the group is skipped, not flagged.
6. If CV is 0.1 or less, report a finding. Severity is always `MEDIUM`.

**Worked example (a beacon).** 10 connections give 9 gaps, in seconds:
`60, 61, 59, 60, 62, 58, 60, 61, 59`.
- Mean = 540 ÷ 9 = **60**.
- Distances from the mean: 0, 1, -1, 0, 2, -2, 0, 1, -1. Squared: 0, 1, 1, 0, 4, 4, 0, 1, 1.
  Sum = 12.
- Sample variance = 12 ÷ (9 - 1) = 1.5. Standard deviation = √1.5 = **1.2247**.
- CV = 1.2247 ÷ 60 = **0.0204**. That is under 0.1, so it fires.

**Worked example (a human).** Gaps: `3, 45, 2, 120, 8, 300, 15, 1, 60`. Mean 61.56 (close to
the beacon's 60), standard deviation 97.61, CV = **1.586**. Same average gap, completely
different shape. It does not fire.

**What the investigator sees.** "Host A contacted B every ~60s (±1.2s) over 10 connections
(coefficient of variation 0.020, threshold 0.1) — robotic regularity characteristic of C2
beaconing, not human traffic."

**Limits.**
- **Adaptive malware beats it.** Malware that adds random "jitter" to its timer can push
  CV above 0.1 deliberately. This catches the common case, not a determined adversary.
- Only one signal exists, so there is nothing to corroborate it: severity is always
  `MEDIUM`.
- Legitimate automation (software update checks, monitoring agents, NTP) is also regular
  and can false-alarm. The allowlist is the tool for that and is empty today.
- Other detectors can overlap: a scan whose probes are perfectly evenly spaced also has CV
  near 0 and trips this detector too.
- Needs 10 connections; slow beacons in a short capture will not reach that.

---

## 5. Port-scan detector

**What it does.** Flags one machine that touches an unusually large number of different
ports or hosts in a short time, which is what a scanner does when it hunts for open doors.

**The idea.** Normal use touches a few destinations. A scanner knocks on hundreds of ports
(a *vertical* scan, one target) or the same port across many machines (a *horizontal*
scan). We count distinct destinations in a sliding time window.

**How it works, step by step** (`detectors/port_scan.py`).

1. Group flows by source IP.
2. Sort that source's flows by start time.
3. Slide a 10-second window along them. Two counters track how many flows in the window
   hit each destination port and each destination host; the number of distinct keys is the
   fan-out.
4. For each new flow, add it to the window, then drop flows from the left while they are
   more than 10 seconds older than the new flow. Each flow enters and leaves once, so the
   work grows in step with the number of flows.
5. Remember the highest port count and the highest host count seen at any moment. The two
   peaks are tracked separately because they can happen at different times.
6. Fire if ports ≥ 100 **or** hosts ≥ 10. `HIGH` if both, `MEDIUM` if one.

**Worked example (the window moving).** One source makes four connections:

| Time (s) | Port | Host |
|---|---|---|
| 0 | 22 | A |
| 2 | 80 | A |
| 4 | 443 | B |
| 11 | 8080 | A |

At t=4 the window holds all three flows seen so far: distinct ports 22, 80, 443 = 3,
distinct hosts A, B = 2. At t=11 the flow at t=0 is 11 s old, over the 10 s limit, so it is
dropped; the flow at t=2 is 9 s old and stays. Now ports 80, 443, 8080 = 3 and hosts
A, B = 2. Peak is 3 ports and 2 hosts, far under 100 and 10, so no finding. A scanner
touching 850 ports in 8 seconds would reach 850 and fire `MEDIUM` (hosts under 10), or
`HIGH` if it also hit 10 or more hosts.

**Limits.**
- Fixed cutoffs (100 ports, 10 hosts) are proposed values, not tuned on real traffic.
- A slow scan, say one port per minute, never fills a 10-second window and is invisible.
- A busy legitimate machine (a load balancer, a monitoring server, a crawler) can contact
  many hosts quickly and false-alarm.
- Scanners that spread across many source addresses look like many small sources.
- It counts connection attempts that appear in the capture; it cannot say whether a scan
  succeeded.

---

## 6. The seal: hashing the evidence

**What it does.** Records a fingerprint of the uploaded pcap at the moment it arrives, so
anyone can later prove the file has not changed since.

**Concept: a hash.** A hash function reads any amount of data and outputs a fixed-length
fingerprint (here 64 hexadecimal characters). Same input, same fingerprint, always. Change
any one byte of input and the fingerprint changes completely and unpredictably. You cannot
work backwards from a fingerprint to the data, and in practice you cannot craft a second
file with the same fingerprint.

**Worked example.** Real hashes of the 12-byte text `NetForensics`, and of
`NetForensicS` (last letter capitalised, one character different):

| Input | SHA-256 |
|---|---|
| `NetForensics` | `bff91908…26c4e9a` (full: `bff919082f1b3d4c1d5ab0f296b19bc3667244834c46e1c0cb9e236ea26c4e9a`) |
| `NetForensicS` | `bcf28f3b…67374fe` (full: `bcf28f3b2b82a0859a2e99d2ecdad33ec0482b01fd20e7efddca897ec67374fe`) |

One letter changed, and the two fingerprints share nothing recognisable. BLAKE3 behaves the
same way (`NetForensics` gives `0f342397e9221289626886c668929dfbeffc89f683ce12573281a4def777152f`).
This is why flipping a single byte of a sealed pcap is detectable.

**How the seal works, step by step** (`evidence/seal.py`).

1. Note the time received, in UTC (local time is ambiguous). It is taken *before* hashing,
   because custody begins when handling begins, not when a large hash finishes.
2. Read the file in 1 MiB chunks and feed each chunk to **both** hash functions at once.
   Memory use stays flat no matter how big the capture is, and the file is read only once.
3. Store a `SealRecord`: filename, size in bytes, BLAKE3 hash, SHA-256 hash, received-at
   time, and a timestamp status of `PENDING`.

**Why two hashes (BLAKE3 + SHA-256).**
- **BLAKE3** is the primary fingerprint: a modern, fast hash.
- **SHA-256** is what an RFC 3161 trusted-timestamp authority signs and what standard tools
  like `openssl` and most courts recognise. Having it means the timestamp step (not built
  yet) can attest to the file with no conversion.
- (General reasoning, not recorded in the code: two independent algorithms are also a
  safety net. A flaw found in one does not invalidate the other.)

**Sealing and timestamping are separate on purpose.** Sealing is pure hashing and cannot
fail because the internet is down. The trusted timestamp, which proves *when* the hash
existed, is a later step. Until it happens the seal's status is `PENDING`.

**Limits.**
- A hash proves the file is unchanged **since it was sealed**. It says nothing about
  whether the file was genuine or complete when it was captured or uploaded.
- With no trusted timestamp yet, the seal's "received at" time is just our own clock. It
  does not prove the date to a third party.
- The hash is stored in the append-only database (section 8), which blocks edits through
  normal SQL, but a person with write access to the database file could still change it.
  Closing that gap is what the custody chain and its timestamped head are for (section 11).
- Hash-checking on re-open (verification) is not built yet; today the seal is only written.

---

## 7. Current thresholds and what they mean

All come from `backend/config.py`, the single place numbers live. "Proposed" means a
starting guess to be tuned on real captures; only the entropy values came from the
original proposal.

| Setting | Value | What it means |
|---|---|---|
| `benign_entropy_baseline` | 2.5 | Typical entropy of normal subdomains. Shown in evidence for contrast; not used to decide. |
| `entropy_threshold` | 4.2 | DNS subdomain entropy at or above this is required before a DNS finding. Needs a subdomain of 19+ characters to be reachable. |
| `subdomain_length_threshold` | 30 (proposed) | Longest subdomain of at least 30 characters counts as a supporting signal. |
| `query_rate_threshold` | 50 (proposed) | At least 50 queries to one parent domain per window counts as a supporting signal. |
| `query_rate_window_secs` | 60 | The window the rate is scaled to. |
| `min_connections` | 10 (proposed) | A host pair needs 10 connections before beaconing is judged. |
| `max_coefficient_of_variation` | 0.1 (proposed) | Timing spread, as a fraction of the mean, at or below which it counts as robotic. |
| `distinct_ports_threshold` | 100 (proposed) | Port-scan: this many different destination ports within the window. |
| `distinct_hosts_threshold` | 10 (proposed) | Port-scan: this many different destination hosts within the window. |
| `window_secs` | 10 (proposed) | Port-scan: the sliding window length in seconds. |
| `dns_parent_domains` allowlist | `cloudfront.net`, `akamaihd.net`, `googleusercontent.com`, `amazonaws.com` | Parent domains skipped by the DNS detector because they legitimately look random. |
| `beacon_dst_ips` allowlist | empty | Destination IPs skipped by the beacon detector. |
| `max_upload_bytes` | 512 MiB (proposed) | Larger uploads are rejected. |
| `upload_chunk_bytes` / `hash_chunk_bytes` | 1 MiB | Read and write size for streaming; keeps memory flat. |
| `hash_algorithm` | blake3 | Primary hash used in the seal. |
| `tsa_url` | `https://freetsa.org/tsr` | Free timestamp authority for RFC 3161 timestamps (transport built, section 9; token checking not built yet). |
| `tsa_timeout_secs` | 5 | Total deadline for one request to the authority, then it counts as unavailable. |
| `tsa_max_reply_bytes` | 64 KiB | Larger replies are refused (real ones are a few KB). |
| `tsa_retry_attempts` / `tsa_retry_backoff_secs` / `tsa_retry_backoff_max_secs` | 3 / 2s / 30s | Retries per PENDING case, waiting 2s, 4s, … up to 30s between tries. |
| `tsa_batch_stop_after_unavailable` | 3 | After this many cases in a row find the authority down, the rest of the run is skipped. |
| `allow_offline_fallback` | true | If the authority cannot be reached, the seal stays `PENDING` and is retried; a timestamp is never faked. |
| `evidence_store_dir` / `db_path` | `evidence_store`, `evidence_store/netforensics.sqlite` | Where evidence blobs and the SQLite database are kept (git-ignored). |

A threshold is a judgment call, not a fact. Because every finding prints the measured
value next to the cutoff, a reviewer can disagree with the cutoff and still see the data.

---

## 8. Evidence storage: SQLite and content-addressed files

_Issue #2, PR #13._

**What it does.** Keeps every case on disk so that nothing about it can be quietly
changed later: the case, its seal, its findings, its custody log, and the uploaded
pcap itself.

**Concepts, one line each.**
- *SQLite* — a database that lives in a single file; no server to run.
- *Trigger* — a rule stored inside the database that runs automatically before a
  change; ours cancel the change ("abort").
- *Append-only* — rows can be added, never edited or deleted.
- *Hash / digest* — a fixed-length fingerprint of some bytes (SHA-256 gives 64 hex
  characters). Change one byte and the fingerprint changes completely.
- *Content-addressed* — a file is stored under the name of its own fingerprint, so
  the name proves what the content must be.

**How it works, step by step.**
1. An upload is streamed into `evidence_store/staging/<case_id>/` (never held in
   memory in one piece) and size-capped.
2. It is sealed there (BLAKE3 + SHA-256 fingerprints, section 6), then analysed.
3. The store re-computes the SHA-256 of the staged file. If it does not equal the
   name it is about to be stored under, it refuses.
4. The file is linked to `evidence_store/blobs/<sha256>` and made read-only. If a
   blob with that name already exists (same evidence uploaded twice), the store
   re-hashes the *existing* blob first and refuses loudly if it was altered.
5. The case, seal and findings go into SQLite in one transaction (all or nothing).
6. Triggers refuse every UPDATE and DELETE, and refuse any INSERT whose key already
   exists (this closes `INSERT OR REPLACE`, which would otherwise delete-and-rewrite
   a row without firing the delete trigger). The only allowed change: a seal's
   timestamp going from PENDING to GRANTED once, with a non-empty token (a NULL or
   empty token is refused).

**Worked example.** The 10 bytes `pcap-bytes` have SHA-256
`ee93…` (64 hex chars). They are stored at `blobs/ee93…`. Someone edits the file to
`Pcap-bytes` (one letter). Its SHA-256 is now completely different, so
`hash_file(blob).sha256_hex != blob.name` — re-uploading the original bytes now gets
HTTP 409 "the stored copy was altered", instead of silently trusting the old file.

**Limits.**
- Triggers stop mistakes in *our code*. Someone who can write the `.sqlite` file can
  drop a trigger or edit bytes directly. Catching that is the job of the custody hash
  chain (#10) and anchoring its head with a trusted timestamp (#12).
- The custody log here only checks that entries arrive in order (0, 1, 2…); it does
  not check the hash links — that is verification's job, so a broken link stays
  visible instead of being hidden.

---

## 9. Trusted-timestamp transport and retry

_Issue #3, PR #14._

**What it does.** Sends the seal's fingerprint to an outside *Timestamp Authority*
and stores the signed reply, without ever letting a slow or missing internet
connection break an upload or produce a fake timestamp.

**Concepts, one line each.**
- *RFC 3161* — the internet standard for trusted timestamps: you send a hash, a
  Timestamp Authority (TSA) signs "I saw this hash at time T" and sends back a *token*.
- *TSA* — the outside service that signs; we use freetsa.org. Because it is a third
  party, we cannot back-date its clock.
- *DER* — the compact binary format RFC 3161 requests and replies are written in.
- *PENDING / GRANTED* — the seal's timestamp state: waiting for a token, or holding one.
- *Exponential backoff* — waiting longer after each failed try (2s, 4s, 8s…) so a
  struggling server is not hammered.
- *Circuit breaker* — after several failures in a row, stop trying for now instead
  of waiting on every remaining case.

**How it works, step by step.**
1. `request_timestamp` POSTs the request bytes to the TSA with the RFC 3161 content
   type, in a background worker that the caller waits on for at most a **total
   deadline** (`tsa_timeout_secs`), and reads the reply against a **size cap** (`tsa_max_reply_bytes`, 64 KiB; real
   replies are a few KB). Any timeout, connection or DNS failure, non-200 status,
   oversized or empty reply raises `TsaUnavailableError`. It never retries itself.
2. On upload the API makes **one** attempt. If it fails for any reason the case is
   still stored, with the seal PENDING; the upload never fails because of the TSA.
3. Later, `retry_all_pending` walks every PENDING case. For each it makes up to
   `tsa_retry_attempts` tries with backoff. A token is stored through the database's
   one-time PENDING → GRANTED rule. A lost race with another retry is reported as
   "already granted"; an empty token is refused and reported as an error.
4. If `tsa_batch_stop_after_unavailable` cases in a row find the TSA down, the rest
   of the run is skipped and left PENDING for next time.

**Worked example (backoff and breaker).** Defaults: 3 attempts, base 2s, cap 30s.
After failure 1 wait min(2·2⁰, 30) = 2s; after failure 2 wait min(2·2¹, 30) = 4s;
attempt 3 is the last, so no wait after it. One case costs at most 2 + 4 = 6s of
waiting plus 3 request deadlines (3 × 5s = 15s), so about 21s. With the TSA down
and 100 PENDING cases, the breaker stops after 3 cases (~63s) instead of ~35 minutes.

**Worked example (deadline).** httpx's timeout counts per network read, so a server
sending 1 byte every 0.5s — in the headers or the body — would never trip a 5s read
timeout. So the whole request runs in a background worker and the caller waits at
most `tsa_timeout_secs` in total, then gives up and closes the connection. With
`tsa_timeout_secs = 2`, Pam's body-drip test stops at 2.0s instead of 49.9s, and her
header-drip test stops at 2.0s instead of running past 70s.

**Limits.**
- This code moves bytes; it does **not** check the token. Checking the TSA's
  signature, certificate chain, that the token covers *our* hash, and its time is
  core work in `timestamp.py` (#11) and `verify.py` (#12). Until #11 lands, no
  timestamper is wired in and every seal stays PENDING.
- HTTP redirects are not followed (a 307 is treated as "unavailable"), on purpose:
  the TSA URL is fixed configuration.

---

## 10. The command-line tool

_Issue #4 (first part: `seal`, `analyze`, `retry-timestamps`)._

**What it does.** Lets you drive the evidence layer from a terminal, with no web server
or browser: hand it a pcap and it seals it, stores it as a case and prints the
fingerprints and findings. It is the base for the "flip one byte, watch verification
fail" demo, which needs the verifier (#12) before it can be added.

**Concepts, one line each.**
- *CLI (command-line interface)* — a program you run by typing its name and options in
  a terminal, such as `python -m backend.cli seal capture.pcap`.
- *Subcommand* — the verb after the program name (`seal`, `analyze`, ...), like `git commit`.
- *Exit code* — a number every program hands back when it ends. `0` means success;
  anything else means something went wrong. Scripts and CI read it instead of the text.
- *stdout / stderr* — a program's two output streams: normal results, and error
  messages. Results go to stdout so they can be saved to a file without errors mixed in.
- *TTY* — a real terminal window, as opposed to output piped into a file or another program.
- *Intake* — the shared path a pcap takes from "offered" to "stored case"
  (`backend/intake.py`). The web upload and the CLI both call it, so there is one way
  to seal and store evidence, not two that could drift apart.

**How it works, step by step.**
1. `python -m backend.cli [--store DIR] <command> ...` parses the command line with
   Python's built-in `argparse` (no new dependency). `--store DIR` puts the blobs and
   the database under `DIR` instead of `evidence_store/`, handy for a throwaway demo.
2. `seal <pcap>` and `analyze <pcap>` both run the full intake, exactly as an upload
   does: the file is opened **read-only** and copied into `staging/` in 1 MiB chunks;
   the copy is checked to be a real pcap; it is sealed (section 6), parsed and
   analysed; the copy moves to `blobs/<sha256>`; the case is saved (section 8). Your
   original file is never written to.
3. `seal` then prints the case id, size, BLAKE3, SHA-256, the time received and the
   timestamp status. `analyze` prints the same plus the flow count and every finding
   with its *Why* and *Evidence* lines.
4. Both run the whole analysis, not just the hash, because a case record is
   write-once: findings cannot be added to it later. The two differ only in what they print.
5. `retry-timestamps` walks every PENDING seal through the retry of section 9. Until
   #11 supplies a timestamper it only counts the PENDING cases and says why they stay
   that way. Nothing is faked.
6. `verify` and `tamper-demo` are listed so they can be found, but they say "not built
   yet (needs #10/#11/#12)" and exit with code 3.

**Exit codes.**

| Code | Meaning |
|---|---|
| 0 | Success (for `retry-timestamps`: nothing left PENDING) |
| 1 | Error: missing file, not a pcap, too large, stored blob corrupt; one `error:` line on stderr |
| 2 | `retry-timestamps` left at least one seal PENDING; also argparse's usage error |
| 3 | Command not built yet (`verify`, `tamper-demo`) |

When `verify` lands it adds its own meaning: 0 = INTACT, 1 = ALTERED, 2 = INCOMPLETE.

**Worked example.** A 12-packet test capture, one connection attempt every 60 seconds
(the fixture the tests use), run with `analyze`:

```
Case       c2b6b129754f4145bc33f97b013ad4ec
File       beacon.pcap (864 bytes)
BLAKE3     18cbdf6a74320b84f4b3516cab850f8ab17d97af704819db858575e7ddf73688
SHA-256    e21071f3b192d0eee832c401d44ad446ef7e47e2c62748f7ed53c4a1d5c7f76f
Received   2026-10-20T08:56:08.601423+00:00
Timestamp  PENDING (retry later: python -m backend.cli retry-timestamps)
Flows      12
Findings   1

[MEDIUM] c2_beacon: 10.0.0.5 -> 203.0.113.7
  Why       Connection timing is far more regular than human-driven traffic — ...
  Evidence  Host 10.0.0.5 contacted 203.0.113.7 every ~60s (±0.0s) over 12 connections
            (coefficient of variation 0.000, threshold 0.1) — ...
```

The numbers, checked: the file is 864 bytes, so it is copied in one read
(864 < 1 MiB = 1,048,576 bytes) and is far under the 512 MiB limit
(536,870,912 bytes). Each of the 12 SYN packets starts a new connection, so there are
12 flows. The gaps are exactly 60 s each, so their standard deviation is 0 and the
coefficient of variation is 0 ÷ 60 = 0.000, under the 0.1 threshold (section 4). The
evidence file now lives at `blobs/e21071f3…` (its SHA-256), and the exit code is 0.

**Limits.**
- No `verify` or `tamper-demo` yet: both need the custody chain (#10), the timestamp
  check (#11) and case verification (#12). They come in a follow-up PR on #4.
- `retry-timestamps` cannot obtain timestamps until #11 lands; it reports and exits 2.
- The CLI keeps the web upload's 512 MiB limit, because both use the same intake.
- No custody entry is written when a case is created yet; that stacks on the custody
  chain PR (#19) and lands after it.
- Output is plain text with no colour, so it reads the same in a terminal, a file or a
  CI log. Only argparse's own `--help` may colour itself, and only in a real terminal.

---

## 11. Not built yet

Listed so nobody mistakes a plan for a feature. Each gets its own section above when it
lands (standing rule).

- **Hash-chained custody log:** every event appended as an entry that includes the
  previous entry's hash, so editing or deleting one breaks every later link. Data shapes
  exist (`CustodyEntry`); the logic does not.
- **RFC 3161 token building and checking:** a third party signs "this hash existed at
  this time". The transport and retry are built (section 9); building the request and
  checking the returned token is #11, so seals stay `PENDING` until then.
- **Case verification and the tamper demo:** re-hash the stored file, compare to the seal,
  walk the chain. The 10-second flip-one-byte demonstration. The CLI already lists
  `verify` and `tamper-demo` (section 10); they say "not built yet" until #12.
- **JA3 fingerprinting (4th detector):** matches TLS handshake fingerprints to a known
  malware list. Deliberately deferred; proposal in section 12.

---

## 12. JA3 fingerprinting (proposed)

_Status: concept draft for human approval. No JA3 code exists yet. Written 2026-10-20._

### What it does
JA3 gives every program that opens a TLS connection a short ID (32 hex characters), built from how the program *introduces itself* to a server. If that ID is on a list of IDs seen in malware, we raise a finding. We never decrypt anything and never read page content.

### First, the background

- **TLS** is the encryption used by HTTPS. Before any private data flows, the two sides do a **handshake** (an opening exchange where they agree on how to encrypt).
- The first message is the **ClientHello**, sent by the client (the program making the connection). It says, in plain text (not encrypted), "here is what I support": which TLS versions, which encryption recipes, which optional features. The server's reply picks from this menu.
- A **cipher suite** is one such encryption recipe, identified by a number. A client sends its whole list, in its own order of preference.
- An **extension** is an optional feature the client announces, also a number (for example `0` = "I want the site called example.com", the server name, SNI).
- **Curves** (elliptic curves) are the maths families the client can use for key exchange; **point formats** is a tiny setting for how curve data is written.

Because the ClientHello is plain text, a passive capture contains it. That is why this works on a pcap.

### Why a fingerprint identifies a program
The menu in a ClientHello is not chosen by the user. It is baked in by the TLS library and settings of the program: Chrome, Firefox, Python `requests`, a given malware family each send a different menu, in a different order. The same program sends the same menu to every server. So the menu is like a handwriting sample: it says which *program* is talking, not which *person* or which *website*. Malware built from one codebase shares one menu, so one fingerprint covers all its infections.

### How JA3 is computed (5 fields)
Take these five values from the ClientHello, as decimal numbers, **in the order they appear on the wire**:

1. **TLS version** (the ClientHello's own version field; 771 = TLS 1.2, even for TLS 1.3 clients, which hide the real version in an extension)
2. **Cipher suites** list
3. **Extensions** list (just the numbers, not their contents)
4. **Curves** (the "supported groups" extension, number 10)
5. **Point formats** (extension 11)

Join numbers inside a field with `-`, join the five fields with `,`, then take the **MD5** of that text. (MD5 is a hash: a function that turns any text into a fixed 32-hex-character summary; same text always gives the same summary, any change gives a completely different one. We use it here only as a short label, not for security, so MD5's known weaknesses do not matter for this use.)

**Worked example** (small made-up client, real arithmetic):

| Field | Raw values on the wire | After dropping GREASE |
|---|---|---|
| Version | 771 | 771 |
| Ciphers | 2570, 4865, 4866, 49195 | 4865-4866-49195 |
| Extensions | 2570, 0, 23, 65281, 10, 11 | 0-23-65281-10-11 |
| Curves | 6682, 29, 23, 24 | 29-23-24 |
| Point formats | 0 | 0 |

JA3 string: `771,4865-4866-49195,0-23-65281-10-11,29-23-24,0`
MD5 of that string: `d513a2c384da97e772fef72dfe6d8276` (computed with Python `hashlib`). Change one number (say 24 to 25) and the hash is completely different.

### GREASE: why some values must be dropped
**GREASE** (RFC 8701) is a trick modern clients use on purpose: they insert made-up, meaningless numbers into the lists (always of the form `0x0a0a`, `0x1a1a`, ... `0xfafa`: 16 values, both bytes equal, low nibble `a`) and pick a *different* one each connection. The aim is to stop servers from breaking on unknown values. Above, 2570 (`0x0a0a`) and 6682 (`0x1a1a`) are GREASE. If we kept them, the same Chrome would give a different hash on every connection. So the JA3 rule is: **remove every GREASE value from ciphers, extensions and curves before building the string.** Getting this wrong is the most common JA3 bug, so we test it directly.

### Matching against abuse.ch SSLBL
**SSLBL** is a free blocklist from abuse.ch listing JA3 hashes seen in malware (CSV: `https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv`). Match rule: our hash equals a listed hash (exact, yes/no). Evidence: the hash, the JA3 string, the listing reason (malware family), and the SNI if present.

Checked 2026-10-20:
- The CSV header says "Last updated: 2021-08-03", it has fewer than 100 rows, and its newest "last seen" date is 2021-08-11. **The list is about five years old.** It will miss malware families from 2022 onwards.
- The SSLBL website itself warns the fingerprints "have not been tested against known good traffic yet and may cause a significant amount of FPs" (false positives = harmless traffic wrongly flagged). Malware that uses the operating system's TLS library shares a fingerprint with ordinary programs.
- I did not check whether abuse.ch plans to retire the service.

So a match is a **lead for a human, not proof**. The finding text must say so.

### Known limits
- **Collisions:** two different programs can share a JA3 (same library, same settings). A match says "looks like", not "is".
- **Randomised order:** Chrome (since about 2023) shuffles extension order each connection, so Chrome has no stable JA3. Harmless for a *malware* list (malware rarely randomises), but JA3 is useless for identifying browsers.
- **Evasion:** a malware author can copy a browser's ClientHello.
- **JA4** is the newer successor: it sorts the extensions before hashing, so shuffling no longer matters, and it is readable. Natural upgrade path; not in scope.
- **Not visible to JA3:** QUIC/HTTP3 (ClientHello is inside encrypted packets), anything not on TCP, and ClientHellos split across several TCP packets if we do not reassemble (our scope rule excludes TCP reassembly). Newer browsers with large post-quantum key shares make a split more likely; for malware, rare.

### What do we need to install?
| | Parse with `dpkt` (already a dependency) | Use `tshark` (Wireshark's engine) |
|---|---|---|
| Install | nothing | `brew install wireshark` (missing on this Mac; the PyShark path is not built) |
| Who computes JA3 | our own code (~60-80 lines: read TLS record, read ClientHello, drop GREASE, join, MD5) | Wireshark, via a JA3 field (field names not verified here: tshark is not installed) |
| Explainability | every step is ours and shown in the evidence | black box call; "same engine as Wireshark" is a good courtroom line, though |
| Split ClientHello | missed (no reassembly) | handled |
| Speed / robustness | one pass in-process | a subprocess per file, depends on Wireshark version |
| Testable offline | yes | needs the install in CI |

I confirmed on this machine that `dpkt` 1.9.8 parses a ClientHello and returns cipher suites and extensions in wire order, and it even labels GREASE ciphers. Extensions come back as numbers with raw data, which is all JA3 needs.

### Testing with no licence-clear sample
No small public capture with a known SSLBL hit has a clear licence. Plan:
1. **Generate our own** ClientHello bytes in a test (like the synthetic pcaps in `scripts/make_synthetic_pcaps.py`), including GREASE values, and check our function's output against the hash computed independently by `hashlib` from a string written out by hand (the table above is exactly such a test).
2. Put a self-made hash in a **test blocklist file**, to prove the match path and the evidence text. This proves the code, not that the list catches real malware, and the docs must say so.
3. **One-time cross-check** (optional): if the human is willing to install Wireshark, compare our hash with Wireshark's on one real capture of our own browser traffic.

### Recommended design
- Parse the ClientHello with `dpkt` plus a small amount of our own code. No tshark. Core logic, so pairing mode: explain, write, review one function at a time (drop-GREASE, build-string, hash, match).
- Fill the existing `TlsFeatures(ja3, ja3_string, server_name)`, one flow per TCP connection, from the first ClientHello only.
- Blocklist: a local copy of the SSLBL CSV loaded from the path already in config (`sslbl_cache_path`), fetched by a separate small script with a pinned hash; the detector itself does no network.
- Severity: always MEDIUM (one signal, and the source warns about false positives); evidence names the list's age.
- One detector module, one finding per (client IP, JA3), the same interface as the other three.

### Open questions
The five decisions this feature needs are in section 13, question C.

---

## 13. Open questions for Garv

Read the whole document first, then decide here in one sitting. Each question stands
alone: terms are defined where they first appear in that question, there is a small
example where it helps, then numbered options with pros, cons and the team's
recommendation, then an empty `Decision:` line for you to fill in. Questions are grouped by
topic. Sources are named in brackets so you can check them.

| Group | Questions |
|---|---|
| Evidence layer | A (custody chain, PR #19), H (what order to build), I (coming later: anchoring) |
| Detectors and data | B (DNS non-text bytes, PR #18), C (JA3), D (threshold tuning), E (SSDP false positive, issue #17) |
| Wording and process | F (evidence wording), G (working mode) |

### Group 1: the evidence layer

#### A. Approve the custody hash chain? (PR #19, five design choices)

**Background.** The custody log is the list of events for a case (uploaded, parsed, each
finding, report made). To make edits detectable, each entry stores a **hash** of its own
contents, and also the hash of the entry before it. (A hash is a fixed-length fingerprint
of data: same data always gives the same fingerprint, any change gives a different one.)
Change entry 3 and its fingerprint no longer matches what entry 4 recorded, and the break
shows. The first entry is tied to the sealed pcap, so a chain cannot be moved onto other
evidence. Jim built it in PR #19; Pam tested it hard and found it held up. Pam raised
findings that Jim has since fixed (PR #19, now at `e602d8d`, 169 tests pass): the hash
algorithm (SHA-256) and the domain tags are now fixed in code, not config, so a config
change can no longer weaken the chain or make old chains read as broken; an entry nested
more than 32 levels deep (a crafted 5,000-level one used to crash the checker) is now
reported as a break; and a seal time with no timezone is reported as a break, not a crash.

**What the chain does not do (both gaps are fixed later by question I).** It cannot tell if
the *last* entries were cut off the end, and someone with write access to the database who
recomputes every later fingerprint produces a chain that still verifies.

**The five choices you are asked to approve** (sources: PR #19 Part 4, Pam's review of #19).

1. **Use SHA-256 for the chain**, not BLAKE3. SHA-256 is the older, universally supported
   hash (what `shasum` and `openssl` compute, and what a timestamp authority signs).
   *Pro:* anyone can re-check it with standard tools, and the chain's head can go straight
   into a timestamp request later. *Con:* a second hash algorithm in the system (the seal
   uses BLAKE3 as primary). Related: **MD5 and SHA-1** are older hashes now known to be
   breakable by crafting two different inputs with the same fingerprint. The chain pins
   SHA-256 in code so they can never be selected by a config change (done).
2. **Hash a canonical JSON form of each entry.** *Canonical JSON* means one fixed way to
   write the data as text: keys sorted, no spaces, one spelling of each value, so writer
   and checker hash exactly the same bytes. Example why it matters: if you join fields with
   a `|`, the pair `("ingest", "x|y")` and the pair `("ingest|x", "y")` both become
   `ingest|x|y`, so two different entries give the same hash input. JSON puts quotes around
   every string, so a boundary cannot move. *Alternative:* length-prefixed binary fields,
   equally safe but not readable in a hex dump.
3. **Refuse floating-point numbers; store them as text.** A float such as `4.2` has no single
   text form across programs (`4.2` vs `4.2000000000000002`), so two honest systems could
   hash it differently and report a false tamper. Callers store `"4.2"` instead, which is
   also exactly what the evidence sentence shows. *Con:* callers must remember to convert.
4. **No Unicode normalisation.** Unicode allows one visible character to be stored in two
   ways: `é` as one code point (bytes `c3 a9`, SHA-256 starts `4a99557e`) or `e` plus a
   combining accent (bytes `65 cc 81`, SHA-256 starts `bf12767b`). *Normalising* would
   convert both to one form before hashing. We do **not**: we hash exactly what was stored.
   *Pro:* a change in bytes is never hidden. *Con:* a harmless re-encoding looks like
   tampering, a false alarm (the safe direction for evidence).
5. **An empty log counts as broken.** Every sealed case starts with an ingest entry, so an
   empty log means entries were lost, and it must never quietly pass.

**Options.**
1. **Approve all five and merge #19.** *Pro:* unblocks the rest of the evidence layer.
   *Con:* choices 1 and 4 are costly to change later (every existing chain would read as
   broken; a new format gets a new tag, `v2`).
2. **Approve with changes** (say which choice). *Pro:* you stay in control of the format.
   *Con:* rework and a delay.
3. **Hold the merge** until you have read the PR's line-by-line walk-through. *Pro:* full
   understanding. *Con:* slows everything behind it.

**Recommendation:** option 1.
Pam found no way to forge or silently alter an entry (9,218 random corruptions, all caught
at the exact entry). You can reproduce the first fingerprint yourself: the shell one-liner
in the PR gives `f3504c93…db360d`.

Decision: 

#### H. May Jim start the timestamp verifier (#11) while #19 is under review?

**Background.** Issue #11 is the *RFC 3161 token verifier*. RFC 3161 is the internet
standard for a **TSA** (timestamp authority: a trusted third party that signs "this hash
existed at this time"). The verifier checks a signed answer from such a party. It does not
depend on #19 (the custody chain). You asked for one pull request at a time; running both
breaks that order.

**Options.**
1. **Keep strict order:** #19 merges, then Jim starts #11. *Pro:* you review one thing at
   a time, nothing piles up. *Con:* Jim idles while waiting for you.
2. **Allow #11 to start now, review it only after #19.** *Pro:* no idle time. *Con:* two
   open pull requests; if #19 changes, #11 may need rebasing (small risk, they touch
   different files).
3. **Allow both and review in either order.** *Pro:* fastest. *Con:* the most to hold in
   your head.

**Recommendation:** option 2 (Jim writes now, you still review one at a time).

Decision: 

#### I. Coming later, information only: why the chain head must be anchored (issue #12)

No decision needed yet. This is so the later question makes sense.

**The problem.** A chain proves the entries you can see are in order and unedited. It
cannot prove nothing was cut off the end. Example: a chain has 10 entries; someone deletes
entries 8 and 9. The remaining 8 entries still link perfectly, so the log verifies as intact
while the final events (say "report exported" and "verify") are gone. Entries have no secret
key, so someone with database access could also rewrite entries and recompute all later
fingerprints.

**The fix.** *Anchoring*: take the latest entry's fingerprint (the "head") and have a
timestamp authority sign it. Later, if the log's head is not the signed one, or a signed
entry has vanished, truncation shows. Pam's note: the signed copy must live somewhere other
than the same database, or it proves nothing.

**What happens next.** When Jim reaches issue #12 he will compare options (for example
signing the head at set points, and also printing the head in the PDF so a person can
compare it on paper) and recommend one. It will come to you as a question then.

Decision: (none needed now)

### Group 2: detectors and data

#### B. DNS names with non-text bytes: measure the escaped text or the raw bytes? (PR #18)

**Background.** A DNS name is dot-separated *labels* (`www`, `example`, `com`). Each label
is raw bytes. The library we use insists the bytes be valid UTF-8 (the standard way to turn
bytes into text); some bytes such as `0xE4` are not valid on their own, and a capture of the
tunnelling tool **iodine** (which hides data in DNS names) crashed the whole upload for that
reason. PR #18 fixes the crash by keeping the label and writing each bad byte as text:
`0xE4` becomes the four characters `\xe4`.

**The side effect.** The detector measures a label's *length* and its *entropy* (a score of
how random a string looks; 0 = predictable, higher = random; see section 3) on that escaped
text, not on the real bytes. Real numbers from `dns-iodine.pcap`:

| | Measured on raw bytes | Measured on escaped text (what PR #18 does) |
|---|---|---|
| Longest label length | 55 | 193 (46 bad bytes × 4 characters) |
| Entropy | 5.74 | 3.43 |

Tiny example: the four bytes `E4 E5 E6 E7` have entropy 2.0 raw (four different values) but
2.5 on the 16-character escaped text `\xe4\xe5\xe6\xe7`. On long, dense labels like iodine's,
escaping *lowers* the entropy, because the repeated `\`, `x` and `e` characters add
predictability. So the tunnel looks less random than it is: errors lean toward **missing**
a tunnel, not false alarms. The detector still fires HIGH on this capture (another label
reaches 4.81), so nothing is lost today. But the length in a finding ("193 chars") is not
what is on the wire (about 55 bytes), and evidence should state what is true.

**Options** (sources: PR #18, Pam's QA of #18).
1. **Keep escaping, document it, word the evidence "measured on the escaped rendering".**
   *Pro:* smallest change; crash is fixed now. *Con:* numbers in findings differ from the
   wire.
2. **Measure raw bytes now** (carry the bytes through to the detector). *Pro:* true numbers,
   evidence matches the wire. *Con:* touches more of the parser and the data shape; delays
   the crash fix.
3. **Keep escaping now, switch to raw bytes as a follow-up.** *Pro:* fixes the crash today
   and gets truth later. *Con:* findings carry the escaped numbers in the meantime.

**Recommendation:** option 3 (god's suggestion; the team agrees).

Decision: 

#### C. JA3 fingerprinting: five questions (Dwight's draft, section 12)

Read section 12 first; it explains what **TLS** (the encryption behind HTTPS), the
ClientHello, JA3, MD5, GREASE, and the blocklist are. In short: JA3 turns how a program
introduces itself during the TLS handshake into a 32-character label, then checks the label
against a list of labels seen in malware.

1. **Is a 2021 blocklist acceptable?** The abuse.ch SSLBL list was last updated on
   2021-08-03 and has under 100 rows; the site itself warns of false positives. *Option
   1:* use it, and state its age in every finding (*pro:* free and works now; *con:* misses
   malware from 2022 onward, matches are leads not proof). *Option 2:* look for a fresher
   source first (*pro:* better coverage; *con:* delay, and no source is identified yet).
   **Recommend 1.**
2. **dpkt only, no tshark.** `dpkt` is the packet library we already use; `tshark` is
   Wireshark's engine, which would need installing and runs as a separate program. *Option
   1:* dpkt only; our own ~60-80 lines build the label (*pro:* every step explainable, no
   install; *con:* we write and test it). *Option 2:* tshark (*pro:* mature, same engine as
   Wireshark, handles split packets; *con:* black box, not installed on this Mac, harder to
   test). *Option 3:* dpkt, plus a one-time comparison against Wireshark on a capture of
   your own browser (*pro:* independent check; *con:* you install Wireshark once).
   **Recommend 3 (3 includes 1).**
3. **Accept missing a ClientHello split across several packets.** Finding it would need
   *TCP reassembly* (stitching packets back into one stream), which the project excluded.
   *Option 1:* accept and document (*pro:* scope stays fixed; *con:* some real handshakes
   missed, more likely with modern post-quantum key sizes). *Option 2:* add reassembly
   (*pro:* complete; *con:* breaks the scope rule, much more code). **Recommend 1.**
4. **Severity.** *Option 1:* always MEDIUM (*pro:* simple, honest; one signal and a list
   that warns of false positives). *Option 2:* MEDIUM, but LOW when the label is also common
   in harmless software (*pro:* fewer false alarms; *con:* we have no data on which labels
   those are). **Recommend 1.**
5. **Seal the blocklist.** Record the list's own hash and download date with the case, so a
   finding can be reproduced later. *Option 1:* yes (*pro:* fits the project's purpose;
   *con:* a little more code). *Option 2:* no (*pro:* simpler; *con:* a later reader cannot
   tell which list version produced a match). **Recommend 1.**

Decision 1 (list age): 
Decision 2 (dpkt/tshark): 
Decision 3 (split hellos): 
Decision 4 (severity): 
Decision 5 (seal list): 

#### D. Threshold tuning: what it means and the known weak spots

**Background.** A *threshold* is a cutoff number a detector compares a measurement to. All
current cutoffs are in section 7; most are "proposed" starting guesses, never tested
against real traffic. *Tuning* means: run the detectors on many captures (the real and
synthetic ones Dwight curated), see what fires and what is missed, change a number, repeat,
and **write down why** each number is what it is. Because every finding prints the measured
value next to its cutoff, you can always see how close a call was.

**Known weak spots** (all measured, none hidden):
- **DNS needs long names.** The entropy cutoff 4.2 cannot be reached by a string shorter than
  19 characters (the highest possible entropy of a 19-character string is `log2(19)` = 4.25).
  Our 20-character base32 sample scores 3.684 and is missed.
- **A paced port scan also trips the beacon detector.** A scan that sends probes at perfectly
  even intervals has a *coefficient of variation* (CV: how uneven the gaps are, as a
  fraction of their average; 0 = metronome) near 0, so it also looks like a beacon.
- **Jitter evades the beacon check.** Malware that randomises its timer pushes CV up. Gaps
  of `60, 63, 57, 66, 54, 61, 59, 64, 56` seconds (about ±10% jitter) still give CV 0.066 and
  fire. Gaps of `42, 78, 51, 66, 45, 72, 58, 63, 84, 55` (roughly ±35% jitter) give CV 0.226
  and do not.

**Options.**
1. **Tune now** against the existing sample captures, record the reasons in `docs/logic.md`
   and `dev-notes.md`. *Pro:* numbers become evidence-based. *Con:* small sample set, risk
   of fitting the examples.
2. **Tune later** (Phase 4), after the evidence layer is done. *Pro:* focus on the product's
   differentiator first. *Con:* weak spots stay visible in demos.
3. **Never tune; document the limits instead.** *Pro:* least work. *Con:* the tool stays a
   guess.

**Recommendation:** option 2, then option 1 in Phase 4; mode decided in question G.

Decision: 

#### E. SSDP false positive: how to stop flagging harmless discovery traffic (issue #17)

**Background.** **SSDP** (Simple Service Discovery Protocol) is how devices on a home or
office network announce themselves. It sends to a **multicast** address (one address that
many devices listen on at once; `239.255.255.250` here). In the capture `ctu-185-1`, the
host `192.168.1.2` sends there every 120 seconds with CV 0.000, so the beacon detector fires
`MEDIUM`. The measurement is true (it *is* regular); the conclusion (command-and-control) is
wrong. The same capture family also has a real beacon, `ctu-130-1`: 6,949 connections about
every 9 seconds, CV 0.020, which must keep firing.

An **allowlist** is a list of things the detector is told to ignore. **CIDR** is a compact
way to write a block of addresses: `224.0.0.0/4` means "every address whose first 4 bits are
1110", i.e. all 268,435,456 multicast addresses, and it contains `239.255.255.250`.

**Options.**
1. **Skip every multicast destination in the detector code.** *Pro:* simplest; fully covers
   multicast. *Con:* the rule lives in code, not config; can't skip other benign addresses.
2. **A CIDR allowlist in config** (extend the existing, empty list to hold ranges; default
   multicast and broadcast). *Pro:* one source of truth, auditable, editable without code
   changes, covers other benign ranges later. *Con:* a little more code, and a reviewer must
   trust the list.
3. **Still flag it, but add "likely benign: multicast discovery" to the evidence.** *Pro:*
   nothing hidden. *Con:* the false alarm is still shown.

Whichever is chosen, suppressed traffic should be recorded, not silently dropped.

**Acceptance test:** `ctu-185-1` stops producing the multicast finding, while
`ctu-130-1` still fires and a unit test shows even-timed traffic to multicast is skipped but
the same timing to a normal address fires.

**Recommendation:** option 2 (Angela and god recommend it; the team agrees).

Decision: 

### Group 3: wording and process

#### F. Evidence wording: consistent sentences, and drop "court-admissible"

**Background.** Each finding has an *evidence sentence* a reviewer reads. Today the three
detectors word them differently:
- DNS: "Subdomain 'x' of 'p' has Shannon entropy 4.40 (benign baseline ~2.5), length 40 chars, with 200 queries in 60s…"
- Beacon: "Host A contacted B every ~60s (±1.2s) over 10 connections (coefficient of variation 0.020, threshold 0.1)…"
- Port scan: "Source A reached 850 distinct destination ports (threshold 100) and … within a 10s window…"

They differ in what they name, where the threshold appears, and units. Separately, the
project text calls the evidence layer "**court-admissible**" (`CLAUDE.md` line 5; `docs/logic.md`
already advises against it, and risk #3 in `handoff.md` is still open). *Admissible* means a court will accept it as evidence, which
depends on law and procedure we cannot certify. What the tool *does* prove is narrower: a
file has not changed since it was sealed, and the log of what was done to it has not been
silently altered. That is **tamper-evident / evidentiary integrity**, "designed toward"
admissibility.

**Options.**
1. **One fixed template for every sentence** (what was measured, the value, the cutoff, the
   plain-language meaning, in that order) and replace "court-admissible" everywhere with
   "tamper-evident / designed toward admissibility". *Pro:* consistent, defensible under
   questioning ("prove it"). *Con:* touches detector code (core) and several docs.
2. **Reword only the claims** (docs and README), leave sentences. *Pro:* small and quick.
   *Con:* sentences stay uneven.
3. **Leave both as is.** *Pro:* no work. *Con:* an overclaim an expert could attack.

**Recommendation:** option 1, in two steps: claims first (docs only, immediate), sentences
as core code under the mode chosen in G.

Decision: 

#### G. How should the next pieces be built? (threshold tuning, SSDP fix, evidence wording, JA3 code)

**Background.** Questions D, E, F and the JA3 code are *core logic* (the parts that decide
what is flagged and what a finding says). You decide how they are built. A *worktree* (the
git feature that gives a second working folder on the same repository, so two people never
overwrite each other's files) is how agents already work separately.

**Options.**
1. **Jim builds, explaining before each change, and you approve each pull request before
   it merges.** *Pro:* fast; the explanation is in the pull request for you to read at your
   pace. *Con:* you read finished code, so you learn by reviewing rather than by shaping
   it.
2. **Line-by-line pairing:** explain a piece, write one piece, stop for your review, repeat.
   *Pro:* you learn most; you steer every decision. *Con:* slowest; needs you present at
   each step.

This already applies to the evidence-layer steps 3-5 (option 1, your decision of
2026-10-20). Today the older pairing rule still covers the rest until you say otherwise.

**Recommendation:** option 1 for D, E and F (small, well-specified); option 2 for the JA3
build (new, concept-heavy, and you said you want to learn the concepts).

Decision: 
