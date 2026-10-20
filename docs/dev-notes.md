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
10. [Not built yet](#10-not-built-yet)

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

1. **Upload** (`POST /api/cases`, `backend/api/app.py`). The file is written to disk in
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
  chain and its timestamped head (section 10).
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
  Closing that gap is what the custody chain and its timestamped head are for (section 10).
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

## 10. Not built yet

Listed so nobody mistakes a plan for a feature. Each gets its own section above when it
lands (standing rule).

- **Hash-chained custody log:** every event appended as an entry that includes the
  previous entry's hash, so editing or deleting one breaks every later link. Data shapes
  exist (`CustodyEntry`); the logic does not.
- **RFC 3161 token building and checking:** a third party signs "this hash existed at
  this time". The transport and retry are built (section 9); building the request and
  checking the returned token is #11, so seals stay `PENDING` until then.
- **Case verification and the tamper demo:** re-hash the stored file, compare to the seal,
  walk the chain. The 10-second flip-one-byte demonstration.
- **JA3 fingerprinting (4th detector):** matches TLS handshake fingerprints to a known
  malware list. Deliberately deferred.
