# Demo script: seal, analyze, verify, tamper

A walkthrough of the evidence layer on a synthetic capture, about five minutes. Every
command runs from the repo root with the virtual environment active (see
[`README.md`](../README.md)). The output blocks are real; digests are stable because the
synthetic captures are deterministic, while case ids, times and the throwaway-store path
differ on every run.

## 0. Get a capture

```bash
python scripts/make_synthetic_pcaps.py
```

This writes four small captures to `sample-pcaps/`: `synthetic-benign.pcap`,
`synthetic-dns-exfil.pcap`, `synthetic-c2-beacon.pcap` and `synthetic-port-scan.pcap`.
No network is needed. The commands below use `synthetic-dns-exfil.pcap` (15,624 bytes).

## 1. Seal and analyze

```bash
python -m backend.cli analyze sample-pcaps/synthetic-dns-exfil.pcap
```

The capture is hashed and sealed before anything reads its contents, stored, then
analyzed. Expected output (online; `--offline` before the command leaves the timestamp
`PENDING`):

```
Case       4a1ee44f9b264895bd510e231b3e0933
File       synthetic-dns-exfil.pcap (15624 bytes)
BLAKE3     3ee6719d96750665f506b2031ce57d0a262674902b4a3271445d77dc272ec0b7
SHA-256    8efb03fd13a4f2de01e16b376e845f8e1a31176168ae38b1fe52c1b0cb5044a4
Received   <time>
Timestamp  GRANTED by https://freetsa.org/tsr at <time> (checked on arrival; re-checked by verify)
Flows      1
Findings   1

[HIGH] dns_exfil: DNS parent domain exfil.example
  Why       Subdomain randomness exceeds the benign DNS baseline, ...
  Evidence  DNS parent domain 'exfil.example', longest subdomain '5kncyj8u...': Shannon entropy 4.80 bits/char (cutoff: at least 4.2 bits/char, met; benign baseline about 2.5); subdomain length 40 chars (cutoff: at least 30 chars, met); query rate 121.0 queries per 60 s (cutoff: at least 50 queries per 60 s, met; ...). Meaning: ...
```

What to point out: the BLAKE3 and SHA-256 lines are the seal; the finding states its
measured values next to its cutoffs, with no confidence score. The case id is what the
next command needs; the examples below use `<case-id>`.

## 2. Verify the untouched case

```bash
python -m backend.cli verify <case-id>
```

Expected with a granted timestamp (exit code 0):

```
[PASS] pcap_digests: The stored file re-hashes to the sealed values: BLAKE3 3ee6...c0b7, SHA-256 8efb...44a4, 15624 bytes.
[PASS] custody_chain: All 3 custody entries recompute to their stored hashes and each links to the one before; ...
[PASS] seal_binding: Custody entry 0 is bound to this seal (genesis hash ...).
[PASS] rfc3161_timestamp: www.freetsa.org signed SHA-256 8efb...44a4 at ...
[PASS] chain_head_anchor: 1 anchor(s) match the chain; the latest, entry 1 (hash ...), was signed by the TSA at ...

Verdict    INTACT
Anchor     entry 3, hash ... (GRANTED); keep a copy outside this system: a later verify must still find this entry.
```

Offline, the two timestamp checks read `[NOT RUN]` and the verdict is `INCOMPLETE` (exit
code 2): nothing failed, but no independent clock vouches for the seal yet. Run
`python -m backend.cli retry-timestamps` once the network is back.

## 3. Tamper and verify again

```bash
python -m backend.cli tamper-demo sample-pcaps/synthetic-dns-exfil.pcap
```

This seals a copy in a throwaway store, verifies it, flips one bit of the stored copy,
and verifies again. Your file is only read; the store is deleted afterwards. Expected
output (offline run; the throwaway-store path varies):

```
Flipped one bit of byte 7812 of the stored copy.

check                before      after
pcap_digests         PASS        FAIL
custody_chain        PASS        PASS
seal_binding         PASS        PASS
rfc3161_timestamp    NOT RUN     NOT RUN
chain_head_anchor    NOT RUN     NOT RUN
verdict              INCOMPLETE  ALTERED

After tampering:
[FAIL] pcap_digests: The stored evidence no longer matches its seal: BLAKE3 sealed 3ee6...c0b7, measured e760...ba620; SHA-256 sealed 8efb...44a4, measured a55f...78f6e.
```

What to point out: one flipped bit changes both digests completely, the check that
catches it names the sealed and the measured value, and the chain and the seal binding
still pass because only the capture changed, not the log. Online, the "before" verdict
is `INTACT`.

## 4. Other captures to try

| Capture | Expected |
|---|---|
| `synthetic-benign.pcap` | 0 findings |
| `synthetic-c2-beacon.pcap` | `c2_beacon` MEDIUM (20 connections, gaps of 60 s +/- 1 s) |
| `synthetic-port-scan.pcap` | `port_scan` MEDIUM (200 ports in about 5 s) |

Real captures are listed in [`../sample-pcaps/README.md`](../sample-pcaps/README.md).

## What this proves, and what it does not

The tool is tamper-evident: any change to the stored capture is detected, and the
timestamp and anchor come from an authority outside this machine. It is designed toward
admissibility; it does not claim that any court will accept it.
