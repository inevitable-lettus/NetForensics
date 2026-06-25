# Architecture

System *structure* for NetForensics: the pipeline, the stack, how data flows, the
proposed repo layout, and external-dependency risks. For detector formulas and
evidence-layer mechanics see [`logic.md`](logic.md). For current build state see
[`handoff.md`](handoff.md).

> Anything below marked **(proposed / to confirm)** is a design suggestion, not a
> settled fact — there is no code yet.

## Four-stage pipeline

```
.pcap  ──▶  Stage 1: Ingest & Seal   [EVIDENCE INTEGRITY]
            Stage 2: Parse to Flows
            Stage 3: Run Explainable Detectors
            Stage 4: Build the Case File  [EVIDENCE INTEGRITY]  ──▶  forensic PDF
```

Stages **1 and 4 are the evidence-integrity differentiator**. Stages 2–3 are
table-stakes traffic analysis. Every stage's output must be explainable and, where it
concerns evidence, independently verifiable.

| Stage | Does | Output |
|---|---|---|
| 1 — Ingest & Seal | Hash the pcap (BLAKE3) + record an RFC 3161 trusted timestamp **before any analysis**. The digital evidence-bag seal. | Seal record (hash, timestamp, received-at) |
| 2 — Parse to Flows | Decompose capture into connection flows with extracted features. | Flows w/ features (counts, timing, DNS fields, TLS handshake params) |
| 3 — Run Detectors | Four transparent detectors, each emitting a finding + its triggering evidence. | Findings w/ evidence |
| 4 — Build Case File | Write findings + evidence + integrity record to append-only custody log; export forensic PDF. | Custody log + PDF report |

## Stack

| Layer | Technology |
|---|---|
| Packet parsing | **dpkt** (fast bulk pass over large captures); **PyShark / tshark** (Wireshark dissectors, for protocol-rich TLS & DNS fields) |
| Backend | **Python**, **FastAPI** |
| Detection / stats | **NumPy** & **SciPy** (Shannon entropy, timing statistics) |
| TLS fingerprinting | **JA3** fingerprint generation; **abuse.ch SSLBL** blocklist as threat-intel source |
| Evidence integrity | **BLAKE3** (hashing), **RFC 3161** trusted timestamping, append-only custody log |
| Storage | **SQLite** |
| Report generation | **ReportLab / WeasyPrint** (forensic PDF) |
| Frontend | **React** |
| Test data | Public malware-traffic PCAPs (e.g. malware-traffic-analysis.net) |

**Parsing split rationale:** dpkt gives speed on big captures; PyShark wraps Wireshark's
own dissectors for correctness on complex protocols. "We parse with the same engine as
Wireshark" is a defensible courtroom correctness claim.

## Data flow

```
pcap file
  └─▶ [Stage 1] BLAKE3 hash + RFC 3161 timestamp ──▶ seal record (SQLite)
        └─▶ [Stage 2] dpkt bulk parse + PyShark TLS/DNS ──▶ flows + features
              └─▶ [Stage 3] 4 detectors ──▶ findings + evidence
                    └─▶ [Stage 4] append-only custody log ──▶ forensic PDF
```

Integrity verification re-hashes the stored pcap and compares against the seal record;
a mismatch flags broken chain of custody (see [`logic.md`](logic.md)).

## Proposed repo layout (proposed / to confirm)

```
cybersec_hackathon/
├── CLAUDE.md
├── docs/                  architecture.md · logic.md · handoff.md
├── backend/               (proposed)
│   ├── ingest/            Stage 1 — hashing + timestamping (seal)
│   ├── parse/             Stage 2 — dpkt + PyShark flow reconstruction
│   ├── detectors/         Stage 3 — one module per detector (dns_exfil, c2_beacon, port_scan, tls_client)
│   ├── evidence/          custody log + integrity verification
│   ├── report/            Stage 4 — PDF generation
│   ├── db/                SQLite schema + access
│   └── api/               FastAPI routes (upload, analyze, verify, report)
├── frontend/              (proposed) React dashboard
└── sample-pcaps/          curated demo captures (each must fire ≥1 detector)
```

Detector modules share a common interface so new detectors plug in without touching the
evidentiary core (Hard Rule 4).

## External dependencies & risks

| Dependency | Risk | Mitigation direction |
|---|---|---|
| **tshark** (PyShark backend) | Must be installed on the demo machine; missing/old tshark breaks Stage 2. | Verify on the actual demo laptop; keep dpkt path working independently of PyShark. |
| **RFC 3161 TSA** | Needs a live external Timestamp Authority — **will fail on flaky demo-day wifi**, killing the headline feature. | Choose a TSA (e.g. freeTSA.org) **and** build an offline/cached fallback so the demo never hard-fails. Open risk in [`handoff.md`](handoff.md). |
| **abuse.ch SSLBL feed** | JA3 hits are rare in random pcaps; feed must be fetched/cached. | Curate demo pcaps with a known SSLBL match; cache the blocklist locally. |
| **Encrypted traffic (TLS/DoH)** | Hides payloads — limits inspection by design. | Detectors use metadata only (timing, plaintext-DNS entropy, handshake fingerprints). Scope this honestly; do not overclaim. |
