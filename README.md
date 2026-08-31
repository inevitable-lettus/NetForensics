# NetForensics

Explainable packet-forensics tool for cybercrime investigators. It ingests a
`.pcap`, runs four transparent detectors, and wraps every finding in a
tamper-evident evidence layer — a BLAKE3 hash, an RFC 3161 trusted timestamp,
and an append-only chain of custody — so an investigator can not only see
*what* fired, but prove the evidence behind it hasn't been altered.

Personal project. The point is learning the security concepts properly and
building something that would actually hold up to scrutiny, not shipping the
fastest possible demo.

## Why no ML

Every detector here is a plain, explainable rule — Shannon entropy, timing
statistics, fan-out counts, a hash match — never a black-box model. "The model
flagged it" doesn't survive a follow-up question; "this subdomain has entropy
4.2 where benign traffic sits near 2.5" does. That tradeoff — explainability
over algorithmic sophistication — drives every design choice in this repo.

**The evidence-integrity layer is the actual point of the project, not the
detection.** Tools like Zeek and Suricata already detect these traffic
patterns well. What they don't do is seal the evidence and prove to a
skeptical third party that it wasn't tampered with after capture — that's
the piece this project is built around.

## What it detects

| Detector | Signal | Example evidence |
|---|---|---|
| **DNS exfiltration** | Shannon entropy of subdomains + length + query rate to one parent domain | *"Subdomain `a8f3...` of `evil.com` has entropy 4.2 (benign baseline ~2.5), 312 queries in 60s"* |
| **C2 beaconing** | Coefficient of variation of inter-arrival times between a host pair | *"Host X contacted Y every ~60s (±2s) over 45 connections, CV 0.033 — robotic regularity"* |
| **Port scan / recon** | Distinct ports/hosts one source touches within a sliding time window | *"Source X reached 850 distinct ports and 12 distinct hosts within a 10s window"* |
| **JA3 fingerprinting** *(planned)* | TLS handshake fingerprint matched against the abuse.ch SSLBL malware blocklist | *"TLS client from X has JA3 `hash`, matching SSLBL entry for family Y"* |

Every finding carries **what** was flagged, **why** it's suspicious in plain
language, and the **supporting data** (measured value vs. benign baseline) —
never a bare confidence score.

## How the evidence layer works

```
.pcap ──▶ BLAKE3 hash + RFC 3161 timestamp   (seal, before any analysis)
      ──▶ parse to flows ──▶ run detectors   (findings + their evidence)
      ──▶ append-only, hash-chained custody log
      ──▶ forensic PDF report
```

Each custody entry references the previous entry's hash, so altering or
removing one breaks every later link. Verification re-hashes the stored pcap
and compares it against the sealed hash — a mismatch is flagged immediately
as a broken chain of custody. Flip one byte of a sealed capture and re-verify:
the tool catches it.

## Status

Actively built in public increments, not finished. Current state:

**Done**
- Shared data models, detector interface, and single-source config
  (`backend/models.py`, `backend/detectors/base.py`, `backend/config.py`)
- DNS-exfiltration detector + dpkt-based DNS parser, wired end-to-end
- C2-beaconing detector
- Port-scan / fan-out detector
- BLAKE3 pcap sealing (`backend/evidence/seal.py`)
- 60 passing tests across all of the above

**Not yet built**
- JA3 fingerprinting detector (4th of four)
- RFC 3161 timestamping + hash-chained custody log
- Upload API, SQLite storage, pipeline orchestrator
- PDF report generation
- React frontend

See [`docs/handoff.md`](docs/handoff.md) for the live, detailed build log —
what's done, what's next, and open decisions — updated every working session.

## Getting started

Requires Python 3.11+. Run everything from the repo root.

```bash
# one-time setup
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# check environment readiness (flags missing deps + tshark)
python scripts/check_deps.py

# run the test suite
python -m pytest -q
```

`tshark` (Wireshark) is an external dependency for the PyShark parse path —
`brew install wireshark` (macOS) or your platform's package manager. Not a pip
package; the dpkt parse path works without it.

## Project layout

```
backend/
├── models.py          shared data shapes (Flow, Finding, SealRecord, CustodyEntry)
├── config.py           single source of truth for thresholds/baselines
├── detectors/          one module per detector, common Detector.run() interface
├── parse/               pcap → flow/feature extraction (dpkt, entropy)
└── evidence/           BLAKE3 sealing, custody chain (in progress)
docs/
├── architecture.md    system structure, pipeline, stack, dependency risks
├── logic.md            detector formulas, thresholds, evidence-layer mechanics
├── handoff.md          living build state — read this for where things stand
└── plan.md              phased build roadmap
tests/                  one test module per detector/parser, crafted fixtures
sample-pcaps/            curated captures for exercising each detector (git-ignored)
```

## Docs

- [`docs/architecture.md`](docs/architecture.md) — pipeline stages, stack, data flow
- [`docs/logic.md`](docs/logic.md) — exact detector formulas and the evidence contract
- [`docs/handoff.md`](docs/handoff.md) — current phase, session log, open decisions
- [`docs/plan.md`](docs/plan.md) — the phased build roadmap

## License

[MIT](LICENSE)
