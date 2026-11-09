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
| **DNS exfiltration** | Shannon entropy of subdomains + length + query rate to one parent domain | *"…longest subdomain `a8f3…`: Shannon entropy 4.40 bits/char (cutoff: at least 4.2, met; benign baseline about 2.5); …"* |
| **C2 beaconing** | Coefficient of variation of inter-arrival times between a host pair | *"Host X to Y: connections 45 (cutoff: at least 10, met); coefficient of variation of the gaps 0.033 (cutoff: at most 0.1, met; …)"* |
| **Port scan / recon** | Distinct ports/hosts one source touches within a sliding time window | *"Source X, busiest 10 s window: distinct destination ports 850 (cutoff: at least 100, met); distinct destination hosts 12 (cutoff: at least 10, met)…"* |
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
the tool catches it. The output is tamper-evident and designed toward admissibility;
the project does not claim legal admissibility.

## Status

Actively built in public increments, not finished. Current state:

**Done**
- Shared data models, detector interface, and single-source config
  (`backend/models.py`, `backend/detectors/base.py`, `backend/config.py`)
- Three of four detectors: DNS exfiltration (+ dpkt DNS parser), C2 beaconing, port scan
- Generic flow parser, upload validation, and the analysis pipeline
  (`backend/parse/flow_parser.py`, `backend/ingest/`, `backend/pipeline.py`)
- Dual-hash pcap seal: BLAKE3 + SHA-256 in one streaming pass (`backend/evidence/seal.py`)
- Hash-chained custody log (`backend/evidence/custody.py`)
- RFC 3161 timestamping: request, pinned-certificate check, `PENDING` and retry when the
  authority is unreachable (`backend/evidence/timestamp.py`, `tsa_client.py`)
- Case verification with chain-head anchoring, so a cut-off chain end is detected
  (`backend/evidence/verify.py`, `anchor.py`)
- Append-only SQLite storage with a content-addressed pcap store (`backend/db/`)
- Command line: `seal`, `analyze`, `verify`, `tamper-demo`, `retry-timestamps`
  (`backend/cli.py`)
- FastAPI upload/case/report API and PDF report (`backend/api/`, `backend/report/`)
- React + TypeScript frontend (`frontend/`): kept in the repo, but not part of v1; the
  command line is the v1 interface
- 362 passing tests across all of the above (live-network tests are opt-in)

**Not yet built**
- JA3 fingerprinting detector (4th of four, deliberately deferred)
- A verify endpoint in the API and a tamper-test control in the frontend (the command
  line has both)

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

Walk through a seal, an analysis, a verification and a tamper test on a sample
capture with [`docs/demo-script.md`](docs/demo-script.md).

Command line (no server needed; writes to `evidence_store/` unless you pass `--store DIR`):

```bash
python -m backend.cli seal capture.pcap       # seal and store; prints case id, BLAKE3, SHA-256
python -m backend.cli analyze capture.pcap    # same, plus each finding with its evidence
python -m backend.cli verify <case-id>        # INTACT / ALTERED / INCOMPLETE, each check with its evidence
python -m backend.cli tamper-demo capture.pcap   # sealed copy, flip one byte, watch verify say ALTERED
python -m backend.cli retry-timestamps        # retry seals still waiting for a trusted timestamp
# add --offline before the command to never contact the timestamp authority
```

Exit codes: 0 success, 1 error (explained in one line). `verify` uses 0 = INTACT,
1 = ALTERED, 2 = INCOMPLETE (nothing failed, but a timestamp is still pending).

Running the API and the (optional) frontend:

```bash
uvicorn backend.api.app:app --reload          # API on :8000; cases stored under evidence_store/
cd frontend && npm install && npm run dev     # Vite dev server on :5173, proxies /api to :8000
```

`tshark` (Wireshark) is an external dependency for the PyShark parse path —
`brew install wireshark` (macOS) or your platform's package manager. Not a pip
package; the dpkt parse path works without it.

## Project layout

```
backend/
├── models.py          shared data shapes (Flow, Finding, SealRecord, CustodyEntry)
├── config.py          single source of truth for thresholds/baselines
├── pipeline.py        seal first, then parse and detect
├── intake.py          stage, validate, seal, store: shared by the API and the CLI
├── cli.py             command line: seal / analyze / verify / tamper-demo / retry-timestamps
├── api/               FastAPI routes (upload, case, report)
├── ingest/            upload validation
├── parse/             pcap → flow/feature extraction (dpkt, entropy)
├── detectors/         one module per detector, common Detector.run() interface
├── evidence/          seal, custody chain, RFC 3161 timestamps, verification, anchoring
├── db/                append-only SQLite store, content-addressed pcap store
└── report/            PDF report
frontend/              React + Vite + TypeScript UI (kept; not part of v1)
docs/
├── architecture.md    system structure, pipeline, stack, dependency risks
├── logic.md           detector formulas, thresholds, evidence-layer mechanics
├── handoff.md         living build state — read this for where things stand
├── dev-notes.md       plain-language explanations with worked examples
├── demo-script.md     seal, analyze, verify, tamper-demo on a sample capture
└── plan.md            phased build roadmap
tests/                 one test module per detector/parser, crafted fixtures
scripts/               environment check, sample-capture generator and fetcher
sample-pcaps/          curated captures for exercising each detector (git-ignored; generate with scripts/make_synthetic_pcaps.py)
```

## Docs

- [`docs/architecture.md`](docs/architecture.md) — pipeline stages, stack, data flow
- [`docs/logic.md`](docs/logic.md) — exact detector formulas and the evidence contract
- [`docs/demo-script.md`](docs/demo-script.md) — seal, analyze, verify and tamper-demo, with the output to expect
- [`docs/handoff.md`](docs/handoff.md) — current phase, session log, open decisions
- [`docs/plan.md`](docs/plan.md) — the phased build roadmap
- [`docs/dev-notes.md`](docs/dev-notes.md) — plain-language explanations of everything built, with worked examples

## License

[MIT](LICENSE)
