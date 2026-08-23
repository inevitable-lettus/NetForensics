# Build Plan — NetForensics

The dependency-ordered roadmap for building NetForensics. This is the **static plan**;
live progress is tracked in [`handoff.md`](handoff.md), not here. Design
reference: [`architecture.md`](architecture.md) ·
[`logic.md`](logic.md). Coding rules: [`../CLAUDE.md`](../CLAUDE.md).

---

## Ownership & collaboration model

Every work item below is tagged by owner:

- **`[CORE]`** — all algorithmic code: parsing/feature-extraction, the four detectors, and
  the evidence-integrity logic. **Pairing/teaching mode**, one function/module at a
  time: Claude explains the decisions in plain language (jargon defined) → shows the
  complete code → user reads it line by line and approves → only then does Claude write
  it to the file → stop for the next checkpoint. No unprompted full-detector dumps, no
  chaining multiple core files together, no writing to disk before approval.
- **`[INDEP]`** — pure plumbing: scaffold, FastAPI, SQLite/DAO, file storage, frontend,
  PDF, test harness. **Claude writes these directly**, user reviews the diff.

Full loop detail (including how to answer "why X not Y" and what subtleties to call out)
lives in [`../CLAUDE.md`](../CLAUDE.md) "Collaboration model" — this is the summary, that
is the source of truth.

**Parallelism:** while a `[CORE]` item is mid-checkpoint, Claude can build the next
phase's `[INDEP]` plumbing. Phase N core work and Phase N+1 plumbing can overlap.

> **Current model — updated 2026-08-23 (pairing mode)**, see [`handoff.md`](handoff.md)
> "Collaboration model" and [`../CLAUDE.md`](../CLAUDE.md). Refines the 2026-08-21
> version: code now gets explained and shown in full *before* it's written to disk,
> not drafted-then-reviewed. Phase order and file list below are unchanged.

All work follows the [`../CLAUDE.md`](../CLAUDE.md) coding standards: functions ≤50–60 lines,
the shared `Detector` interface, one source of truth for thresholds, strict separation of
concerns (parsing never touches the DB, detectors never touch HTTP).

---

## Phase 0 — Foundation & contracts  ·  `[INDEP]`

The scaffolding the user later fills. No business logic yet — just the shapes everything
plugs into.

- `[INDEP]` Repo scaffold per [`docs/architecture.md`](docs/architecture.md):
  `backend/{ingest,parse,detectors,evidence,report,db,api}`, `frontend/`, `sample-pcaps/`.
- `[INDEP]` **Shared data models, defined once** (single source of truth):
  `Flow`, `Features`, `Finding` (carries the human-readable evidence string),
  `SealRecord`, `CustodyEntry`.
- `[INDEP]` **Detector base interface:** `Detector.run(flows) -> list[Finding]`.
- `[INDEP]` **Config module:** all thresholds, baselines, and allowlists in one place — no
  magic numbers anywhere else.
- `[INDEP]` Test harness + tiny crafted pcap fixtures; dependency setup (`requirements`,
  tshark availability check).

**Deliverable:** importable skeleton, every interface defined, test suite runs (red).

---

## Phase 1 — Vertical slice  ·  *(mixed)*

The thinnest end-to-end path. Proves the whole spine works before deepening any stage.

- `[INDEP]` Upload endpoint + file storage.
- `[INDEP]` SQLite seal table + DAO.
- `[INDEP]` Pipeline orchestrator (wires the four stages).
- `[INDEP]` Minimal forensic PDF.
- `[INDEP]` Minimal React upload + results page.
- `[CORE]` BLAKE3 seal function (hash the pcap on ingest → `SealRecord`).
- `[CORE]` dpkt bulk parse → DNS flows.
- `[CORE]` **DNS-exfil entropy detector** — the first real detector (most iconic and
  explainable: Shannon entropy ~2.5 benign vs ~4.2+ encoded).

**Checkpoint:** upload a real pcap → it is sealed → a DNS-exfil finding with its evidence
string → exported to PDF.

---

## Phase 2 — Parsing depth & remaining detectors  ·  *(mostly `[CORE]`, Claude scaffolds)*

- `[CORE]` Full flow/feature extraction, incl. PyShark TLS handshake parsing + **JA3**
  computation.
- `[CORE]` **C2 beaconing** detector — inter-arrival-time regularity.
- `[CORE]` **Port scan / recon** detector — fan-out analysis.
- `[CORE]` **JA3 fingerprinting** detector — JA3 hash matched vs abuse.ch SSLBL.
- `[INDEP]` SSLBL blocklist fetch + local cache.
- `[INDEP]` Allowlist wiring (CDN/heartbeat false-positive suppression).
- `[INDEP]` Route all findings through the pipeline + DB; results UI renders every detector
  type.

**Checkpoint:** all four detectors fire on curated pcaps, each emitting its evidence
string.

---

## Phase 3 — Evidence-integrity layer  ·  *(`[CORE]` logic + `[INDEP]` plumbing)* — **the differentiator**

This is the product. Make tamper-evidence genuine, not cosmetic.

- `[CORE]` Custody **hash-chain** — each entry references the prior entry's hash, so no
  entry can be altered or removed without breaking every later link.
- `[CORE]` **Integrity-verify** — re-hash the stored pcap → compare to the seal → flag
  mismatch as a broken chain of custody.
- `[CORE]` RFC 3161 timestamp **verification** logic.
- `[INDEP]` Append-only custody-log table + DAO (append-only enforced; no edits/deletes).
- `[INDEP]` RFC 3161 TSA client **with offline/cached fallback** (open risk #1 — must not
  hard-fail on demo-day wifi).
- `[INDEP]` Verify endpoint + "tamper test" UI control.

**Checkpoint:** flip one byte of a sealed pcap → re-verify → the tool declares the evidence
altered and the chain broken. *This 10-second demo is the pitch.*

---

## Phase 4 — Report, polish & demo hardening  ·  *(mostly `[INDEP]`)*

- `[INDEP]` Full forensic PDF: findings + evidence + custody trail + verification status.
- `[INDEP]` Dashboard polish.
- `[INDEP]` **Curate sample pcaps so every detector fires** (open risk #2).
- `[INDEP]` Written demo script.
- `[CORE]` Tune thresholds against real captures.
- `[CORE]` Finalize evidence-string wording + the "court-admissible" → "evidentiary
  integrity / tamper-evident" reframing (open risk #3).

**Checkpoint:** rehearsed end-to-end — upload → detect → explain → verify → court-ready
report.

---

## Cross-cutting

**Open risks** (tracked live in [`docs/handoff.md`](docs/handoff.md)):
1. RFC 3161 TSA choice + offline fallback — addressed in Phase 3.
2. Curate demo pcaps so all four detectors fire — addressed in Phases 2 & 4.
3. "Court-admissible" wording → reframe toward "evidentiary integrity / tamper-evident."
4. tshark installed on the demo laptop — verify early (Phase 0 dependency check).

**Build order rationale:** shared models/interfaces (Phase 0) precede all
implementations; parsing precedes detectors; detectors precede the evidence layer and
report. The vertical slice (Phase 1) front-loads demo confidence; the differentiator
(Phase 3) gets dedicated, disproportionate effort.
