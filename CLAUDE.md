# NetForensics

Explainable packet-forensics tool for cybercrime investigators. Ingests a `.pcap`,
runs four transparent detectors (DNS exfil, C2 beaconing, port scan, malicious TLS),
and wraps results in a **court-admissible evidence layer** (BLAKE3 hash + RFC 3161
trusted timestamp + append-only chain of custody → forensic PDF report).

Built for **KANAD S.H.I.E.L.D. 2026** (Ahmedabad City Police Cybersecurity Innovation
Challenge) · Category 2 · Problem ID `KANADSHIELD26_P2_08`.

**The differentiator is the evidence-integrity layer, not the detection.** Zeek/Suricata
already detect these patterns; nobody else seals the evidence and proves to a court it
was not altered. Invest there.

## Guiding principle

> Explainability and evidentiary integrity over algorithmic sophistication. Every
> finding must be something a human investigator can understand, defend, and present
> in a court of law.

This governs every design choice — most importantly, **why there is no ML/LLM core**:
"the AI flagged it" does not survive cross-examination; "this subdomain has entropy 4.2
where benign sits near 2.5" does.

## Read this first

**Start every session by reading [`docs/handoff.md`](docs/handoff.md)** — it holds the
current build state, what to do next, and open decisions.

| Doc | What it holds |
|---|---|
| [`docs/handoff.md`](docs/handoff.md) | **Living state** — current phase, done/next, open risks, session log. Read first. |
| [`docs/architecture.md`](docs/architecture.md) | System structure — pipeline, stack, data flow, repo layout, dependency risks. |
| [`docs/logic.md`](docs/logic.md) | Business rules — detector formulas/thresholds, evidence-layer mechanics, explainability contract. |
| `NetForensics_Solution_Document.docx` | Original source — full proposal. The docs above are extracted from it. |
| `NetForensics_Flow_Diagram.pdf` | Original source — pipeline flow diagram. |

## Hard rules

1. **No ML/LLM black-box detector core.** Admissibility requires explainable rules. A
   confidence score is not defensible in court.
2. **Every detector emits human-readable evidence.** A finding without its triggering
   evidence (the measured number vs. the benign baseline) is incomplete.
3. **The evidence/custody layer is the product.** Make tamper-evidence *genuine*, not
   cosmetic — disproportionate effort goes here.
4. **Scope is fixed to four detectors.** Resist scope creep (no live capture, no TCP
   reassembly, no ML). Shippable beats ambitious. New detectors plug in without
   touching the evidentiary core.

## Coding standards

Keep the codebase clean enough that any session can read a module and understand it in a
minute. **No spaghetti.** These are enforced, not aspirational.

### Functions & files
- **Functions ≤ 50–60 lines.** If one grows past that, it is doing too much — extract.
- **One job per function.** A function name should fully describe what it does; if you
  need "and" to describe it, split it.
- **Files stay focused.** One detector per module, one concern per file (per the
  [`docs/architecture.md`](docs/architecture.md) layout). Aim for files under ~300 lines.
- **≤ 3 levels of nesting.** Use early returns / guard clauses instead of deep `if`
  pyramids.
- **Few parameters.** More than ~4 → pass a dataclass / typed object.

### Reuse & DRY — the anti-spaghetti rules
- **Search before you write.** Before adding a helper, look for an existing one. Do not
  reimplement hashing, entropy, flow access, or DB calls in two places.
- **Every detector implements the same interface** (e.g. `Detector.run(flows) ->
  list[Finding]`). Shared logic (entropy, timing stats, allowlist checks) lives in a
  common module, not copy-pasted per detector.
- **One source of truth.** Thresholds, baselines, and config live in one place (a config
  module), not scattered as magic numbers. The `Finding` / evidence shape is defined
  once and reused everywhere.
- **Rule of three:** the second time you copy code, extract it; never a third copy.

### Structure & clarity
- **Separation of concerns is non-negotiable.** Parsing never touches the DB; detectors
  never touch HTTP; report generation never re-parses pcaps. Data flows one direction
  through the pipeline stages — no stage reaches backwards.
- **Pure functions where possible.** Detectors take data in, return findings out — no
  hidden global state, no side effects. This is also what makes them testable and
  court-defensible.
- **Type hints on every public function.** They are documentation that can't go stale.
- **Names over comments.** Prefer a clear name to a comment explaining an unclear one.
  Comment *why*, not *what*.
- **Fail loudly, early.** Validate inputs at boundaries (upload, parse) and raise with a
  clear message rather than letting bad data flow downstream.

### Efficiency
- **Stream / single-pass over large captures.** Don't load a whole pcap into memory or
  iterate the packet list repeatedly — dpkt does the bulk pass once; detectors consume
  the extracted flows, not raw packets again.
- **Measure before optimizing.** Correct and explainable first; fast second. Don't add
  complexity for speed the demo doesn't need.

### Tests
- Each detector gets a unit test with a tiny crafted input proving it fires (and a benign
  input proving it doesn't). The evidence string is part of what's asserted.

## Commands

_To be filled when the scaffold exists (Phase 0)._

```
# run backend      — TBD (FastAPI)
# run frontend     — TBD (React)
# run tests        — TBD
# analyze a pcap   — TBD
```

## Doc maintenance

- Update [`docs/handoff.md`](docs/handoff.md) at the **end of every session** (add a
  dated session-log entry; refresh current phase / next-up / open risks).
- Update `architecture.md` / `logic.md` **only when the design itself changes**, not
  routinely. Keep roles separate — do not duplicate detail across docs.
