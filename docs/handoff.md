# Handoff — Living State

**Read this first each session.** This is the only doc that changes every session. It
holds where the build is, what to do next, and unresolved decisions. For the design see
[`architecture.md`](architecture.md) and [`logic.md`](logic.md).

---

## Current phase

**Pre–Phase 0.** No code yet. Context docs just created. Next concrete work is the
Phase 0 scaffold.

## Done so far

- Solution document (`NetForensics_Solution_Document.docx`) and flow diagram
  (`NetForensics_Flow_Diagram.pdf`) authored.
- Context docs created: `CLAUDE.md`, `docs/architecture.md`, `docs/logic.md`,
  `docs/handoff.md` (this file). — 2026-06-21
- Build roadmap created: [`../plan.md`](../plan.md) — phased, with `[CORE]`/`[INDEP]`
  ownership tags. — 2026-06-23

## Next up (Phase 0 — Foundation & contracts) · `[INDEP]`

Per [`../plan.md`](../plan.md). Scaffolding the user later fills; no business logic yet.

- [ ] Repo scaffold per [`architecture.md`](architecture.md) layout.
- [ ] Shared data models defined once: `Flow`, `Features`, `Finding`, `SealRecord`,
      `CustodyEntry`.
- [ ] Detector base interface: `Detector.run(flows) -> list[Finding]`.
- [ ] Config module (single source of truth for thresholds/baselines/allowlists).
- [ ] Test harness + crafted pcap fixtures; `requirements` + tshark availability check.
- [ ] Fill the **Commands** section in [`../CLAUDE.md`](../CLAUDE.md) once runnable.

## Roadmap snapshot

Authoritative roadmap is [`../plan.md`](../plan.md). Phases: 0 Foundation & contracts →
1 Vertical slice (upload→seal→DNS-exfil→PDF) → 2 Parsing depth & remaining detectors →
3 Evidence-integrity layer (the differentiator) → 4 Report, polish & demo.

## Open decisions / risks to resolve

| # | Issue | Why it matters | Status |
|---|---|---|---|
| 1 | **RFC 3161 TSA choice + offline fallback** | Live TSA will fail on demo-day wifi and kill the headline feature. Pick a TSA (e.g. freeTSA.org) and cache/fallback so it never hard-fails. | OPEN |
| 2 | **Curate demo pcaps so all 4 detectors fire** | A demo where TLS/SSLBL shows zero hits is weak. Hand-pick captures from malware-traffic-analysis.net per detector. | OPEN |
| 3 | **"Court-admissible" wording** | Overclaiming invites a brutal judge question. Reframe toward "evidentiary integrity / tamper-evident, designed toward admissibility." Prove tamper-evidence live instead. | OPEN |
| 4 | **tshark on the demo laptop** | PyShark needs tshark installed; verify on the actual machine. Keep dpkt path independent. | OPEN |
| 5 | **Custody-log tamper-evidence mechanism** | Decide hash-chained entries (each references prior). Must be genuine, not cosmetic. | OPEN |

## Session log (newest first)

- **2026-06-23** — Created [`../plan.md`](../plan.md): phased build roadmap with
  `[CORE]`/`[INDEP]` ownership tags. Strategy locked: user owns all algorithmic code
  (parsing, detectors, evidence logic) with "Claude scaffolds stub+test → user
  implements"; Claude builds plumbing solo; vertical-slice-first build order. Added
  coding-standards section to `CLAUDE.md`. No application code yet. Next: Phase 0
  scaffold & contracts.
- **2026-06-21** — Created the four context docs (`CLAUDE.md` + `docs/{architecture,logic,handoff}.md`),
  extracting content from the solution doc and flow diagram. Defined strict per-doc roles
  to prevent drift. No code written. Next: Phase 0 scaffold.

---

## How to update this file (do at the end of every session)

1. Add a dated entry to the top of **Session log** — what you did, what changed.
2. Refresh **Current phase**, **Done so far**, and **Next up** to match reality.
3. Update **Open decisions / risks** — mark resolved ones RESOLVED with the outcome; add
   new ones.
4. Only touch [`architecture.md`](architecture.md) / [`logic.md`](logic.md) if the
   *design* changed — not for routine progress.
