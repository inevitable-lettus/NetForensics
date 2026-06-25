# Handoff — Living State

**Read this first each session.** This is the only doc that changes every session. It
holds where the build is, what to do next, and unresolved decisions. For the design see
[`architecture.md`](architecture.md) and [`logic.md`](logic.md).

---

## Current phase

**Phase 0 complete.** Scaffold + contracts in place, test suite green (8 passed),
deps install on Python 3.14. Next concrete work is **Phase 1 — vertical slice**.

## Done so far

- Solution document (`NetForensics_Solution_Document.docx`) and flow diagram
  (`NetForensics_Flow_Diagram.pdf`) authored.
- Context docs created: `CLAUDE.md`, `docs/architecture.md`, `docs/logic.md`,
  `docs/handoff.md` (this file). — 2026-06-21
- Build roadmap created: [`../plan.md`](../plan.md) — phased, with `[CORE]`/`[INDEP]`
  ownership tags. — 2026-06-23
- **Phase 0 scaffold** — repo layout, shared models, detector interface, config,
  test harness, dep-check. — 2026-06-25

## Next up (Phase 1 — Vertical slice) · *(mixed)*

Per [`../plan.md`](../plan.md). Thinnest end-to-end path: upload → seal → DNS-exfil
→ PDF. `[INDEP]` items Claude builds solo; `[CORE]` items follow the
stub→user-implements loop.

- [ ] `[INDEP]` Upload endpoint + file storage; SQLite seal table + DAO; pipeline
      orchestrator; minimal PDF; minimal React upload/results page.
- [ ] `[CORE]` BLAKE3 seal function (pcap → `SealRecord`).
- [ ] `[CORE]` dpkt bulk parse → DNS flows.
- [ ] `[CORE]` DNS-exfil entropy detector (first real detector).

### Phase 0 — done

- [x] Repo scaffold per [`architecture.md`](architecture.md) layout.
- [x] Shared data models defined once: `Flow`/`Features`, `Finding`, `SealRecord`,
      `CustodyEntry` (`backend/models.py`).
- [x] Detector base interface `Detector.run(flows) -> list[Finding]`
      (`backend/detectors/base.py`).
- [x] Config module — single source of truth (`backend/config.py`, `CONFIG` singleton).
- [x] Test harness + dependency-free pcap/flow fixtures; `requirements.txt`,
      `scripts/check_deps.py` (tshark availability check).
- [x] Filled the **Commands** section in [`../CLAUDE.md`](../CLAUDE.md).

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
| 4 | **tshark on the demo laptop** | PyShark needs tshark installed; verify on the actual machine. Keep dpkt path independent. | OPEN — confirmed MISSING on this dev machine (`scripts/check_deps.py`). `brew install wireshark` before relying on PyShark; dpkt path unaffected. |
| 5 | **Custody-log tamper-evidence mechanism** | Decide hash-chained entries (each references prior). Must be genuine, not cosmetic. | OPEN |

## Session log (newest first)

- **2026-06-25** — **Phase 0 scaffold shipped** (all `[INDEP]`). Created
  `backend/{ingest,parse,detectors,evidence,report,db,api}`, `frontend/`,
  `sample-pcaps/`, `tests/`, `scripts/`. Shared models in `backend/models.py`
  (`Flow`/`Features`/`DnsFeatures`/`TlsFeatures`, `Finding`+`Severity`, `SealRecord`,
  `CustodyEntry`). Detector contract `backend/detectors/base.py`. Single-source config
  `backend/config.py` (`CONFIG`). Dependency-free fixtures (`tests/fixtures/pcap_builder.py`:
  libpcap byte writer + flow builders). Contract tests green — **8 passed**.
  `requirements.txt` + `pyproject.toml` (pytest config) + `scripts/check_deps.py`.
  Verified: full `requirements.txt` installs on Python 3.14.3 in `.venv/`. tshark
  confirmed MISSING (risk #4). Filled CLAUDE.md Commands. Repo on `main`, NOT committed —
  awaiting user. Next: Phase 1 vertical slice.
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
