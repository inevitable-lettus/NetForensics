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
- Build roadmap created: [`plan.md`](plan.md) — phased, with `[CORE]`/`[INDEP]`
  ownership tags. — 2026-06-23
- **Phase 0 scaffold** — repo layout, shared models, detector interface, config,
  test harness, dep-check. — 2026-06-25

## Next up (Phase 1 — Vertical slice)

Per [`plan.md`](plan.md) file/phase order; ownership tags superseded — see
"Collaboration model" above. User writes every item solo, Claude explains + reviews.

- [x] BLAKE3 seal function (pcap → `SealRecord`) — `backend/evidence/seal.py`.
      Smoke-tested manually (temp file → correct `SealRecord`, all fields populated).
- [x] `tests/test_seal.py` — deterministic-hash + one-byte-flip-changes-hash cases.
      Untracked, not yet committed.
- [x] `backend/parse/entropy.py` — `shannon_entropy(text) -> float`, bits/char via
      `Counter` + `-Σp·log2(p)`. Untracked, not yet committed. No unit test yet.
- [ ] **DNS-exfil detector (`backend/detectors/dns_exfil.py`) — in progress.** Concepts +
      Python syntax explained and written up in
      [`notes/dns-exfil-detector.md`](notes/dns-exfil-detector.md). Now the first
      pairing-mode core-logic item per the updated collaboration model — draft one
      piece, explain, checkpoint. Testable now against `dns_flow()` fixtures — does NOT
      need the parser first. `entropy.py` above is its dependency.
- [ ] dpkt bulk parse → DNS flows (`backend/parse/dns_parser.py`).
- [ ] Upload endpoint + file storage; SQLite seal table + DAO; pipeline orchestrator;
      minimal PDF; minimal React upload/results page.

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

Authoritative roadmap is [`plan.md`](plan.md). Phases: 0 Foundation & contracts →
1 Vertical slice (upload→seal→DNS-exfil→PDF) → 2 Parsing depth & remaining detectors →
3 Evidence-integrity layer (the differentiator) → 4 Report, polish & demo.

## Collaboration model — updated 2026-08-21 (pairing mode)

Superseded the 2026-07-16 "user writes everything solo" model (kept below for
history). New split, per [`../CLAUDE.md`](../CLAUDE.md) "Collaboration model":

- **Plumbing** (FastAPI, SQLite, React, PDF export) — Claude writes directly, user
  reviews the diff. No walkthrough.
- **Core logic** (four detectors + evidence-integrity layer) — pairing/teaching mode.
  Claude drafts one function/module at a time, briefly explains the approach *before*
  writing, stops for review after each piece, never chains core files without a
  checkpoint. If the user asks "why X not Y," answer by teaching trade-offs/failure
  modes. Call out subtleties (hash collisions, timestamp forgery, FP rates) explicitly.
  No unprompted full-detector dumps. If the user goes quiet at a checkpoint, ping
  rather than assume approval and continue.

This is a personal project, no deadline — the point is learning the concepts, not
just shipping. Supersedes the `[CORE]`/`[INDEP]` tags in [`plan.md`](plan.md) as the
*working* model (those tags now map to: `[CORE]` = pairing/teaching mode, `[INDEP]` =
Claude writes directly); plan.md's phase/file order still holds.

<details>
<summary>Previous model — 2026-07-16 (historical)</summary>

User is learning Python and wanted to write **every part of the codebase themselves**,
not just `[CORE]` items — including the `[INDEP]` plumbing plan.md assigned to Claude
solo. Loop was: Claude explains the concept + what's supposed to happen (plain
language, no code) → user researches + writes it → user asks for help only if stuck.
</details>

## Collaboration model — refined 2026-08-23

Same pairing-mode split as 2026-08-21 (plumbing direct, core logic teaching mode), but
the `[CORE]` loop now gates writing to disk on approval, instead of drafting the file
then reviewing it:

explain decisions in plain language, jargon defined → show the complete code → user
reads it line by line and approves → **only then** write the file → stop for next
checkpoint.

Full detail in [`../CLAUDE.md`](../CLAUDE.md) "Collaboration model" (source of truth);
[`plan.md`](plan.md) ownership section carries the short summary. Also fixed broken
`../plan.md` relative links across this file and `plan.md` (both live in `docs/`, so
links needed to be `plan.md` / `../CLAUDE.md` not `../plan.md` / `CLAUDE.md`) and added
`plan.md` to the doc table in `../CLAUDE.md` (it was missing despite being the build-order
reference). No application code written this session.

## Open decisions / risks to resolve

| # | Issue | Why it matters | Status |
|---|---|---|---|
| 1 | **RFC 3161 TSA choice + offline fallback** | Live TSA will fail on demo-day wifi and kill the headline feature. Pick a TSA (e.g. freeTSA.org) and cache/fallback so it never hard-fails. | OPEN |
| 2 | **Curate demo pcaps so all 4 detectors fire** | A demo where TLS/SSLBL shows zero hits is weak. Hand-pick captures from malware-traffic-analysis.net per detector. | OPEN |
| 3 | **"Court-admissible" wording** | Overclaiming invites a brutal judge question. Reframe toward "evidentiary integrity / tamper-evident, designed toward admissibility." Prove tamper-evidence live instead. | OPEN |
| 4 | **tshark on the demo laptop** | PyShark needs tshark installed; verify on the actual machine. Keep dpkt path independent. | OPEN — confirmed MISSING on this dev machine (`scripts/check_deps.py`). `brew install wireshark` before relying on PyShark; dpkt path unaffected. |
| 5 | **Custody-log tamper-evidence mechanism** | Decide hash-chained entries (each references prior). Must be genuine, not cosmetic. | OPEN |

- **2026-08-23** — Refined the pairing-mode `[CORE]` loop: explain decisions in plain
  language (jargon defined) → show complete code → user reads line by line and approves
  → only then write the file, replacing the 2026-08-21 version's "draft then review"
  order. Updated `../CLAUDE.md` "Collaboration model" (source of truth) and `plan.md`
  ownership section to match; added `plan.md` to `../CLAUDE.md`'s doc table (was
  missing); fixed broken `../plan.md`/`CLAUDE.md` relative links in this file and
  `plan.md` (both live in `docs/`, links pointed one directory too high). No application
  code written this session.
- **2026-08-21** — Collaboration model changed to **pairing mode** (see
  [`../CLAUDE.md`](../CLAUDE.md) "Collaboration model" and updated section above):
  Claude writes plumbing directly; core logic (detectors, evidence layer) goes back to
  Claude drafting one piece at a time with a brief explain-first + review checkpoint,
  replacing the 2026-07-16 "user writes everything solo" model. Updated all four
  context docs to match, incl. renaming the 4th detector "malicious TLS client" →
  "JA3 fingerprinting" throughout (mechanism unchanged — JA3 hash vs. abuse.ch SSLBL).
  Also reconciled this file with actual untracked repo state: `tests/test_seal.py` and
  `backend/parse/entropy.py` exist but aren't committed yet; `docs/notes/` untracked.
  No detector code written this session.
- **2026-08-20** — Session was explain-only, no application code written. Walked the
  full concept + Python-syntax set needed for the DNS-exfil detector (ABC subclassing,
  guard clauses, `None` handling on `Features.dns`, allowlist suffix-matching with
  dot-anchoring, query-rate normalisation via `total_seconds()`, signal combination,
  f-string evidence construction, `Finding` keyword construction, helper decomposition,
  test shape). Captured as durable notes: [`notes/dns-exfil-detector.md`](notes/dns-exfil-detector.md).
  Noted two things worth carrying forward: (a) `dns_parser.py` is NOT a blocker — the
  detector consumes `Flow`+`DnsFeatures` and is fully testable today against
  `tests/fixtures/pcap_builder.py::dns_flow`; (b) entropy math caps per-char Shannon at
  `log2(len)`, so the 4.2 threshold implicitly requires subdomain length >= 19 — may need
  tuning against real captures. Next: user writes `backend/detectors/dns_exfil.py` +
  `tests/test_dns_exfil.py`, then `tests/test_seal.py` still outstanding.

- **2026-07-16 (cont.)** — `backend/evidence/seal.py` `seal_pcap()` written by user,
  reviewed line-by-line (fixed: `f.read()` vs `...` placeholder, filename via
  `os.path.basename`, dropped a confused `int.to_bytes`/`int()` round-trip for the size
  field, removed dead unreachable code). Smoke-tested — works correctly. Next: write
  `tests/test_seal.py`, then move to dpkt DNS parsing.
- **2026-07-16** — Decided collaboration model: user writes all code solo (learning
  Python), Claude's role narrows to explaining concepts + scaffolding tests, not
  co-authoring implementations. Walked full Phase 1–4 file-by-file build order (see
  plan.md phases). Starting Phase 1 step 1: `backend/evidence/seal.py`
  (BLAKE3 seal function) — concept explained, user writing it solo. No code written
  this session yet.
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
- **2026-06-23** — Created [`plan.md`](plan.md): phased build roadmap with
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
