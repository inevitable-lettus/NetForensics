# Handoff — Living State

**Read this first each session.** This is the only doc that changes every session. It
holds where the build is, what to do next, and unresolved decisions. For the design see
[`architecture.md`](architecture.md) and [`logic.md`](logic.md).

---

## Current phase

**Phase 0 complete.** Phase 1 vertical slice underway — DNS-exfil detector drafted,
dpkt DNS parser drafted (helpers only, grouping into Flow/DnsFeatures still open),
entropy now tested. Test suite green (33 passed). Next concrete work: finish
`dns_parser.py` (group parsed queries into `Flow`+`DnsFeatures` per
(src_ip, parent_domain)) so it plugs into the DNS-exfil detector end-to-end.

## Done so far

- Solution document (`NetForensics_Solution_Document.docx`) and flow diagram
  (`NetForensics_Flow_Diagram.pdf`) authored.
- Context docs created: `CLAUDE.md`, `docs/architecture.md`, `docs/logic.md`,
  `docs/handoff.md` (this file). — 2026-06-21
- Build roadmap created: [`../plan.md`](../plan.md) — phased, with `[CORE]`/`[INDEP]`
  ownership tags. — 2026-06-23
- **Phase 0 scaffold** — repo layout, shared models, detector interface, config,
  test harness, dep-check. — 2026-06-25
- **DNS-exfil detector** (`backend/detectors/dns_exfil.py`) — `_is_allowlisted`,
  `_query_rate`, `_longest_subdomain`, `DnsExfilDetector.run/_evaluate/_build_finding`.
  10 tests in `tests/test_dns_exfil.py`. — 2026-08-25
- **`backend/parse/entropy.py`** (`shannon_entropy`) — now covered by
  `tests/test_entropy.py` (5 cases: empty string, uniform-repeat zero, 1-bit/2-bit
  known values, random-like > low-entropy sanity check). — 2026-08-27
- **`backend/parse/dns_parser.py`** (plumbing, Claude-direct per pairing-mode split) —
  `_iter_dns_queries` (single-pass dpkt walk, UDP/53 only, skips malformed/non-DNS
  packets) and `_split_domain` (naive last-two-labels heuristic, documented
  multi-part-TLD limitation e.g. `co.uk`). 9 tests in `tests/test_dns_parser.py`.
  **Not yet wired to `Flow`/`DnsFeatures`** — no top-level function groups queries by
  (src_ip, parent_domain) yet, so it doesn't feed the DNS-exfil detector end-to-end.
  Untracked, uncommitted. — 2026-08-27
- Full suite: **33 passed.**

## Next up (Phase 1 — Vertical slice)

Per [`../plan.md`](../plan.md) file/phase order; ownership tags superseded — see
"Collaboration model" above. User writes every item solo, Claude explains + reviews.

- [x] BLAKE3 seal function (pcap → `SealRecord`) — `backend/evidence/seal.py`.
      Smoke-tested manually (temp file → correct `SealRecord`, all fields populated).
- [x] `tests/test_seal.py` — deterministic-hash + one-byte-flip-changes-hash cases.
      Untracked, not yet committed.
- [x] `backend/parse/entropy.py` — `shannon_entropy(text) -> float`, bits/char via
      `Counter` + `-Σp·log2(p)`. Untracked, not yet committed. No unit test yet.
- [x] **DNS-exfil detector (`backend/detectors/dns_exfil.py`) — drafted, pending
      user review.** Built piece-by-piece per pairing mode: `_is_allowlisted` →
      `_query_rate` → `run`/`_evaluate`/`_build_finding`. 10 tests pass. Open call
      flagged for review: severity is `HIGH` only when *both* length and rate
      corroborate entropy, `MEDIUM` if just one — confirm that split is wanted.
- [x] `backend/parse/entropy.py` unit tests (`tests/test_entropy.py`, 5 cases).
- [~] dpkt bulk parse → DNS flows (`backend/parse/dns_parser.py`) — helpers drafted
      and tested (`_iter_dns_queries`, `_split_domain`), grouping into
      `Flow`/`DnsFeatures` still open. — **NEXT UP.**
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

Authoritative roadmap is [`../plan.md`](../plan.md). Phases: 0 Foundation & contracts →
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

## Open decisions / risks to resolve

| # | Issue | Why it matters | Status |
|---|---|---|---|
| 1 | **RFC 3161 TSA choice + offline fallback** | Live TSA will fail on demo-day wifi and kill the headline feature. Pick a TSA (e.g. freeTSA.org) and cache/fallback so it never hard-fails. | OPEN |
| 2 | **Curate demo pcaps so all 4 detectors fire** | A demo where TLS/SSLBL shows zero hits is weak. Hand-pick captures from malware-traffic-analysis.net per detector. | OPEN |
| 3 | **"Court-admissible" wording** | Overclaiming invites a brutal judge question. Reframe toward "evidentiary integrity / tamper-evident, designed toward admissibility." Prove tamper-evidence live instead. | OPEN |
| 4 | **tshark on the demo laptop** | PyShark needs tshark installed; verify on the actual machine. Keep dpkt path independent. | OPEN — confirmed MISSING on this dev machine (`scripts/check_deps.py`). `brew install wireshark` before relying on PyShark; dpkt path unaffected. |
| 5 | **Custody-log tamper-evidence mechanism** | Decide hash-chained entries (each references prior). Must be genuine, not cosmetic. | OPEN |

- **2026-08-27** — Closed testing gap flagged 2026-08-25: `backend/parse/entropy.py`
  had no unit test — added `tests/test_entropy.py` (empty string, uniform-repeat,
  known 1-bit/2-bit values, random-like-vs-benign sanity check). Also cleaned trailing
  dead blank lines in `entropy.py`. Confirmed `backend/parse/dns_parser.py` (untracked)
  is further along than this file previously recorded: `_iter_dns_queries` +
  `_split_domain` drafted and covered by 9 tests, but the grouping step that turns
  parsed queries into `Flow`/`DnsFeatures` (per (src_ip, parent_domain), per the
  module docstring) is not written yet — parser doesn't feed the DNS-exfil detector
  end-to-end. Full suite now **33 passed**. Nothing committed this session — `dns_exfil.py`,
  `dns_parser.py`, `test_dns_exfil.py`, `test_dns_parser.py`, `test_entropy.py` all
  still untracked. Open item carried forward: confirm DNS-exfil HIGH-severity split
  (both signals vs. either) before moving on. Next: finish `dns_parser.py` grouping
  function, then commit the DNS-exfil vertical slice as a unit.
- **2026-08-25** — Drafted `backend/detectors/dns_exfil.py` end-to-end in pairing mode:
  `_is_allowlisted` (dot-anchored suffix match, checkpoint+tested), `_query_rate`
  (normalizes count to per-window rate, zero-duration guard, checkpoint+tested), then
  `DnsExfilDetector.run`/`_evaluate`/`_build_finding` (entropy required + length-or-rate
  corroboration, HIGH only when both corroborate). 10 tests added
  (`tests/test_dns_exfil.py`); full suite 20 passed. Mid-session the user changed the
  teaching-mode workflow: explain code **line by line before writing it**, not a brief
  approach summary beforehand with detail after — `CLAUDE.md` "Collaboration model"
  updated to require this going forward (applies to remaining core-logic pieces: the
  parser is plumbing/Claude-direct, but the C2/port-scan/JA3 detectors and the
  evidence-integrity layer are core logic and fall under the new rule). Open item:
  confirm the HIGH-severity split (both signals vs. either) before moving on.
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
