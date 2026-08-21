---
title: DNS Exfil Detector — Concepts & Python Syntax
project: NetForensics
phase: Phase 1 — vertical slice
file: backend/detectors/dns_exfil.py
date: 2026-08-20
tags: [netforensics, python, detectors, dns, learning]
---

# DNS Exfil Detector — Concepts & Python Syntax

Working notes for writing `backend/detectors/dns_exfil.py`.
Design source: `docs/logic.md` §1. Contract: `backend/detectors/base.py`.

> [!info] Prerequisite status
> `backend/parse/dns_parser.py` does **not** exist yet. Not a blocker.
> The detector consumes `Flow` objects with `DnsFeatures` already populated, and
> `tests/fixtures/pcap_builder.py::dns_flow()` builds those directly.
> → Detector is writable and fully testable today. Real pcaps wait on the parser.

---

## 0. What the detector does

Class subclassing `Detector`. Input `Sequence[Flow]`, output `list[Finding]`.
Three signals, every threshold read from `self.config.dns_exfil` — never hard-coded.

| Signal | Field on `DnsFeatures` | Config threshold | Value |
|---|---|---|---|
| Randomness | `max_subdomain_entropy` | `entropy_threshold` | 4.2 (benign baseline 2.5) |
| Tunnel payload size | `max_subdomain_length` | `subdomain_length_threshold` | 30 |
| Volume | `query_count` / duration | `query_rate_threshold` | 50 per 60s |

Plus suppression: `config.allowlists.dns_parent_domains` (CDNs are legitimately high-entropy).

Every finding must carry WHAT / WHY / SUPPORTING DATA + a courtroom-ready `evidence`
sentence. No confidence scores (Hard Rule 1).

---

## 1. Subclassing an ABC

`Detector` is abstract (`ABC` + `@abstractmethod`). Python refuses to instantiate it
directly — `tests/test_detector_interface.py::test_base_detector_is_abstract` proves it.
A subclass becomes concrete by implementing `run`.

```python
class DnsExfilDetector(Detector):
    name = "dns_exfil"          # class attribute — shared by all instances

    def run(self, flows: Sequence[Flow]) -> list[Finding]:
        ...
```

- `name` sits at **class level**, not inside `__init__`. Still read as `self.name`.
- Write **no `__init__`** — the base class already does `self.config = config`.
  Inheritance gives that for free.
- `self` = the instance, passed automatically. `detector.run(flows)` → `run(detector, flows)`.

## 2. `from __future__ import annotations`

First line of every module in this repo. Makes Python treat type hints as strings rather
than evaluating them. Lets you write `str | None` and `list[Finding]` on older versions,
and avoids import cycles. Copy the pattern.

## 3. Reading nested frozen dataclasses

Path: `Flow` → `.features` → `.dns` → fields.
`dns` is `DnsFeatures | None` — **None whenever the flow isn't DNS**. Never assume.

```python
dns = flow.features.dns
if dns is None:
    continue            # skip non-DNS flows
entropy = dns.max_subdomain_entropy
```

- `frozen=True` → immutable. `dns.query_count = 5` raises `FrozenInstanceError`.
  Good: detectors are pure, they read input and produce output, never mutate.
- `is None`, not `== None`. Identity check — the idiom.

## 4. Guard clauses over nested ifs

CLAUDE.md caps nesting at 3 levels.

Bad — 4 deep, unreadable:

```python
for flow in flows:
    if flow.features.dns is not None:
        if not allowlisted:
            if entropy > threshold:
                findings.append(...)
```

Good — bail early, stay flat:

```python
for flow in flows:
    dns = flow.features.dns
    if dns is None:
        continue
    if _is_allowlisted(dns.parent_domain, self.config.allowlists.dns_parent_domains):
        continue
    triggers = self._check_signals(dns, flow)
    if not triggers:
        continue
    findings.append(self._build_finding(dns, flow, triggers))
```

- `continue` → skip to next loop iteration.
- `return` → leave the function now.
- Both flatten code. Reach for them before an `else`.

## 5. Accumulating a list

```python
findings: list[Finding] = []      # annotated empty list
findings.append(one_finding)      # add one
findings.extend(many_findings)    # add several
return findings
```

Comprehension only when it is a pure one-line map/filter:

```python
dns_flows = [f for f in flows if f.features.dns is not None]
```

Explicit loop when the body does real work. Don't force a comprehension.

## 6. Allowlist matching with `endswith`

Parent `d3ab1c.cloudfront.net` must match allowlist entry `cloudfront.net` — suffix
match, not equality. `str.endswith` accepts a tuple and returns True on any match.

> [!warning] Suffix-match bug
> `"evilcloudfront.net".endswith("cloudfront.net")` → `True`.
> Anchor on the dot.

```python
def _is_allowlisted(domain: str, allowlist: tuple[str, ...]) -> bool:
    domain = domain.lower().rstrip(".")     # DNS names may carry a trailing dot
    return any(domain == entry or domain.endswith("." + entry) for entry in allowlist)
```

- `any(...)` → True if any element truthy. `all(...)` is the mirror.
- The thing inside is a **generator expression** — lazy, stops at the first True.
- `.rstrip(".")` strips trailing dots (FQDNs often end with one).

## 7. Threshold comparison — config only

```python
cfg = self.config.dns_exfil          # local alias, saves repetition
if dns.max_subdomain_entropy >= cfg.entropy_threshold:
```

- Never write `4.2` inside the detector. One-source-of-truth rule;
  `test_detector_interface.py::test_detector_reads_thresholds_from_config` guards it.
- Pick `>=` and stay consistent.
- Floats: never test equality.

## 8. Query rate needs a duration

`query_count` is a raw count; the threshold is "50 per 60s". Normalize with the flow's timespan.

```python
duration = (flow.end_time - flow.start_time).total_seconds()

if duration <= 0:
    rate = float(dns.query_count)          # single instant — treat count as the rate
else:
    rate = dns.query_count / duration * cfg.query_rate_window_secs
```

- `datetime - datetime` → `timedelta`; `.total_seconds()` → float.
- Guard the zero. Float division by zero raises `ZeroDivisionError` and single-packet
  flows will hit it.

## 9. Combining the signals (design call, not syntax)

Don't OR everything — length alone fires on long legitimate CDN names.
**Recommended: entropy required, plus at least one corroborating signal.**

```python
entropy_hit = dns.max_subdomain_entropy >= cfg.entropy_threshold
length_hit  = dns.max_subdomain_length  >= cfg.subdomain_length_threshold
rate_hit    = rate                       >= cfg.query_rate_threshold

if not entropy_hit:
    continue
corroborating = length_hit or rate_hit

severity = Severity.HIGH if (length_hit and rate_hit) else Severity.MEDIUM
```

Ternary: `A if cond else B` — reads "A, when cond, otherwise B".

> [!important] Non-obvious entropy math
> Shannon entropy per char maxes at `log2(distinct chars)`, itself capped by string
> length. A 10-char subdomain can **never** exceed 3.32 bits.
> Threshold 4.2 therefore implicitly requires length ≥ 19.
> So "entropy required" is weaker than it looks on long tunnel labels, and short labels
> can't trip it at all. Keep in mind when tuning.

## 10. Grouping flows by parent domain (optional refinement)

Per-flow `query_count` may undercount if the parser emits one flow per DNS conversation.
Aggregating across flows sharing a parent is truer to "312 queries in 60s to one parent".

```python
from collections import defaultdict

by_parent: dict[str, list[Flow]] = defaultdict(list)
for flow in dns_flows:
    by_parent[flow.features.dns.parent_domain].append(flow)

for parent, group in by_parent.items():
    total_queries = sum(f.features.dns.query_count for f in group)
    peak_entropy  = max(f.features.dns.max_subdomain_entropy for f in group)
```

- `defaultdict(list)` auto-creates `[]` on first touch — no `if key not in d` dance.
- `.items()` yields `(key, value)` pairs, unpacked into two loop variables.
- `max(...)` / `sum(...)` over a generator; add `default=0.0` if the group can be empty.

**Today's simpler path:** one finding per flow. Ship it, revisit grouping once the parser
exists and real shapes are visible. Detector stays pure either way.

## 11. f-strings for the evidence line

The courtroom sentence. Must carry the measured value **and** the benign baseline.

```python
evidence = (
    f"Subdomain {longest!r} of {parent!r} has Shannon entropy "
    f"{entropy:.2f} (benign baseline ~{cfg.benign_entropy_baseline}), "
    f"with {total_queries} queries in {window}s — consistent with encoded "
    f"data exfiltrated over DNS."
)
```

- `f"..."` → expressions inside `{}` evaluated and inserted.
- `{entropy:.2f}` → format spec, 2 decimals. Without it you print `4.199999999`.
- `{longest!r}` → `repr()`, wraps strings in quotes. Good for domains in evidence text.
- Adjacent string literals concatenate automatically. No `+` needed.
- Whole thing in parens → line breaks without backslashes.
- Never build this with `+` and `str()`.

## 12. Constructing the Finding

Keyword arguments, always. Positional args on a 6-field dataclass is how `what` and `why`
get silently swapped.

```python
Finding(
    detector=self.name,
    what=f"DNS parent domain {parent}",
    why="Subdomain randomness far exceeds benign DNS, with sustained query volume "
        "to a single parent — the signature of data encoded into DNS queries.",
    supporting_data={
        "max_subdomain_entropy": round(entropy, 2),
        "benign_entropy_baseline": cfg.benign_entropy_baseline,
        "entropy_threshold": cfg.entropy_threshold,
        "max_subdomain_length": length,
        "query_count": total_queries,
        "window_secs": cfg.query_rate_window_secs,
    },
    evidence=evidence,
    severity=severity,
)
```

- `supporting_data` is `dict[str, object]` — plain dict literal, `"key": value`.
- Put **every number the evidence string quotes** in it, plus the baseline compared against.
- That dict is what the PDF renders; `evidence` is the prose version of the same facts.

## 13. Helper functions and the 50-line rule

`run` will blow past 60 lines if everything is inlined. Split:

```python
def _is_allowlisted(domain: str, allowlist: tuple[str, ...]) -> bool: ...
def _query_rate(dns: DnsFeatures, flow: Flow, window_secs: int) -> float: ...
def _build_evidence(...) -> str: ...
```

- Leading `_` = module-private by convention, not enforced.
- Module-level functions (not methods) when they don't need `self` — pure and directly testable.
- Type hints on every one.
- If `_build_finding` wants more than ~4 params → pass a small dataclass or the `Flow`
  itself instead of 7 loose values.

## 14. The test — `tests/test_dns_exfil.py`

Two cases minimum per CLAUDE.md (fires / doesn't), and **assert on the evidence string**.

```python
from tests.fixtures.pcap_builder import dns_flow

def test_fires_on_high_entropy_tunnel(config):
    flow = dns_flow(
        parent="evil.example.com",
        subdomains=["a8f3k2j9d0s7f6g5h4j3k2l1m0n9b8v7c6x5z4"],
        entropy=4.6,
        query_count=300,
    )
    findings = DnsExfilDetector(config).run([flow])
    assert len(findings) == 1
    assert "4.6" in findings[0].evidence
    assert "2.5" in findings[0].evidence          # baseline must appear

def test_silent_on_benign_dns(config):
    flow = dns_flow("google.com", ["www"], entropy=1.5, query_count=3)
    assert DnsExfilDetector(config).run([flow]) == []

def test_allowlisted_cdn_suppressed(config):
    flow = dns_flow("d3ab1c.cloudfront.net", ["d3ab1c9f8e7d6c5b4a3f2e1d0c9b8a7f6e5"], 4.8, 400)
    assert DnsExfilDetector(config).run([flow]) == []
```

- `config` is the fixture from `tests/conftest.py` — pytest injects it by **parameter name**.
- `dns_flow` computes `max_subdomain_length` itself from the strings passed in, so make the
  fake subdomain genuinely long to trip the length signal.

```bash
python -m pytest tests/test_dns_exfil.py -q
```

---

## Build order

1. `_is_allowlisted` + its test — smallest, pure, no dependencies.
2. `_query_rate` + its test — exercise the divide-by-zero guard.
3. `run` skeleton: loop, guards, `continue`s, `return []`.
4. Signal booleans read from config.
5. `_build_evidence` + `Finding` construction.
6. The three detector tests.

## Open questions to revisit

- [ ] Per-flow findings vs. grouped-by-parent-domain aggregation → decide after the parser lands.
- [ ] Whether `entropy_threshold` 4.2 needs lowering once real captures are seen (see entropy-math note in §9).
- [ ] Severity mapping — is `HIGH` only for all-three-signals, or entropy+rate too?

## Related

- `docs/logic.md` — detector spec + evidence-string wording
- `docs/architecture.md` — pipeline stage order
- `backend/config.py` — `DnsExfilConfig`, `Allowlists`
- `backend/models.py` — `DnsFeatures`, `Flow`, `Finding`, `Severity`
- `backend/parse/entropy.py` — `shannon_entropy()` (already written; used by the parser, not the detector)
