# Findings

A finding is the result of one detector rule firing. It is built to be explainable: it
carries the entity, the reason, the numbers and one sentence that ties them together.

| Field | Type | Meaning |
|---|---|---|
| `detector` | text | Which rule fired: `dns_exfil`, `c2_beacon` or `port_scan`. |
| `what` | text | The entity flagged: a parent domain, a host pair or a source address. |
| `why` | text | The reason in plain language. |
| `supporting_data` | key/value pairs | The measured values and the baselines or cutoffs they were compared with. |
| `evidence` | text | One sentence built from the fields above; shown by `analyze`. |
| `severity` | `info`, `low`, `medium`, `high` | In practice `medium` or `high`; see below. |

There is no confidence score, by design.

## The evidence sentence

Every detector builds its sentence from one template:

```text
<what was flagged>: <measured thing> <value> (cutoff: at least|at most <cutoff>,
met|not met[; context]); ... Meaning: <plain-language meaning>.
```

Rules:

- Every measurement the rule looked at is listed, **including ones that did not cross their
  cutoff**, so you can see how close a result is.
- *met* / *not met* is the detector's own decision, not recomputed for display.
- A value that would round onto a cutoff it did not equal is printed with more decimals, so
  the number and the verdict never disagree.

## Severity

| Detector | MEDIUM | HIGH |
|---|---|---|
| `dns_exfil` | Entropy cutoff met, plus the length **or** the rate cutoff. | Entropy, length **and** rate cutoffs all met. |
| `c2_beacon` | Always. | Never. |
| `port_scan` | The port **or** the host cutoff met. | Both met. |

Severity measures how much independent evidence agreed. It is not a probability of harm.

## Where findings are stored

In the case's `findings` table and, as events, in the custody chain. See
[Storage layout](storage.md).
