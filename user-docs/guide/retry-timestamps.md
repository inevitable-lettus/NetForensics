# retry-timestamps

Ask the timestamp authority again for every seal that is still `PENDING`.

```bash
python -m backend.cli [--store DIR] retry-timestamps
```

A seal is `PENDING` when the authority could not be reached or answered "not yet" at the
time of sealing, or when you ran with `--offline`. The case is complete and usable; it
simply has no outside clock vouching for its seal.

## What it does

- Retries each `PENDING` case up to three times, waiting longer between attempts.
- Stores a reply only if it passes every check: granted, signed by the pinned authority
  certificate, valid at its own time, marked for time stamping, covering exactly the sealed
  hash, and echoing the random number the request carried. A bad reply is refused, not stored.
- Stops the whole run after three cases in a row find the authority unreachable, so an
  outage does not make you wait on every case.

## Example (offline)

```text
--8<-- "user-docs/examples/retry-timestamps-offline.txt"
```

With `--offline` it reports the pending count and changes nothing. Online, it prints one
line per case (case id, outcome, number of attempts, detail) and a summary such as
`3 case(s): 2 granted, 1 still pending, 0 error(s).`

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No seal is `PENDING` any more. |
| 1 | At least one retry ended in an error. |
| 2 | At least one seal is still `PENDING`. |

After a successful retry, run [`verify`](verify.md) again: the timestamp check can now pass.
