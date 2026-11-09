# User guide

One page per command. All commands run as `python -m backend.cli [options] <command>` from
the repository root. The full option list is generated in the
[command-line reference](../reference/cli.md).

| Command | Use it to | Network |
|---|---|---|
| [`seal`](seal.md) | Seal and store a capture as a case; print only the seal. | Timestamp authority, unless `--offline` |
| [`analyze`](analyze.md) | Same intake as `seal`, and also print every finding. | Same |
| [`verify`](verify.md) | Re-check a stored case and get INTACT, ALTERED or INCOMPLETE. | Anchors the chain head, unless `--offline` |
| [`retry-timestamps`](retry-timestamps.md) | Ask the authority again for every seal that is still `PENDING`. | Yes |
| [`tamper-demo`](tamper-demo.md) | See tampering caught, on a throwaway copy. | Timestamp authority, unless `--offline` |

## Options that go before the command

| Option | Meaning |
|---|---|
| `--store DIR` | Where cases live. Default `evidence_store/` in the current directory. Holds the database, the stored captures and staging files together. |
| `--offline` | Never contact the timestamp authority. Seals and anchors stay `PENDING`; nothing is faked. |

```bash
python -m backend.cli --store ./cases --offline analyze capture.pcap
```

Putting an option after the command is a usage error (exit code 2).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. `verify`: INTACT. `tamper-demo`: the altered copy was caught. |
| 1 | Error (one `error:` line on standard error), or `verify`: ALTERED. |
| 2 | `retry-timestamps` left a seal `PENDING`; `verify`: INCOMPLETE; or a usage error. |

## Input rules

- Classic `.pcap` only. A pcapng file is refused with a hint to convert it
  (`editcap -F pcap`).
- Up to 512 MiB.
- The file is streamed, never loaded whole into memory.
