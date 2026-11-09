# seal

Hash a capture, ask the timestamp authority to sign the hash, and store the capture as a
new case. It prints the seal only; [`analyze`](analyze.md) takes the same steps and also
prints the findings.

```bash
python -m backend.cli [--store DIR] [--offline] seal <pcap>
```

## Example

```text
--8<-- "user-docs/examples/seal-dns-exfil.txt"
```

| Line | Meaning |
|---|---|
| `Case` | The id to give to `verify`. |
| `File` | The file name and size as received. |
| `BLAKE3`, `SHA-256` | Two independent fingerprints of the whole file, computed in one pass. |
| `Received` | When this system took the file in (its own clock). |
| `Timestamp` | `PENDING` until an authority signs the seal. With a live authority it reads `GRANTED by <authority> at <time>`. |

## When to use it

Use `seal` when you only need the case id and the seal, for example in a script. Both
commands run the same intake: the capture is sealed, stored, parsed and checked by the
detectors, and the findings are stored with the case. Running either one on the same file
again creates another case, so run one of them once per capture.

## Notes

- The capture is sealed **before** it is parsed. Nothing the parser does can change what
  was sealed.
- Sealing the same bytes twice creates two cases that share one stored copy.
- A slow authority can delay the command by up to 5 seconds. Beyond that the case is stored
  `PENDING` and the command still succeeds.
- Errors: a missing file, a non-pcap file, a pcapng file or a file over 512 MiB print one
  `error:` line and exit with code 1. See [Troubleshooting](../help/troubleshooting.md).
