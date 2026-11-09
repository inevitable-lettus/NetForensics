# Troubleshooting

Errors print one line starting `error:` on standard error and exit with code 1. Find the
message below.

## Errors on `seal` and `analyze`

| Message | Cause | Fix |
|---|---|---|
| `<path> is not a file.` | The path is wrong, or names a directory. | Check the path; run from the repository root. |
| `File is not a libpcap capture (bad or missing header).` | The file is not a classic pcap. | Check the file type. A text file, an archive or a truncated download all give this. |
| `pcapng captures are not supported yet; convert with editcap -F pcap.` | The capture is pcapng, which Wireshark often saves by default. | Convert it: `editcap -F pcap in.pcapng out.pcap` (comes with Wireshark), or re-save as "Wireshark/tcpdump - pcap". |
| `Upload exceeds the 536870912-byte limit.` | The file is over 512 MiB. | Split or trim it with `editcap`, or raise `max_upload_bytes` in `backend/config.py`. |
| `Stored evidence <sha256> now hashes to <sha256>: the stored copy was altered. It is left in place for investigation.` | The same bytes were sealed before, and the stored copy of them no longer matches its name. | Treat this as a finding about the store: run `verify` on the earlier case and do not delete the file. |

```text
--8<-- "user-docs/examples/analyze-not-a-pcap.txt"
```

## Usage errors (exit code 2)

`unrecognized arguments: --offline` (or `--store`) means the option came after the command.
Options go **before** the command name:

```bash
python -m backend.cli --offline analyze capture.pcap     # right
python -m backend.cli analyze capture.pcap --offline     # usage error
```

## Timestamps

### The timestamp stays `PENDING`

You ran with `--offline`, the authority could not be reached, or it answered "not yet". The
case is complete; it just has no outside clock yet.

1. Check the machine can reach `https://freetsa.org/tsr` (a firewall or proxy may block it).
2. Run `python -m backend.cli retry-timestamps` (without `--offline`).
3. Run `verify` again.

A retry run stops after three cases in a row find the authority unreachable; run it again
later rather than in a loop.

### A reply was refused

The authority's reply failed one of the checks (see
[the evidence layer](../concepts/evidence-layer.md#timestamps-that-cannot-be-faked)). The
case stays `PENDING` and the reason is printed. If it persists across several tries, the
authority's certificate may have been renewed; the pinned copy in `backend/evidence/certs/`
would then need updating.

## The verdict is INCOMPLETE

Exit code 2. Nothing failed; a timestamp or anchor is `PENDING`. See above, then verify again.
If it stays INCOMPLETE after a successful retry, read the `[NOT RUN]` lines: each says what
it is waiting for. A pending **anchor** is not upgraded later; the next `verify` creates a new
one, so verifying once more online usually clears it.

## The verdict is ALTERED

Exit code 1. At least one check failed. **Do not run anything that writes to the case.**

1. Read the `[FAIL]` lines. Each names the values compared.
2. `pcap_digests` fails: the stored capture no longer matches the seal. Compare the stored
   file under `blobs/` with your original; the original may still be good.
3. `custody_chain` fails: the message names the first entry where the chain breaks and why
   (altered, wrong link, wrong index).
4. `chain_head_anchor` fails: an anchored entry is missing or has a different hash; entries may
   have been removed from the end.
5. Record that you ran `verify` and what it said; an ALTERED case is left unchanged, so the
   chain itself will not hold that fact.

An ALTERED verdict says the evidence **no longer matches its seal**. It does not say who
changed it or why.

## `verify` says `error:` and exits 1

Exit code 1 is shared with ALTERED. Standard error tells them apart: an error prints
`error:`, ALTERED prints `[FAIL]` lines on standard output.

```text
--8<-- "user-docs/examples/verify-unknown-case.txt"
```

An unknown case id prints `no case with id` and the id you typed. Check that `--store` points at the store the case was
made in; each store has its own database.

## `tshark` not found

Only matters for the optional PyShark parse path. Every command here uses the default parser.
`python scripts/check_deps.py` reports it; install Wireshark if you want it.

## `ModuleNotFoundError: backend`

Run the commands from the repository root, with the virtual environment active.
