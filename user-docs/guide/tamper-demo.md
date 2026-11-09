# tamper-demo

Show the tamper check working. A ten-second proof that changing a sealed capture is caught.

```bash
python -m backend.cli [--offline] tamper-demo <pcap>
```

It always works in a throwaway store; a `--store` given before the command is ignored.

## What it does

1. Creates a temporary store and seals a copy of your capture in it.
2. Verifies the case (the "before" column).
3. Flips **one bit** of the stored copy, at the middle byte of the file.
4. Verifies again (the "after" column).
5. Prints both side by side and deletes the store.

Your capture is only read. Nothing is written to your own store.

## Example

```text
--8<-- "user-docs/examples/tamper-demo.txt"
```

Read the table:

- `pcap_digests` goes from PASS to FAIL. The evidence sentence names the sealed and the
  measured digest; one flipped bit changes both completely.
- `custody_chain` and `seal_binding` still PASS, because the log itself was not touched;
  only the capture was.
- The verdict goes from `INCOMPLETE` to `ALTERED`. Online, "before" is `INTACT`.

The exit code is 0 when the altered copy was caught and 1 if it was not, so the command also
works as a smoke test in a script.

## The note at the end

The last line, "nothing was written to its custody chain", comes from the second
verification, which leaves an ALTERED case exactly as found (see
[`verify`](verify.md#an-altered-case-is-left-as-found)). It goes to standard error, so on a
terminal it may appear earlier than it does here; this page shows standard error after
standard output so the example is the same on every run.
