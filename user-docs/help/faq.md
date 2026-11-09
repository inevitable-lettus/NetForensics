# FAQ

## Is the output court-admissible?

No claim of that kind is made. The output is **tamper-evident, designed toward admissibility**:
it can show the stored capture has not changed since it was sealed. Whether any court accepts it
is not something software can certify, and depends on jurisdiction, how the capture was taken
and who testifies.

## Does INTACT mean the capture is genuine?

No. It means the stored capture matches its seal, and that an outside authority signed the seal
at a given time. It says nothing about whether the capture was complete or honest when it was
taken.

## Why does it say `PENDING`?

No timestamp authority has signed the seal yet: you ran with `--offline`, or the authority could
not be reached. The tool never invents a timestamp. See
[Troubleshooting](troubleshooting.md#the-timestamp-stays-pending).

## Can it run with no internet?

Yes. Use `--offline`: you get seals, analysis and the hash and chain checks, and the verdict is
INCOMPLETE rather than INTACT until a timestamp exists. Run `retry-timestamps` later.

## What is sent to the timestamp authority?

Only the SHA-256 of the capture (and, for anchors, the SHA-256 of a chain head), plus a random
number. Never the capture, its name or its contents.

## Why is there no confidence score?

A score hides the reasoning. Each finding lists the values it measured and the cutoffs it was
compared with, so a person can agree or disagree with the rule itself.

## Why can I not change a threshold from the command line?

So a finding is reproducible from the capture and the program alone. Thresholds are in
`backend/config.py`; if you change them, record the change with the case.

## It found nothing. Is the capture clean?

No. `Findings 0` means these three rules did not fire. They look for data in DNS names,
regular timing, and wide scans, in plain-text metadata. See [Limits](../reference/limits.md).

## It flagged something harmless. Why?

See [Known limitations](known-limitations.md). Content-delivery networks, software updaters and
discovery protocols look like attacks to a rule that only sees randomness and timing.

## Can I use a pcapng file?

Convert it first: `editcap -F pcap in.pcapng out.pcap`.

## What about the web interface?

The repository contains a web API and a React frontend. They are kept but are not part of v1; the
command line is the supported interface and the only one documented here.

## Where does the data live, and can I delete a case?

Under the store directory ([layout](../reference/storage.md)). The database refuses updates and
deletes by design. To discard a case you delete the whole store directory, which also destroys
its evidence.
