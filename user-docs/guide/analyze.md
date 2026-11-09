# analyze

Seal and store a capture (exactly like [`seal`](seal.md)), then print the seal, the number
of flows and every finding the detectors produced.

```bash
python -m backend.cli [--store DIR] [--offline] analyze <pcap>
```

## A capture with a finding

```text
--8<-- "user-docs/examples/analyze-c2-beacon.txt"
```

## A capture with none

```text
--8<-- "user-docs/examples/analyze-benign.txt"
```

`Findings 0` is a result, not an error: the rules did not fire on this capture. It does not
mean the capture is harmless; see [Limits](../reference/limits.md).

## Reading a finding

```text
[MEDIUM] c2_beacon: 10.0.0.5 -> 198.51.100.7
  Why       ...
  Evidence  ...
```

- The tag is the **severity** (`MEDIUM` or `HIGH`) and the name of the detector.
- **Why** says in plain language what the pattern usually means.
- **Evidence** lists every measurement the rule looked at, with its cutoff and whether it
  was met, including measurements that did not cross their cutoff. The sentence is
  written so you can re-compute the numbers yourself.

[Findings format](../reference/findings.md) has the full structure; the
[detector pages](../concepts/detectors.md) explain each rule.

## Three detectors, three captures

| Capture | What fires |
|---|---|
| `synthetic-dns-exfil.pcap` | `dns_exfil`, HIGH. See the [quick start](../getting-started/quick-start.md). |
| `synthetic-c2-beacon.pcap` | `c2_beacon`, MEDIUM (above). |
| `synthetic-port-scan.pcap` | `port_scan`, MEDIUM: |

```text
--8<-- "user-docs/examples/analyze-port-scan.txt"
```

Here 200 distinct ports met their cutoff, but one distinct host did not meet the host
cutoff of 10, so the severity is MEDIUM rather than HIGH.

## Notes

- Everything `seal` says about timestamps and errors applies here too.
- Detector thresholds are fixed in the program's configuration;
  [Configuration](../reference/configuration.md) lists them. There are no command-line flags
  to change them, on purpose: a finding must be reproducible.
