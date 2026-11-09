# Reference

Exact facts, for lookup.

| Page | Contents |
|---|---|
| [Command line](cli.md) | Every command, option and exit code. Generated from the program's own parser. |
| [Configuration](configuration.md) | Detector thresholds, allowlists, ingest and timestamp settings. |
| [Findings](findings.md) | The fields of a finding and the evidence sentence format. |
| [Storage layout](storage.md) | What is written to the evidence store and how it is protected. |
| [Limits](limits.md) | What the tool accepts and what it deliberately does not do. |

!!! info "What is generated"
    The command-line page is generated from the argparse parser in `backend/cli.py` by
    `scripts/gen_cli_reference.py`. Every command output shown anywhere on this site is
    produced by `scripts/check_docs_examples.py`. CI fails if either is out of date.
