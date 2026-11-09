# Getting started

Three short pages take you from a fresh clone to a verified case.

1. **Install** (this page): Python, a virtual environment and the dependencies.
2. [Quick start](quick-start.md): seal, analyze, verify and tamper with a sample capture.
3. [Your first investigation](first-investigation.md): read findings, decide what they
   mean, and keep the evidence in a state you can defend.

## Install

You need Python 3.11 or newer and `git`. Run everything from the repository root.

```bash
git clone https://github.com/inevitable-lettus/NetForensics.git
cd NetForensics
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

Check that the environment is ready:

```bash
python scripts/check_deps.py
```

The script lists missing Python packages and whether `tshark` is installed.

!!! info "tshark is optional"
    `tshark` (part of Wireshark) is only used by the PyShark parse path. The default
    parser (`dpkt`) needs no system packages, and every command in this documentation
    works without `tshark`. Install it with `brew install wireshark` (macOS) or your
    platform's package manager if you want it.

Run the test suite to confirm the install:

```bash
python -m pytest -q
```

Tests that need the internet (a real timestamp-authority round trip) are skipped by
default; opt in with `python -m pytest -m network`.

## Next

Go to the [Quick start](quick-start.md).
