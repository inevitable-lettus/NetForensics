"""Run every command shown in the user documentation and compare its output with the
copy the site embeds (user-docs/examples/*.txt).

    python scripts/check_docs_examples.py            # exit 1 if any example changed (CI)
    python scripts/check_docs_examples.py --update   # rewrite the example files

Every example runs with --offline against the synthetic captures in sample-pcaps/
(python scripts/make_synthetic_pcaps.py), so it needs no network and gives the same
output every run once case ids, times, paths and chain hashes are masked.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import blake3

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "user-docs" / "examples"
PCAPS = ROOT / "sample-pcaps"
CLI = [sys.executable, "-m", "backend.cli", "--offline"]

# name -> (pcap, command). "verify" reuses the case made by the "analyze" of that pcap.
SEQUENCE = [
    ("seal-dns-exfil", "synthetic-dns-exfil.pcap", ["seal", "{pcap}"]),
    ("analyze-dns-exfil", "synthetic-dns-exfil.pcap", ["analyze", "{pcap}"]),
    ("analyze-c2-beacon", "synthetic-c2-beacon.pcap", ["analyze", "{pcap}"]),
    ("analyze-port-scan", "synthetic-port-scan.pcap", ["analyze", "{pcap}"]),
    ("analyze-benign", "synthetic-benign.pcap", ["analyze", "{pcap}"]),
    ("verify-offline", "synthetic-dns-exfil.pcap", ["verify", "{case}"]),
    ("retry-timestamps-offline", None, ["retry-timestamps"]),
    ("tamper-demo", "synthetic-dns-exfil.pcap", ["tamper-demo", "{pcap}"]),
    ("verify-unknown-case", None, ["verify", "00000000000000000000000000000000"]),
    ("analyze-not-a-pcap", None, ["analyze", "README.md"]),
]

HEX64 = re.compile(r"\b[0-9a-f]{64}\b")
HEX32 = re.compile(r"\b[0-9a-f]{32}\b")
TIME = re.compile(r"\d{4}-\d\d-\d\dT[\d:.]+\+00:00")


def _digests(pcap: Path) -> set[str]:
    data = pcap.read_bytes()
    return {hashlib.sha256(data).hexdigest(), blake3.blake3(data).hexdigest()}


def _mask(text: str, keep: set[str]) -> str:
    """Hide what changes between runs. Digests of the capture stay; so do the values
    `verify` measures after a bit flip, because the flip is deterministic."""
    def hexes(match: re.Match[str]) -> str:
        before = text[max(0, match.start() - 9):match.start()]
        if match.group(0) in keep or before.endswith("measured "):
            return match.group(0)
        return "<hash>"
    text = HEX64.sub(hexes, text)
    text = HEX32.sub("<case-id>", text)
    text = TIME.sub("<time>", text)
    text = re.sub(r"Throwaway store \S+", "Throwaway store <path>", text)
    return text


def _run(store: str, args: list[str]) -> tuple[str, int]:
    done = subprocess.run([*CLI, "--store", store, *args], cwd=ROOT, text=True,
                          capture_output=True, check=False)
    # Standard error is shown after standard output: the order a reader sees is the
    # order the program wrote them only on a terminal, and the docs must not depend on it.
    return done.stdout + done.stderr, done.returncode


def build() -> dict[str, str]:
    results: dict[str, str] = {}
    cases: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="nf-docs-") as scratch:
        for name, pcap, command in SEQUENCE:
            path = PCAPS / pcap if pcap else None
            if path is not None and not path.exists():
                sys.exit(f"{path} is missing: run python scripts/make_synthetic_pcaps.py")
            store = str(Path(scratch) / name)
            argv = []
            for word in command:
                if word == "{pcap}":
                    argv.append(f"sample-pcaps/{pcap}")
                elif word == "{case}":
                    argv.append(cases[pcap])
                else:
                    argv.append(word)
            if command[0] == "verify" and pcap:
                store = str(Path(scratch) / "analyze-dns-exfil")
            if command[0] == "retry-timestamps":
                store = str(Path(scratch) / "seal-dns-exfil")
            output, code = _run(store, argv)
            made = re.search(r"^Case\s+(\w+)", output, re.M)
            if command[0] == "analyze" and made and pcap:
                cases[pcap] = made.group(1)
            keep = _digests(path) if path else set()
            if command[0] == "tamper-demo":
                keep |= set(HEX64.findall(output))  # the flipped digests are fixed
            shown_args = ["<case-id>" if a in cases.values() else a for a in argv]
            line = _mask("$ python -m backend.cli --offline " + " ".join(shown_args), set())
            results[name] = f"{line}\n{_mask(output, keep)}[exit code {code}]\n"
    return results


def main() -> int:
    update = "--update" in sys.argv[1:]
    stale = []
    for name, text in build().items():
        target = EXAMPLES / f"{name}.txt"
        if update:
            target.write_text(text)
        elif not target.exists() or target.read_text() != text:
            stale.append(target.relative_to(ROOT))
    if stale:
        print("these examples no longer match the tool's output "
              "(run scripts/check_docs_examples.py --update and review the diff):",
              *map(str, stale), sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
