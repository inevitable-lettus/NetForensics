"""Environment readiness check. Run before a demo to catch the dependency risks
flagged in docs/handoff.md — most importantly tshark (open risk #4), which the
PyShark parse path needs and which is NOT bundled with pip.

Exit code 0 = all hard requirements present. tshark missing is a WARNING, not a
failure: the dpkt parse path runs without it.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys

# Python import name -> pip package name (where they differ).
_REQUIRED_MODULES = {
    "dpkt": "dpkt",
    "numpy": "numpy",
    "scipy": "scipy",
    "blake3": "blake3",
    "fastapi": "fastapi",
    "reportlab": "reportlab",
    "pytest": "pytest",
}


def _check_modules() -> list[str]:
    missing: list[str] = []
    for module, package in _REQUIRED_MODULES.items():
        if importlib.util.find_spec(module) is None:
            missing.append(package)
            print(f"  [MISSING] {module}  (pip install {package})")
        else:
            print(f"  [ok]      {module}")
    return missing


def _check_tshark() -> bool:
    path = shutil.which("tshark")
    if path:
        print(f"  [ok]      tshark  ({path})")
        return True
    print("  [WARN]    tshark not found — PyShark TLS/DNS path disabled; "
          "dpkt path still works. Install Wireshark before the demo (risk #4).")
    return False


def main() -> int:
    print("Python:", sys.version.split()[0])
    print("\nRequired modules:")
    missing = _check_modules()
    print("\nExternal tools:")
    _check_tshark()

    if missing:
        print(f"\nFAIL: {len(missing)} required package(s) missing: {', '.join(missing)}")
        return 1
    print("\nOK: all hard requirements present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
