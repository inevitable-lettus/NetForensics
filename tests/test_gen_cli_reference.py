"""The generated CLI reference must be plain text whatever the Python version or colour setting."""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "gen_cli_reference.py"


def _generator():
    spec = importlib.util.spec_from_file_location("gen_cli_reference", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reference_has_no_colour_codes_even_when_colour_is_forced(monkeypatch):
    # Python 3.14+ argparse colours its help when FORCE_COLOR is set.
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert "\x1b" not in _generator().render()


def test_checked_in_page_matches_the_generator_with_colour_forced(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    generator = _generator()
    assert generator.TARGET.read_text() == generator.render()
