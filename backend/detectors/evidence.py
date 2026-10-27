"""The one evidence-sentence template every detector uses (dev-notes question F, option 1).

Every `Finding.evidence` reads the same way, so a reviewer always finds the same four
things in the same order:

    <subject>: <measured thing> <value> (cutoff: <at least|at most> <cutoff>, <met|not met>
    [; <context>]); <next measurement> ... Meaning: <plain-language meaning>.

Each measurement says whether it crossed its cutoff, so a finding that fires on one of
two measurements (a port scan on ports but not hosts) shows that plainly instead of
leaving the reader to compare numbers. The met/not met verdict is the detector's own
decision, passed in, so the rule lives in one place. Numbers are formatted here, once:
a value is shown with more decimals when rounding would make it print the same as a
cutoff it did not equal, so the printed number never contradicts the verdict.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum


class Cutoff(str, Enum):
    AT_LEAST = "at least"   # fires when value >= cutoff
    AT_MOST = "at most"     # fires when value <= cutoff


@dataclass(frozen=True)
class Measurement:
    """One measured number, the cutoff it is judged against, whether the detector found
    it met, and optional context (a baseline or the numbers it was computed from)."""

    name: str
    value: float
    cutoff: float
    direction: Cutoff
    met: bool
    unit: str = ""
    decimals: int = 0
    context: str | None = None

    def render(self) -> str:
        unit = f" {self.unit}" if self.unit else ""
        verdict = "met" if self.met else "not met"
        extra = f"; {self.context}" if self.context else ""
        return (f"{self.name} {self._value_text()}{unit} (cutoff: {self.direction.value} "
                f"{plain_number(self.cutoff)}{unit}, {verdict}{extra})")

    def _value_text(self) -> str:
        """The value at `decimals`, widened (up to 6) while it would still print the same
        as an unequal cutoff: 49.587 against 50 shows "49.6", not "50"."""
        if self.value == self.cutoff:
            return f"{self.value:.{self.decimals}f}"
        for decimals in range(self.decimals, _MAX_DECIMALS + 1):
            text = f"{self.value:.{decimals}f}"
            if float(text) != self.cutoff:
                return text
        return repr(float(self.value))  # e.g. 0.30000000000000004 against 0.3


_MAX_DECIMALS = 6


def plain_number(number: float) -> str:
    """A cutoff or baseline as typed in config: 50, 0.1, 2000000 (never 2e+06)."""
    if float(number).is_integer():
        return str(int(number))
    return f"{number:.{_MAX_DECIMALS}f}".rstrip("0")


def evidence_sentence(subject: str, measurements: Sequence[Measurement], meaning: str) -> str:
    """Join the parts in the fixed order. `meaning` is one plain sentence, no jargon."""
    if not measurements:
        raise ValueError("Evidence needs at least one measurement.")
    body = "; ".join(measurement.render() for measurement in measurements)
    return f"{subject}: {body}. Meaning: {meaning.rstrip('.')}."
