"""The one evidence-sentence template every detector uses (dev-notes question F, option 1).

Every `Finding.evidence` reads the same way, so a reviewer always finds the same four
things in the same order:

    <subject>: <measured thing> <value> (cutoff: <at least|at most> <cutoff>, <met|not met>
    [; <context>]); <next measurement> ... Meaning: <plain-language meaning>.

Each measurement says whether it crossed its cutoff, so a finding that fires on one of
two measurements (a port scan on ports but not hosts) shows that plainly instead of
leaving the reader to compare numbers. Numbers are formatted here, once, with a fixed
number of decimals per measurement.
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
    """One measured number, the cutoff it is judged against, and optional context
    (a baseline or the numbers it was computed from)."""

    name: str
    value: float
    cutoff: float
    direction: Cutoff
    unit: str = ""
    decimals: int = 0
    context: str | None = None

    @property
    def met(self) -> bool:
        if self.direction is Cutoff.AT_LEAST:
            return self.value >= self.cutoff
        return self.value <= self.cutoff

    def render(self) -> str:
        unit = f" {self.unit}" if self.unit else ""
        verdict = "met" if self.met else "not met"
        extra = f"; {self.context}" if self.context else ""
        return (f"{self.name} {self.value:.{self.decimals}f}{unit} "
                f"(cutoff: {self.direction.value} {self.cutoff:g}{unit}, {verdict}{extra})")


def evidence_sentence(subject: str, measurements: Sequence[Measurement], meaning: str) -> str:
    """Join the parts in the fixed order. `meaning` is one plain sentence, no jargon."""
    if not measurements:
        raise ValueError("Evidence needs at least one measurement.")
    body = "; ".join(measurement.render() for measurement in measurements)
    return f"{subject}: {body}. Meaning: {meaning.rstrip('.')}."
