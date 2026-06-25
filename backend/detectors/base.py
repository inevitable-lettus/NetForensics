"""The detector contract. Every detector implements the same interface so new
detectors plug in without touching the evidentiary core (Hard Rule 4).

Detectors are pure: data in (flows), findings out. No DB access, no HTTP, no
hidden global state — this is what makes them testable and court-defensible
(CLAUDE.md: pure functions, separation of concerns).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from backend.config import Config
from backend.models import Finding, Flow


class Detector(ABC):
    """Base class for the four explainable detectors.

    Subclasses set `name` and implement `run`. They receive the shared `Config`
    at construction so all thresholds come from the single source of truth —
    never hard-coded inside the detector.
    """

    #: stable identifier emitted on every Finding (e.g. "dns_exfil")
    name: str = "detector"

    def __init__(self, config: Config) -> None:
        self.config = config

    @abstractmethod
    def run(self, flows: Sequence[Flow]) -> list[Finding]:
        """Inspect the flows and return zero or more findings.

        Each returned Finding MUST satisfy the explainability contract: WHAT was
        flagged, WHY it is suspicious, and the SUPPORTING DATA (measured value vs.
        benign baseline), plus a human-readable `evidence` line. No confidence
        scores (Hard Rule 1).
        """
        raise NotImplementedError
