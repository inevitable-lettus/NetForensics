"""One place that builds the concrete stores from config, so the API and the CLI
open storage the same way and depend only on the `interfaces` contracts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from backend.config import EvidenceConfig
from backend.db.case_repository import SqliteCaseRepository
from backend.db.custody_log import SqliteCustodyLog
from backend.db.evidence_store import ContentAddressedEvidenceStore
from backend.db.interfaces import CaseRepository, CustodyLog, EvidenceStore


@dataclass(frozen=True)
class Storage:
    cases: CaseRepository
    custody: CustodyLog
    evidence: EvidenceStore

    @classmethod
    def open(cls, config: EvidenceConfig) -> Storage:
        db_path = Path(config.db_path)
        return cls(
            cases=SqliteCaseRepository(db_path),
            custody=SqliteCustodyLog(db_path),
            evidence=ContentAddressedEvidenceStore(Path(config.evidence_store_dir)),
        )
