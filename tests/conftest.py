"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.config import CONFIG, Config


@pytest.fixture
def config() -> Config:
    """The default config singleton; tests may construct overrides themselves."""
    return CONFIG


@pytest.fixture
def tmp_pcap(tmp_path: Path) -> Path:
    """A path inside the per-test temp dir for writing crafted pcaps."""
    return tmp_path / "evidence.pcap"
