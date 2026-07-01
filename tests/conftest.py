"""Shared fixtures. `src/` is on sys.path via pyproject `pythonpath`.

An autouse fixture hard-blocks outbound HTTP so a regression can never silently
depend on the network — the whole suite is hermetic and offline.
"""

from __future__ import annotations

import urllib.request
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _block_network(monkeypatch):
    """Make any real HTTP call raise, guaranteeing offline tests."""

    def _raise(*args, **kwargs):  # pragma: no cover - only fires on a bug
        raise RuntimeError("network access is blocked during tests")

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    yield


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def fx():
    """Return a callable mapping a fixture filename -> absolute path string."""

    def _fx(name: str) -> str:
        return str(FIXTURES / name)

    return _fx
