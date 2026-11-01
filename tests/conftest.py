"""Pytest hooks shared across the UAM test suite."""
from __future__ import annotations

import os

import pytest


@pytest.fixture(scope="session", autouse=True)
def _isolate_runtime_manifest_session() -> None:
    """Drop production runtime binding before unittest setUpClass hooks run."""
    os.environ.pop("UAM_RUNTIME_MANIFEST", None)


@pytest.fixture(autouse=True)
def _isolate_runtime_manifest(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests use synthetic registry/state paths; keep runtime manifest unset."""
    monkeypatch.delenv("UAM_RUNTIME_MANIFEST", raising=False)
