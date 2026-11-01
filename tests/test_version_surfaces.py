"""The version of this source tree is stated the same way on every surface that states one.

The release pipeline builds the wheel from ``pyproject.toml`` and the running package reports ``__version__``; the provenance pointer, the README title, the SSOT and the CHANGELOG name
it for the reader. SSOT section 8 requires that "docs/README/CHANGELOG/MANIFEST all reflect" the release version, and nothing enforced it: a surface left behind makes a staged release
disagree with itself. The check reads committed files only and compares them with the package the tests import.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from universal_agent_middleware import __version__

ROOT = Path(__file__).resolve().parent.parent


def text(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_the_machine_readable_surfaces_name_the_package_version():
    assert tomllib.loads(text("pyproject.toml"))["project"]["version"] == __version__
    assert json.loads(text("MANIFEST.json"))["version"] == __version__


def test_the_documents_name_the_package_version():
    assert text("README.md").splitlines()[0] == f"# Universal Agent Middleware (UAM) v{__version__}"
    ssot = text("docs/SSOT.md")
    assert f"\nVersion: `{__version__}`\n" in ssot
    assert f"\nUAM v{__version__} release acceptance requires:\n" in ssot
    assert f"all reflect v{__version__};" in ssot
    assert re.search(rf"^## {re.escape(__version__)} — ", text("CHANGELOG.md"), re.MULTILINE), "the CHANGELOG has no section for this version"
