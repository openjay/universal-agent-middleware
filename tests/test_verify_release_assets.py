"""The release-asset verifier reports every way the release assets, SHA256SUMS and PyPI can disagree.

The verifier (``tools/verify_release_assets.py``) is what ``.github/workflows/release.yml`` runs instead of rebuilding
and publishing in CI: the release carries one frozen wheel and sdist, and the check is that these are the same bytes
as the files PyPI serves. These tests exercise its decision logic on synthetic digests; no network is involved.
"""
from __future__ import annotations

import importlib.util
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "verify_release_assets.py"
# An sdist ships tests but not tools/: without that directory there is nothing to load.
TOOLS_SHIPPED = SCRIPT.is_file()
NO_TOOLS = "tools/ is not part of this tree (an sdist ships tests, not tools/)"

VERSION = "0.6.3"
WHEEL = f"universal_agent_middleware-{VERSION}-py3-none-any.whl"
SDIST = f"universal_agent_middleware-{VERSION}.tar.gz"
A, B, C = "a" * 64, "b" * 64, "c" * 64


def load_verifier():
    spec = importlib.util.spec_from_file_location("verify_release_assets", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(TOOLS_SHIPPED, NO_TOOLS)
class ReleaseAssetVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = load_verifier()

    def test_the_same_two_files_everywhere_is_clean(self) -> None:
        files = {WHEEL: A, SDIST: B}
        self.assertEqual(self.verifier.compare(VERSION, files, dict(files), dict(files)), [])

    def test_a_pypi_file_with_different_bytes_is_reported(self) -> None:
        problems = self.verifier.compare(VERSION, {WHEEL: A, SDIST: B}, {WHEEL: A, SDIST: B}, {WHEEL: C, SDIST: B})
        self.assertEqual(len(problems), 1)
        self.assertIn(WHEEL, problems[0])
        self.assertIn("PyPI", problems[0])

    def test_a_checksum_line_that_does_not_match_its_asset_is_reported(self) -> None:
        problems = self.verifier.compare(VERSION, {WHEEL: A, SDIST: B}, {WHEEL: A, SDIST: C}, {WHEEL: A, SDIST: B})
        self.assertEqual(len(problems), 1)
        self.assertIn(SDIST, problems[0])
        self.assertIn("SHA256SUMS", problems[0])

    def test_missing_and_unexpected_files_are_reported_per_source(self) -> None:
        problems = self.verifier.compare(
            VERSION, {WHEEL: A}, {WHEEL: A, SDIST: B, "extra.txt": C}, {WHEEL: A, SDIST: B},
        )
        self.assertEqual(problems, [
            f"release assets lack {SDIST}",
            "SHA256SUMS carry unexpected extra.txt",
        ])

    def test_files_of_another_version_are_not_the_release(self) -> None:
        other = {"universal_agent_middleware-0.6.2-py3-none-any.whl": A, "universal_agent_middleware-0.6.2.tar.gz": B}
        problems = self.verifier.compare(VERSION, other, other, other)
        self.assertEqual(len(problems), 6)  # each of the three sources lacks both files and carries two unexpected ones

    def test_checksums_parse_both_shasum_spellings_and_refuse_anything_else(self) -> None:
        text = f"{A}  {WHEEL}\n{B} *{SDIST}\n\n"
        self.assertEqual(self.verifier.parse_checksums(text), {WHEEL: A, SDIST: B})
        for bad in (f"{A[:-1]}  {WHEEL}", f"{A} {WHEEL} extra", f"{A}  {WHEEL}\n{B}  {WHEEL}"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.verifier.parse_checksums(bad)

    def test_a_missing_pypi_release_is_retried_and_then_raised(self) -> None:
        pauses: list[float] = []
        gone = urllib.error.HTTPError("https://pypi.org/x", 404, "Not Found", None, None)  # type: ignore[arg-type]
        with mock.patch.object(self.verifier, "fetch_json", side_effect=gone):
            with self.assertRaises(urllib.error.HTTPError):
                self.verifier.pypi_files(VERSION, attempts=3, pause=7.0, sleep=pauses.append)
        self.assertEqual(pauses, [7.0, 7.0])

    def test_pypi_files_are_read_as_filename_to_sha256(self) -> None:
        listing = {"urls": [{"filename": WHEEL, "digests": {"sha256": A}}, {"filename": SDIST, "digests": {"sha256": B}}]}
        with mock.patch.object(self.verifier, "fetch_json", return_value=listing):
            self.assertEqual(self.verifier.pypi_files(VERSION), {WHEEL: A, SDIST: B})


if __name__ == "__main__":
    unittest.main()
