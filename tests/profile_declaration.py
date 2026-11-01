"""Build, read and write the READ_ONLY_SESSION_PROFILE_V3 declaration (``docs/oss/profile-v3-declaration.json``).

The *candidate* side is what this source tree's MCP server advertises, fingerprinted by the release
pipeline's own probe (``release_probe.PROBE_SOURCE``, run unchanged), so it carries exactly the digests
that a release computes and compares. The *baseline* side is the V2 listing of the source commit the
production release was built from: historical data, copied once, never recomputed here.

    python tests/profile_declaration.py write
        refresh the candidate side (and the difference against the baseline) from this source tree
    python tests/profile_declaration.py write --baseline-probe FILE --baseline-commit SHA
        first creation: FILE is the probe output (JSON) of the baseline listing
    python tests/profile_declaration.py check
        exit 1 when the committed file differs from what this source tree advertises

Run from the repository root with the package importable (``pip install -e .`` or ``PYTHONPATH=src``)
and with Python 3.13 or later: the ``description`` digests are those of the text an interpreter that
strips docstring indentation at compile time advertises (see ``DOCSTRINGS_DEDENTED_AT_COMPILE_TIME``).
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from universal_agent_middleware.release_probe import (
    FIXTURE_REGISTRY,
    PROBE_SOURCE,
    contract_sha256,
    diff_tool_fields,
)

REPOSITORY = Path(__file__).resolve().parent.parent
DECLARATION_PATH = REPOSITORY / "docs" / "oss" / "profile-v3-declaration.json"
SCHEMA = "uam-profile-declaration-v1"
PROFILE = "READ_ONLY_SESSION_PROFILE_V3"
BASELINE_PROFILE = "READ_ONLY_SESSION_PROFILE_V2"
# Which top-level key of a tool listing each fingerprint role is the digest of.
FINGERPRINT_ROLES = {
    "input": "inputSchema", "output": "outputSchema", "safety": "annotations", "description": "description",
}
SAFETY = {"destructiveHint": False, "openWorldHint": False, "readOnlyHint": True}
SERVING = {
    "uam_file_digest": {
        "served_by": ["mcp_sdk_adapter"],
        "not_served_by": ["legacy_http_openapi_adapter", "custom_stdio_mcp_adapter"],
    },
}
DEFAULTS = {"directory_admit": False, "static_registration_authorization": "independent_of_root_scopes"}
# Where and when the profile was adopted. Recorded, not derived: adoption is a decision about a deployment and the
# probe cannot observe one. One operator, one host: it is not evidence about any other environment.
ADOPTION = {
    "scope": "the maintainer's own supervised runtime (one operator, one host)",
    "date": "2026-10-31",
    "published_in": "0.6.3",
}
DESCRIPTION_BASIS = (
    "the description text as advertised by an interpreter that strips docstring indentation at compile "
    "time (Python 3.13 or later); the name, input, output and safety digests do not depend on the interpreter"
)


def _two_line_docstring() -> None:
    """First line.

    Second line, indented in the source.
    """


# Python 3.13 strips the common indentation of a docstring when it compiles it; earlier interpreters
# keep it. A tool's MCP description is its docstring, so for one source tree the advertised text is
# indented on 3.11/3.12 and is not on 3.13+. Measured with Python 3.11.15 against 3.14.6 on this
# candidate: 16 of the 20 descriptions differ and no other field of any tool does. The ``description``
# digest is therefore the one digest that is reproducible only on an interpreter that dedents at
# compile time (the service interpreter, 3.14.6, is one).
DOCSTRINGS_DEDENTED_AT_COMPILE_TIME = "\n    Second line" not in (_two_line_docstring.__doc__ or "")


def run_probe() -> dict[str, Any]:
    """The release probe, executed unchanged in this process against an empty fixture registry."""
    with tempfile.TemporaryDirectory(prefix="uam-profile-declaration-") as tmp:
        base = Path(tmp)
        registry = base / "workspaces.json"
        registry.write_text(json.dumps(FIXTURE_REGISTRY), encoding="utf-8")
        (base / "state").mkdir()
        argv, stdout = sys.argv, io.StringIO()
        sys.argv = ["release-probe", str(registry), str(base / "state")]
        try:
            with contextlib.redirect_stdout(stdout):
                # The probe is a script (a string the pipeline hands to the release's own interpreter);
                # running its source here, unchanged, is what ties these digests to the pipeline's.
                exec(compile(PROBE_SOURCE, "<release-probe>", "exec"), {"__name__": "__main__"})
        finally:
            sys.argv = argv
    return json.loads(stdout.getvalue().strip().splitlines()[-1])


def side(probe: dict[str, Any]) -> dict[str, Any]:
    """One listing as the declaration binds it: the exact tool set, its contract and every field digest."""
    contract, fields = probe["contract"], probe["fields"]
    names = sorted(contract)
    if sorted(fields) != names:
        raise ValueError("the probe reported different tools for contract and fields")
    return {
        "tool_count": len(names),
        "tools": names,
        "contract_sha256": contract_sha256(contract),
        "fingerprints": {name: {"contract": contract[name], "fields": fields[name]} for name in names},
    }


def field_digests(declared: dict[str, Any]) -> dict[str, dict[str, str]]:
    return {name: dict(entry["fields"]) for name, entry in declared["fingerprints"].items()}


def without_description_digests(listing: dict[str, Any]) -> dict[str, Any]:
    """A bound listing minus the ``description`` digests, the only interpreter-dependent ones; a copy."""
    stripped = json.loads(json.dumps(listing))
    for entry in stripped["fingerprints"].values():
        entry["fields"].pop(FINGERPRINT_ROLES["description"], None)
    return stripped


def build(baseline: dict[str, Any], probe: dict[str, Any]) -> dict[str, Any]:
    candidate = side(probe)
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "status": "ADOPTED_LOCALLY",
        "adopted_in_production": True,
        "adoption": ADOPTION,
        "extends": BASELINE_PROFILE,
        "fingerprint_roles": FINGERPRINT_ROLES,
        "description_digest_basis": DESCRIPTION_BASIS,
        "safety": SAFETY,
        "serving": SERVING,
        "defaults": DEFAULTS,
        "baseline": baseline,
        "candidate": candidate,
        "metadata_diff_vs_baseline": diff_tool_fields(field_digests(baseline), field_digests(candidate)),
    }


def baseline_from_probe(probe: dict[str, Any], commit: str) -> dict[str, Any]:
    return {
        "profile": BASELINE_PROFILE,
        "source_commit": commit,
        "package_version": probe["version"],
        **side(probe),
    }


def load() -> dict[str, Any]:
    return json.loads(DECLARATION_PATH.read_text(encoding="utf-8"))


def render(declaration: dict[str, Any]) -> str:
    return json.dumps(declaration, indent=2, sort_keys=True) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("write", "check"))
    parser.add_argument("--baseline-probe", type=Path)
    parser.add_argument("--baseline-commit")
    args = parser.parse_args(argv)
    if not DOCSTRINGS_DEDENTED_AT_COMPILE_TIME:
        parser.error(
            "this interpreter keeps docstring indentation, so the descriptions it advertises (and their digests) "
            "differ from the declared ones; run it with Python 3.13 or later"
        )
    probe = run_probe()
    if args.baseline_probe:
        if not args.baseline_commit:
            parser.error("--baseline-probe needs --baseline-commit")
        baseline = baseline_from_probe(json.loads(args.baseline_probe.read_text(encoding="utf-8")), args.baseline_commit)
    else:
        baseline = load()["baseline"]
    text = render(build(baseline, probe))
    if args.action == "check":
        same = DECLARATION_PATH.read_text(encoding="utf-8") == text
        print("declaration matches this source tree" if same else "declaration DIFFERS from this source tree")
        return 0 if same else 1
    DECLARATION_PATH.write_text(text, encoding="utf-8")
    print(f"wrote {DECLARATION_PATH.relative_to(REPOSITORY)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
