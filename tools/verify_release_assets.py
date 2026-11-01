#!/usr/bin/env python3
"""Check that a GitHub Release carries the very wheel and sdist that PyPI serves.

Nothing is built and nothing is published here (GOVERNANCE.md, "Release Process"): the files attached to the release,
its ``SHA256SUMS`` and the files PyPI lists for the release version must be the same bytes. A difference, a missing file
or an unexpected file is reported and the exit status is 1.

    python tools/verify_release_assets.py --repository openjay/universal-agent-middleware --tag v0.6.3
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

PROJECT = "universal-agent-middleware"
CHECKSUMS = "SHA256SUMS"
_LINE = re.compile(r"^(?P<sha>[0-9a-f]{64}) {1,2}\*?(?P<name>\S+)$")
_TAG = re.compile(r"^v(?P<version>\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?)$")


def parse_checksums(text: str) -> dict[str, str]:
    """``<sha256>  <file>`` lines, as ``shasum -a 256`` writes them."""
    sums: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        match = _LINE.match(line.strip())
        if match is None:
            raise ValueError(f"{CHECKSUMS} line {number} is not '<sha256>  <file>'")
        if match["name"] in sums:
            raise ValueError(f"{CHECKSUMS} names {match['name']} twice")
        sums[match["name"]] = match["sha"]
    return sums


def expected_names(version: str) -> set[str]:
    stem = f"universal_agent_middleware-{version}"
    return {f"{stem}-py3-none-any.whl", f"{stem}.tar.gz"}


def compare(version: str, attached: Mapping[str, str], listed: Mapping[str, str],
            pypi: Mapping[str, str]) -> list[str]:
    """Every way the three sources disagree; empty when they are the same two files."""
    problems: list[str] = []
    expected = expected_names(version)
    for label, files in (("release assets", attached), (CHECKSUMS, listed), ("PyPI", pypi)):
        missing, unexpected = sorted(expected - set(files)), sorted(set(files) - expected)
        if missing:
            problems.append(f"{label} lack {', '.join(missing)}")
        if unexpected:
            problems.append(f"{label} carry unexpected {', '.join(unexpected)}")
    for name in sorted(expected & set(attached)):
        for label, files in ((CHECKSUMS, listed), ("PyPI", pypi)):
            if name in files and files[name] != attached[name]:
                problems.append(f"{name}: the release asset ({attached[name]}) differs from {label} ({files[name]})")
    return problems


def _request(url: str, token: str | None) -> urllib.request.Request:
    headers = {"User-Agent": "uam-verify-release-assets", "Accept": "application/json"}
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.Request(url, headers=headers)


def fetch_json(url: str, token: str | None = None) -> Any:
    with urllib.request.urlopen(_request(url, token), timeout=60) as response:
        return json.load(response)


def fetch_bytes(url: str) -> tuple[bytes, str]:
    """The body of ``url`` and its SHA-256, read in chunks."""
    digest, body = hashlib.sha256(), bytearray()
    with urllib.request.urlopen(_request(url, None), timeout=300) as response:
        for chunk in iter(lambda: response.read(1 << 20), b""):
            digest.update(chunk)
            body.extend(chunk)
    return bytes(body), digest.hexdigest()


def pypi_files(version: str, *, attempts: int = 6, pause: float = 20.0,
               sleep: Callable[[float], None] = time.sleep) -> dict[str, str]:
    """``{filename: sha256}`` PyPI lists for ``version``; a 404 is retried (the index can lag a fresh upload)."""
    url = f"https://pypi.org/pypi/{PROJECT}/{version}/json"
    for attempt in range(1, attempts + 1):
        try:
            data = fetch_json(url)
        except urllib.error.HTTPError as error:
            if error.code != 404 or attempt == attempts:
                raise
            sleep(pause)
            continue
        return {item["filename"]: item["digests"]["sha256"] for item in data["urls"]}
    raise AssertionError("the loop returns or raises")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repository", required=True, help="owner/name of the GitHub repository")
    parser.add_argument("--tag", required=True, help="release tag, for example v0.6.3")
    args = parser.parse_args(argv)
    tag = _TAG.fullmatch(args.tag)
    if tag is None:
        print(f"the tag {args.tag!r} is not v<PEP 440 release>", file=sys.stderr)
        return 2
    version = tag["version"]
    release = fetch_json(f"https://api.github.com/repos/{args.repository}/releases/tags/{args.tag}",
                         os.environ.get("GITHUB_TOKEN"))
    attached: dict[str, str] = {}
    listed: dict[str, str] = {}
    for asset in release["assets"]:
        body, sha256 = fetch_bytes(asset["browser_download_url"])
        if asset["name"] == CHECKSUMS:
            listed = parse_checksums(body.decode("utf-8"))
        else:
            attached[asset["name"]] = sha256
    try:
        pypi = pypi_files(version)
    except urllib.error.HTTPError as error:
        print(f"PyPI has no {PROJECT} {version} (HTTP {error.code})", file=sys.stderr)
        return 1
    problems = compare(version, attached, listed, pypi)
    print(json.dumps({"tag": args.tag, "version": version, "release_assets": attached, "sha256sums": listed,
                      "pypi": pypi, "problems": problems}, indent=2, sort_keys=True))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
