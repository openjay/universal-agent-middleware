"""Serve this checkout's package to a release probe, the way a release interpreter would.

``release_probe.run_probe`` starts a release's interpreter as ``python -I -B -c SOURCE REGISTRY STATE``. ``-I`` ignores
``PYTHONPATH``, the user site and the working directory, so the child imports whatever package its own environment has
installed. A fixture interpreter that only ran the test interpreter would therefore probe a stale install (the 19-tool
package of an older checkout) or none at all, and every later gate would fail for a reason that has nothing to do with
the gate under test.

``tests/test_release_contract.py`` installs ``<test python> -I -B release_probe_launcher.py <checkout src> "$@"`` as the
fixture release's ``venv/bin/python``. The launcher accepts exactly the product's own invocation and refuses anything
else, so the product has to keep passing ``-I -B`` (a probe that drops them fails the fixture instead of passing
quietly). It puts the checkout's ``src`` first on ``sys.path`` and runs SOURCE the way ``-c`` would.
"""
from __future__ import annotations

import sys

PRODUCT_FLAGS = ["-I", "-B", "-c"]
REFUSED = 97


def main(argv: list[str]) -> int:
    """``argv`` is ``CHECKOUT_SRC -I -B -c SOURCE [ARGS...]``."""
    if len(argv) < 5 or argv[1:4] != PRODUCT_FLAGS:
        sys.stderr.write(f"release_probe_launcher: expected '-I -B -c SOURCE ARGS', got {argv[1:4]!r}\n")
        return REFUSED
    if not (sys.flags.isolated and sys.flags.dont_write_bytecode):
        sys.stderr.write("release_probe_launcher: the launcher itself must run with -I -B\n")
        return REFUSED
    checkout_src, source, arguments = argv[0], argv[4], argv[5:]
    sys.path.insert(0, checkout_src)
    sys.argv = ["-c", *arguments]
    exec(compile(source, "<string>", "exec"), {"__name__": "__main__"})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
