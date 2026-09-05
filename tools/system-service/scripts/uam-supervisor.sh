#!/bin/bash
set -euo pipefail
# launchd supplies the one canonical manifest; resolve Python relative to this release.
: "${UAM_RUNTIME_MANIFEST:?UAM_RUNTIME_MANIFEST is required}"
RELEASE_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
exec "${RELEASE_DIR}/venv/bin/python" -I -m universal_agent_middleware.supervisor --runtime-manifest "${UAM_RUNTIME_MANIFEST}"
