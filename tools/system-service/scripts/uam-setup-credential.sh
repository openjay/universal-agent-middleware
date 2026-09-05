#!/bin/bash
set -euo pipefail
# First-time setup from an explicit staged/canonical manifest; never rotates a key.
MANIFEST="${1:?Usage: uam-setup-credential.sh /absolute/uam-runtime.json}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${UAM_INSTALL_PYTHON:-${SCRIPT_DIR}/../venv/bin/python}"
if [[ ! -x "${PYTHON}" ]]; then
    PYTHON="${SCRIPT_DIR}/../../../.venv/bin/python"
fi
exec "${PYTHON}" -I -m universal_agent_middleware.service --setup-credential --runtime-manifest "${MANIFEST}"
