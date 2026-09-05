#!/bin/bash
set -euo pipefail
# Stages by default; --activate <manifest> explicitly switches and loads services.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PYTHON="${UAM_INSTALL_PYTHON:-${PROJECT_DIR}/.venv/bin/python}"
exec "${PYTHON}" -m universal_agent_middleware.installer "$@"
