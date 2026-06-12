#!/usr/bin/env bash
# ============================================================
#   pfsense-audit  -  macOS / Linux wrapper script
#
#   Usage:
#     ./run.sh <path-to-config.xml> [options]
#
#   Examples:
#     ./run.sh tests/fixtures/sample_config.xml
#     ./run.sh ~/configs/firewall.xml -f json
#     ./run.sh ~/configs/firewall.xml -o report.txt
# ============================================================

set -e

# Always operate from the directory this script lives in, so
# relative paths like tests/fixtures/... resolve correctly
# regardless of where the user invoked us from.
cd "$(dirname "$0")"

# Pick the Python interpreter. Prefer python3 (most distros),
# fall back to python (some Windows-on-bash setups).
if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo "Error: Python not found on PATH."
    echo "Install Python 3.10 or later from https://www.python.org/downloads/"
    exit 1
fi

# Install dependencies. Try a normal install first; if blocked by
# PEP 668 (externally-managed-environment, common on recent
# Debian/Ubuntu), fall back to --user install. pip is idempotent
# so running every time is fine; takes ~1 second when already up
# to date.
if ! "$PY" -m pip install --quiet --disable-pip-version-check \
        -r requirements.txt 2>/dev/null; then
    echo "System Python is externally managed; installing to user site." >&2
    "$PY" -m pip install --quiet --disable-pip-version-check --user \
        -r requirements.txt
fi

# Forward all script arguments to the tool.
exec "$PY" -m pfsense_auditor "$@"
