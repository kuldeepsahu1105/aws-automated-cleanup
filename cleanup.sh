#!/bin/bash
# Python supplies pagination, bounded polling, and JSON-safe AWS calls.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/environment_cleanup.py" "$@"
