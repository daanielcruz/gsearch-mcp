#!/usr/bin/env bash
# No login, commit, tag, push, deletion, or publication occurs implicitly.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/scripts/release.py" "$@"
