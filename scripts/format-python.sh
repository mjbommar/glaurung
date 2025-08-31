#!/usr/bin/env bash
set -euo pipefail

echo "[format-python] Formatting python/ with ruff"
if ! command -v uvx >/dev/null 2>&1; then
  echo "Error: uvx not found. Please install 'uv' (see project AGENTS.md)" >&2
  exit 127
fi

exec uvx ruff format python/ "$@"

