#!/bin/bash
#
# Builds all sample binaries for all supported platforms.

set -euo pipefail

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Build all Linux and cross-compiled platforms
"$SCRIPT_DIR/build-multiplatform.sh"

