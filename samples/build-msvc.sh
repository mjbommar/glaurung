#!/bin/bash
#
# Builds a C++ sample using the MSVC compiler in a Windows Docker container.
# This script must be run from a Windows host with Docker Desktop configured
# to use Windows containers.

set -euo pipefail

# Ensure the script is run from the 'samples' directory.
if [ ! -f "docker-compose.yml" ]; then
    echo "This script must be run from the 'samples' directory."
    exit 1
fi

echo "Building the MSVC Docker container..."
docker-compose build --profile msvc

echo "Compiling C++ source with MSVC..."
docker-compose run --rm --service-ports windows-msvc powershell.exe -Command "cl.exe /EHsc /O2 /Fe:binaries/msvc/hello-msvc.exe source/cpp/hello.cpp"

echo "MSVC build complete. Executable is in samples/binaries/platforms/windows/amd64/msvc/"
