#!/bin/bash

# Test script for Docker-based sample builds
# Verifies that the Docker setup works correctly

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/docker"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[TEST] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}" >&2; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
info() { echo -e "${BLUE}[INFO] $1${NC}"; }

# Packages whose static archives the signature-library harvest reads. Kept in
# step with ARCHIVE_NAMES in docker/harvest_system_archives.py: an archive that
# is not installed is silently absent from the manifest, and that looks exactly
# like an archive that does not exist.
HARVEST_DEV_PACKAGES=(
    zlib1g-dev libssl-dev libbz2-dev liblzma-dev libzstd-dev
    libsqlite3-dev libpcre2-dev libxml2-dev libcurl4-openssl-dev
    libffi-dev libgmp-dev musl-dev musl-tools
)

check_docker() {
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed or not in PATH"
        return 1
    fi

    if ! docker info &> /dev/null; then
        error "Docker daemon is not running"
        return 1
    fi

    log "✓ Docker is available"
    return 0
}

check_platform_config() {
    if [ ! -f "$DOCKER_DIR/platforms.json" ]; then
        error "Platform configuration file not found: $DOCKER_DIR/platforms.json"
        return 1
    fi

    if ! command -v jq &> /dev/null; then
        warn "jq not available, skipping JSON validation"
        return 0
    fi

    if ! jq empty "$DOCKER_DIR/platforms.json" 2>/dev/null; then
        error "Platform configuration JSON is invalid"
        return 1
    fi

    log "✓ Platform configuration is valid"
    return 0
}

check_dockerfiles() {
    local missing_files=()

    # Check if Dockerfiles exist
    for os in linux windows darwin; do
        for arch_file in "$DOCKER_DIR/$os"/Dockerfile.*; do
            if [ ! -f "$arch_file" ]; then
                missing_files+=("$arch_file")
            fi
        done
    done

    if [ ${#missing_files[@]} -ne 0 ]; then
        error "Missing Dockerfile(s): ${missing_files[*]}"
        return 1
    fi

    log "✓ All Dockerfiles are present"
    return 0
}

check_build_scripts() {
    local scripts=(
        "$DOCKER_DIR/build-linux.sh"
        "$DOCKER_DIR/build-windows.sh"
        "$DOCKER_DIR/build-darwin.sh"
    )

    for script in "${scripts[@]}"; do
        if [ ! -f "$script" ]; then
            error "Build script not found: $script"
            return 1
        fi

        if [ ! -x "$script" ]; then
            warn "Build script is not executable: $script"
        fi
    done

    log "✓ Build scripts are present"
    return 0
}

check_harvest_wiring() {
    local ok=true
    local harvester="$DOCKER_DIR/harvest_system_archives.py"
    local script dockerfile pkg

    if [ ! -f "$harvester" ]; then
        error "System archive harvester not found: $harvester"
        return 1
    fi

    for script in "$DOCKER_DIR/build-linux.sh" "$DOCKER_DIR/build-windows.sh"; do
        if ! grep -q '^harvest_system_archives()' "$script"; then
            error "harvest_system_archives() is not defined in $script"
            ok=false
        fi
        if ! grep -q -- '--harvest-only' "$script"; then
            error "$script has no --harvest-only entry point"
            ok=false
        fi
    done

    for dockerfile in "$DOCKER_DIR"/linux/Dockerfile.*; do
        for pkg in "${HARVEST_DEV_PACKAGES[@]}"; do
            if ! grep -qE "^[[:space:]]+${pkg} \\\\$" "$dockerfile"; then
                error "$(basename "$dockerfile") does not install $pkg"
                ok=false
            fi
        done
        if ! grep -q 'harvest_system_archives.py' "$dockerfile"; then
            error "$(basename "$dockerfile") does not copy the harvester"
            ok=false
        fi
    done

    if [ "$ok" != true ]; then
        return 1
    fi

    log "✓ System archive harvest is wired into the scripts and Linux images"
    return 0
}

test_basic_build() {
    local os="$1" arch="$2"
    local dockerfile="$DOCKER_DIR/${os}/Dockerfile.${arch}"
    local test_tag="glaurung-test-${os}-${arch}:latest"

    if [ ! -f "$dockerfile" ]; then
        warn "Dockerfile not found for ${os}/${arch}, skipping test"
        return 0
    fi

    info "Testing build for ${os}/${arch}..."

    # Quick syntax check (only if --dry-run supported)
    if docker build --help 2>&1 | grep -q "--dry-run"; then
        if ! docker build --dry-run --file "$dockerfile" "$SCRIPT_DIR" &>/dev/null; then
            error "Dockerfile syntax error for ${os}/${arch}"
            return 1
        else
            log "✓ Dockerfile syntax is valid for ${os}/${arch}"
        fi
    else
        warn "Docker build --dry-run not supported, skipping syntax check for ${os}/${arch}"
    fi

    return 0
}

run_tests() {
    local test_platforms=(
        "linux/amd64" "linux/arm64" "linux/armhf" "linux/i386" "linux/riscv64"
        "windows/amd64" "windows/i386"
        "darwin/amd64" "darwin/arm64"
    )
    local failed_tests=()

    for platform in "${test_platforms[@]}"; do
        IFS='/' read -r os arch <<< "$platform"
        if ! test_basic_build "$os" "$arch"; then
            failed_tests+=("$platform")
        fi
    done

    if [ ${#failed_tests[@]} -ne 0 ]; then
        error "Failed tests: ${failed_tests[*]}"
        return 1
    fi

    return 0
}

show_summary() {
    cat << EOF

Docker Setup Test Summary
=========================

This test verifies that your Docker-based build infrastructure is properly configured.

Tested Components:
✓ Docker availability
✓ Platform configuration (platforms.json)
✓ Dockerfile presence and basic syntax
✓ Build script availability
✓ System archive harvest wiring (harvest_system_archives)

Next Steps:
1. Run actual builds: ./build-multiplatform.sh linux/amd64
2. Test cross-platform: ./build-multiplatform.sh --multiplatform
3. Check outputs in samples/binaries/platforms/

For more information, see samples/README.md

EOF
}

main() {
    log "Starting Docker setup tests..."

    local tests_passed=true

    if ! check_docker; then
        tests_passed=false
    fi

    if ! check_platform_config; then
        tests_passed=false
    fi

    if ! check_dockerfiles; then
        tests_passed=false
    fi

    if ! check_build_scripts; then
        tests_passed=false
    fi

    if ! check_harvest_wiring; then
        tests_passed=false
    fi

    if ! run_tests; then
        tests_passed=false
    fi

    if [ "$tests_passed" = true ]; then
        log "✓ All tests passed!"
        show_summary
        exit 0
    else
        error "✗ Some tests failed"
        exit 1
    fi
}

main "$@"
