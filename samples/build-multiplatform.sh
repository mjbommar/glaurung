#!/bin/bash

# Multi-platform Docker build orchestrator
# Builds samples across multiple OS/architecture combinations

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SOURCE_DIR="$SCRIPT_DIR/source"
BINARIES_DIR="$SCRIPT_DIR/binaries"
METADATA_DIR="$BINARIES_DIR/metadata"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

log() { echo -e "${GREEN}[BUILD] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}" >&2; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
info() { echo -e "${BLUE}[INFO] $1${NC}"; }
platform_log() { echo -e "${PURPLE}[PLATFORM] $1${NC}"; }

ensure_dir() { [ -d "$1" ] || mkdir -p "$1"; }

check_docker() {
    if ! command -v docker &> /dev/null; then
        error "Docker is required but not installed. Please install Docker first."
        exit 1
    fi

    if ! docker info &> /dev/null; then
        error "Docker daemon is not running. Please start Docker first."
        exit 1
    fi
}

check_buildx() {
    if ! docker buildx version &> /dev/null; then
        warn "Docker Buildx not available. Multi-platform builds will be limited."
        return 1
    fi
    return 0
}

load_platform_config() {
    if [ -f "$SCRIPT_DIR/docker/platforms.json" ]; then
        PLATFORM_CONFIG="$SCRIPT_DIR/docker/platforms.json"
    else
        error "Platform configuration file not found: $SCRIPT_DIR/docker/platforms.json"
        exit 1
    fi
}

get_platform_info() {
    local os="$1" arch="$2"
    local dockerfile base_image description

    # Try to extract info from JSON config
    if command -v jq &> /dev/null && [ -f "$PLATFORM_CONFIG" ]; then
        dockerfile=$(jq -r ".platforms.\"$os\".\"$arch\".dockerfile" "$PLATFORM_CONFIG" 2>/dev/null || echo "")
        base_image=$(jq -r ".platforms.\"$os\".\"$arch\".base_image" "$PLATFORM_CONFIG" 2>/dev/null || echo "")
        description=$(jq -r ".platforms.\"$os\".\"$arch\".description" "$PLATFORM_CONFIG" 2>/dev/null || echo "")
    fi

    # Fallback to defaults if JSON parsing fails
    if [ -z "$dockerfile" ] || [ "$dockerfile" = "null" ]; then
        dockerfile="$SCRIPT_DIR/docker/${os}/Dockerfile.${arch}"
    else
        dockerfile="$SCRIPT_DIR/$dockerfile"
    fi

    if [ -z "$base_image" ] || [ "$base_image" = "null" ]; then
        case "$os/$arch" in
            "linux/amd64") base_image="ubuntu:22.04" ;;
            "linux/arm64") base_image="arm64v8/ubuntu:22.04" ;;
            "linux/riscv64") base_image="riscv64/ubuntu:22.04" ;;
            "linux/i386") base_image="i386/ubuntu:22.04" ;;
            "windows/amd64") base_image="ubuntu:22.04" ;;
            "darwin/amd64") base_image="ubuntu:22.04" ;;
            *) base_image="ubuntu:22.04" ;;
        esac
    fi

    if [ -z "$description" ] || [ "$description" = "null" ]; then
        description="${os} ${arch} builds"
    fi

    echo "$dockerfile|$base_image|$description"
}

build_platform() {
    local os="$1" arch="$2"
    local platform="${os}/${arch}"
    local tag="glaurung-samples-${os}-${arch}:latest"

    platform_log "Building for ${platform}"

    # Get platform information
    IFS='|' read -r dockerfile base_image description <<< "$(get_platform_info "$os" "$arch")"

    if [ ! -f "$dockerfile" ]; then
        warn "Dockerfile not found: $dockerfile, skipping ${platform}"
        return 1
    fi

    # Determine platform for Docker
    local docker_platform
    if [[ "$os" == "windows" ]] || [[ "$os" == "darwin" ]]; then
        # Cross-compilation from Linux host
        docker_platform="linux/amd64"
    else
        docker_platform="${os}/${arch}"
    fi

    platform_log "Using base image: $base_image"
    platform_log "Description: $description"

    # Build the image
    if docker build \
        --platform "$docker_platform" \
        --tag "$tag" \
        --file "$dockerfile" \
        --build-arg BASE_IMAGE="$base_image" \
        "$SCRIPT_DIR"; then
        log "✓ Build successful for $platform"
        # ... existing code to copy artifacts
    else
        error "✗ Build failed for $platform"
        return 1
    fi
}

build_with_buildx() {
    local platforms="$1"
    local dockerfile="$2"
    local tag="$3"

    info "Using Docker Buildx for multi-platform build"
    info "Platforms: $platforms"

    if docker buildx build \
        --platform "$platforms" \
        --tag "$tag" \
        --file "$dockerfile" \
        --load \
        "$SCRIPT_DIR"; then
        log "✓ Multi-platform build successful"
        return 0
    else
        error "✗ Multi-platform build failed"
        return 1
    fi
}

generate_metadata() {
    info "Generating metadata and index..."

    if [ -f "$PROJECT_ROOT/scripts/index_samples.py" ]; then
        cd "$PROJECT_ROOT"
        python3 scripts/index_samples.py
        log "✓ Metadata generation completed"
    else
        warn "Metadata script not found at $PROJECT_ROOT/scripts/index_samples.py"
    fi
}

show_usage() {
    cat << EOF
Multi-Platform Docker Build Orchestrator for Glaurung Samples

USAGE:
    $0 [OPTIONS] [PLATFORMS...]

PLATFORMS:
    linux/amd64      Linux x86_64 (default)
    linux/arm64      Linux ARM64
    linux/armhf      Linux ARM 32-bit
    linux/riscv64    Linux RISC-V 64-bit
    linux/i386       Linux x86 32-bit
    windows/amd64    Windows x86_64 (cross-compiled)
    windows/i386     Windows x86 32-bit (cross-compiled)
    darwin/amd64     macOS x86_64 (cross-compiled)
    darwin/arm64     macOS ARM64 (cross-compiled)

OPTIONS:
    -m, --multiplatform  Use Docker Buildx for parallel multi-platform builds
    -p, --platforms PLATFORMS  Comma-separated list of platforms for multiplatform builds
    -t, --tag TAG        Docker image tag (default: glaurung-samples:latest)
    -c, --clean          Clean build artifacts before building
    -g, --generate-meta  Generate metadata after build
    -h, --help           Show this help message

EXAMPLES:
    $0 linux/amd64 linux/arm64                    # Build specific platforms
    $0 --multiplatform --platforms linux/amd64,linux/arm64  # Multi-platform build
    $0 --clean --generate-meta linux/amd64       # Clean, build, and generate metadata
    $0                                          # Build default platform (linux/amd64)

DOCKER REQUIREMENTS:
    - Docker installed and running
    - For multi-platform: Docker Buildx and QEMU support
    - For cross-compilation: Appropriate toolchains in Docker images

EOF
}

main() {
    local platforms=()
    local use_buildx=false
    local buildx_platforms=""
    local tag="glaurung-samples:latest"
    local clean=false
    local generate_meta=false

    # Load platform configuration
    load_platform_config

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -m|--multiplatform)
                use_buildx=true
                shift
                ;;
            -p|--platforms)
                buildx_platforms="$2"
                shift 2
                ;;
            -t|--tag)
                tag="$2"
                shift 2
                ;;
            -c|--clean)
                clean=true
                shift
                ;;
            -g|--generate-meta)
                generate_meta=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            linux/*|windows/*|darwin/*)
                platforms+=("$1")
                shift
                ;;
            *)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Default to linux/amd64 if no platforms specified
    if [ ${#platforms[@]} -eq 0 ] && [ "$use_buildx" = false ]; then
        platforms=("linux/amd64")
    fi

    # Set default buildx platforms if not specified
    if [ "$use_buildx" = true ] && [ -z "$buildx_platforms" ]; then
        buildx_platforms="linux/amd64,linux/arm64"
    fi

    check_docker

    if [ "$use_buildx" = true ]; then
        check_buildx || exit 1
    fi

    log "Starting multi-platform Docker builds"
    log "Source: $SOURCE_DIR"
    log "Output: $BINARIES_DIR"

    # Clean if requested
    if [ "$clean" = true ]; then
        info "Cleaning previous build artifacts..."
        rm -rf "$BINARIES_DIR/platforms"/*
        ensure_dir "$METADATA_DIR"
    fi

    ensure_dir "$BINARIES_DIR/platforms"

    # Multi-platform build with Buildx
    if [ "$use_buildx" = true ]; then
        local dockerfile="$SCRIPT_DIR/docker/linux/Dockerfile.amd64"
        if [ -f "$dockerfile" ]; then
            build_with_buildx "$buildx_platforms" "$dockerfile" "$tag"
        else
            error "Dockerfile not found: $dockerfile"
            exit 1
        fi
    else
        # Individual platform builds
        local success_count=0
        local total_count=${#platforms[@]}

        for platform_spec in "${platforms[@]}"; do
            IFS='/' read -r os arch <<< "$platform_spec"
            local dockerfile="$SCRIPT_DIR/docker/${os}/Dockerfile.${arch}"

            if [ -f "$dockerfile" ]; then
                if build_platform "$os" "$arch" "$dockerfile" "${os} ${arch}"; then
                    ((success_count++))
                fi
            else
                warn "Dockerfile not found for ${platform_spec}: $dockerfile"
            fi
        done

        info "Build summary: $success_count/$total_count platforms successful"
    fi

    # Generate metadata if requested
    if [ "$generate_meta" = true ]; then
        generate_metadata
    fi

    log "✓ Multi-platform builds completed"
    if [ "$generate_meta" = true ]; then
        log "Metadata: $METADATA_DIR"
    fi
}

main "$@"
