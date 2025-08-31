#!/bin/bash

# macOS cross-compilation build script
# Builds macOS executables from Linux host using osxcross

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Prefer container workspace if present
DEFAULT_WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
if [ -d "/workspace" ]; then
    WORKSPACE_DIR="/workspace"
else
    WORKSPACE_DIR="$DEFAULT_WORKSPACE"
fi
SOURCE_DIR="$WORKSPACE_DIR/source"
BINARIES_DIR="$WORKSPACE_DIR/binaries"
METADATA_DIR="$BINARIES_DIR/metadata"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[BUILD] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}" >&2; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
info() { echo -e "${BLUE}[INFO] $1${NC}"; }

ensure_dir() { [ -d "$1" ] || mkdir -p "$1"; }

write_metadata() {
    local meta_file="$1"; shift
    local content="$*"
    ensure_dir "$(dirname "$meta_file")"
    echo "$content" > "$meta_file"
}

build_java_variants() {
    local source_file="$1" basename
    basename="$(basename "$source_file" .java)"

    # Discover installed JDKs
    local javac_paths=()
    while IFS= read -r p; do javac_paths+=("$p"); done < <(compgen -G "/usr/lib/jvm/*/bin/javac" || true)
    # Include default if present
    if command -v javac &>/dev/null; then
        local sys_javac
        sys_javac="$(command -v javac)"
        local found=false
        for p in "${javac_paths[@]}"; do [ "$p" = "$sys_javac" ] && found=true && break; done
        [ "$found" = false ] && javac_paths+=("$sys_javac")
    fi

    if [ ${#javac_paths[@]} -eq 0 ]; then
        warn "javac not found, skipping Java"
        return 0
    fi

    ensure_dir "$BINARIES_DIR/java"

    # Default jar using first detected JDK
    local default_javac="${javac_paths[0]}"
    local default_dir="$BINARIES_DIR/java"
    if "$default_javac" -d "$default_dir" "$source_file"; then
        echo "Main-Class: ${basename}" > "$default_dir/manifest.txt"
        local default_jar="$default_dir/${basename}.jar"
        local jar_bin
        jar_bin="$(dirname "$(dirname "$default_javac")")/bin/jar"
        [ -x "$jar_bin" ] && (cd "$default_dir" && "$jar_bin" cfm "$default_jar" manifest.txt "${basename}.class")
    fi

    for javac_bin in "${javac_paths[@]}"; do
        local java_home version outdir class_file jar_bin jar_file
        java_home="$(dirname "$(dirname "$javac_bin")")"
        version="$($javac_bin -version 2>&1 | awk '{print $2}' | cut -d. -f1)"; [ -z "$version" ] && version="unknown"
        outdir="$BINARIES_DIR/java/jdk$version"
        ensure_dir "$outdir"
        class_file="$outdir/${basename}.class"
        write_metadata "$METADATA_DIR/${basename}-javac-jdk$version.json" "{
  \"source_file\": \"$source_file\",
  \"compiler\": \"$javac_bin\",
  \"java_home\": \"$java_home\",
  \"java_version\": \"$($javac_bin -version 2>&1)\",
  \"output_file\": \"$class_file\",
  \"compilation_flags\": \"\",
  \"description\": \"Java compiled to bytecode (JDK $version)\",
  \"timestamp\": \"$(date -Iseconds)\",
  \"platform\": \"darwin\",
  \"architecture\": \"$(uname -m)\"
}"
        if ! "$javac_bin" -d "$outdir" "$source_file"; then
            warn "javac (JDK $version) failed"
            continue
        fi
        jar_bin="$java_home/bin/jar"
        if [ -x "$jar_bin" ]; then
            jar_file="$outdir/${basename}.jar"
            echo "Main-Class: ${basename}" > "$outdir/manifest.txt"
            (cd "$outdir" && "$jar_bin" cfm "$jar_file" manifest.txt "${basename}.class")
            write_metadata "$METADATA_DIR/${basename}-jar-jdk$version.json" "{
  \"source_file\": \"$source_file\",
  \"compiler\": \"$javac_bin+jar\",
  \"java_home\": \"$java_home\",
  \"java_version\": \"$($javac_bin -version 2>&1)\",
  \"output_file\": \"$jar_file\",
  \"compilation_flags\": \"\",
  \"description\": \"Java JAR (JDK $version)\",
  \"timestamp\": \"$(date -Iseconds)\",
  \"platform\": \"darwin\",
  \"architecture\": \"$(uname -m)\"
}"
        fi
    done
}
compile_binary() {
    local source_file="$1" compiler="$2" output_dir="$3" basename="$4" extra_flags="$5" description="$6"
    local output_file="$output_dir/${basename}"
    ensure_dir "$output_dir"

    log "Compiling $source_file with $compiler -> $output_file"

    write_metadata "$METADATA_DIR/${basename}.json" "{
  \"source_file\": \"$source_file\",
  \"compiler\": \"$compiler\",
  \"output_file\": \"$output_file\",
  \"compilation_flags\": \"$extra_flags\",
  \"description\": \"$description\",
  \"timestamp\": \"$(date -Iseconds)\",
  \"platform\": \"darwin\",
  \"architecture\": \"$(echo $compiler | grep -o 'x86_64\|arm64' || echo 'unknown')\",
  \"target_os\": \"macos\"
}"

    if ! $compiler $extra_flags -o "$output_file" "$source_file"; then
        error "Failed to compile $source_file with $compiler"
        return 1
    fi
    chmod +x "$output_file"
}

build_macos_variants() {
    local source_file="$1" lang="$2" basename
    basename="$(basename "$source_file" .${lang})"

    # Select C vs C++ drivers
    local osxcross="o64-clang"
    local osxcrossxx="o64-clang++"
    if [[ "$lang" == "cpp" ]]; then
        osxcross="$osxcrossxx"
    fi

    # macOS x86_64 variants
    if command -v "$osxcross" &> /dev/null; then
        for opt in O0 O1 O2 O3; do
            compile_binary "$source_file" "$osxcross" "$BINARIES_DIR/darwin/x86_64/$opt" \
                "${basename}-macos-x86_64-${opt}" "-$opt -Wall -Wextra" "OSXCross x86_64 -$opt" || warn "osxcross x86_64 $opt failed"
        done
        compile_binary "$source_file" "$osxcross" "$BINARIES_DIR/darwin/x86_64/debug" \
            "${basename}-macos-x86_64-debug" "-O0 -g -Wall -Wextra" "OSXCross x86_64 debug" || warn "osxcross x86_64 debug failed"
        compile_binary "$source_file" "$osxcross" "$BINARIES_DIR/darwin/x86_64/release" \
            "${basename}-macos-x86_64-release" "-O2" "OSXCross x86_64 release" || warn "osxcross x86_64 release failed"
    else
        warn "OSXCross not found, skipping macOS builds"
    fi
}

build_cross_from_macos() {
    local source_file="$1" lang="$2" basename
    basename="$(basename "$source_file" .${lang})"

    # Select C vs C++ drivers
    local gcc_cross="gcc"
    local aarch64_cross="aarch64-linux-gnu-gcc"
    local arm_cross="arm-linux-gnueabihf-gcc"
    local riscv64_cross="riscv64-linux-gnu-gcc"
    local mingw64_cross="x86_64-w64-mingw32-gcc"
    if [[ "$lang" == "cpp" ]]; then
        gcc_cross="g++"
        aarch64_cross="aarch64-linux-gnu-g++"
        arm_cross="arm-linux-gnueabihf-g++"
        riscv64_cross="riscv64-linux-gnu-g++"
        mingw64_cross="x86_64-w64-mingw32-g++"
    fi

    # Cross-compile to Linux ARM64
    if command -v "$aarch64_cross" &> /dev/null; then
        compile_binary "$source_file" "$aarch64_cross" "$BINARIES_DIR/cross/linux-arm64" \
            "${basename}-linux-arm64-${gcc_cross}" "-O2 -Wall" "Cross-compile to Linux ARM64" || warn "aarch64 cross failed"
    fi

    # Cross-compile to Linux ARM 32-bit
    if command -v "$arm_cross" &> /dev/null; then
        compile_binary "$source_file" "$arm_cross" "$BINARIES_DIR/cross/linux-armhf" \
            "${basename}-linux-armhf-${gcc_cross}" "-O2 -Wall" "Cross-compile to Linux ARM 32-bit" || warn "armhf cross failed"
    fi

    # Cross-compile to Linux RISC-V
    if command -v "$riscv64_cross" &> /dev/null; then
        compile_binary "$source_file" "$riscv64_cross" "$BINARIES_DIR/cross/linux-riscv64" \
            "${basename}-linux-riscv64-${gcc_cross}" "-O2 -Wall" "Cross-compile to Linux RISC-V 64" || warn "riscv64 cross failed"
    fi

    # Cross-compile to Windows
    if command -v "$mingw64_cross" &> /dev/null; then
        compile_binary "$source_file" "$mingw64_cross" "$BINARIES_DIR/cross/windows-x86_64" \
            "${basename}-windows-x86_64-${mingw64_cross}.exe" "-O2 -Wall" "Cross-compile to Windows x86_64" || warn "mingw64 cross failed"
    fi

    # 32-bit x86 (if multilib supported)
    if command -v ${gcc_cross} &> /dev/null; then
        if echo "int main(){}" | ${gcc_cross} -m32 -x c - -o /dev/null &>/dev/null; then
            compile_binary "$source_file" ${gcc_cross} "$BINARIES_DIR/cross/linux-x86_32" \
                "${basename}-linux-x86_32-${gcc_cross}" "-m32 -O2 -Wall" "Cross-compile to Linux x86 32-bit" || warn "x86_32 cross failed"
        fi
    fi
}

build_fortran_macos() {
    local source_file="$1" basename
    basename="$(basename "$source_file" .f90)"

    # Use osxcross Fortran if available
    if command -v o64-gfortran &> /dev/null; then
        for opt in O0 O1 O2 O3; do
            compile_binary "$source_file" o64-gfortran "$BINARIES_DIR/darwin/fortran" \
                "${basename}-macos-gfortran-${opt}" "-$opt -Wall -Wextra" "OSXCross Fortran -$opt" || warn "osxcross gfortran $opt failed"
        done
        compile_binary "$source_file" o64-gfortran "$BINARIES_DIR/darwin/fortran" \
            "${basename}-macos-gfortran-debug" "-O0 -g -Wall -Wextra" "OSXCross Fortran debug" || warn "osxcross gfortran debug failed"
    else
        warn "OSXCross Fortran not found, skipping macOS Fortran builds"
    fi
}

main() {
    log "Starting macOS cross-compilation builds"
    log "Source: $SOURCE_DIR"
    log "Output: $BINARIES_DIR"

    ensure_dir "$METADATA_DIR"
    ensure_dir "$BINARIES_DIR/darwin/x86_64/O0"; ensure_dir "$BINARIES_DIR/darwin/x86_64/O1"
    ensure_dir "$BINARIES_DIR/darwin/x86_64/O2"; ensure_dir "$BINARIES_DIR/darwin/x86_64/O3"
    ensure_dir "$BINARIES_DIR/darwin/x86_64/debug"; ensure_dir "$BINARIES_DIR/darwin/x86_64/release"
    ensure_dir "$BINARIES_DIR/darwin/fortran"
    ensure_dir "$BINARIES_DIR/cross/linux-arm64"; ensure_dir "$BINARIES_DIR/cross/linux-armhf"
    ensure_dir "$BINARIES_DIR/cross/linux-riscv64"; ensure_dir "$BINARIES_DIR/cross/linux-x86_32"
    ensure_dir "$BINARIES_DIR/cross/windows-x86_64"

    # Build C/C++ samples for macOS
    [ -f "$SOURCE_DIR/c/hello.c" ] && build_macos_variants "$SOURCE_DIR/c/hello.c" c && build_cross_from_macos "$SOURCE_DIR/c/hello.c" c
    [ -f "$SOURCE_DIR/cpp/hello.cpp" ] && build_macos_variants "$SOURCE_DIR/cpp/hello.cpp" cpp && build_cross_from_macos "$SOURCE_DIR/cpp/hello.cpp" cpp

    # Build Fortran for macOS
    [ -f "$SOURCE_DIR/fortran/hello.f90" ] && build_fortran_macos "$SOURCE_DIR/fortran/hello.f90"

    # Build Java with multiple JDKs (platform-independent artifact)
    [ -f "$SOURCE_DIR/java/HelloWorld.java" ] && build_java_variants "$SOURCE_DIR/java/HelloWorld.java"

    log "macOS cross-compilation builds completed successfully"
}

main "$@"
