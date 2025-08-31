#!/bin/bash

# Linux-specific build script for sample binaries
# Handles native and cross-compilation builds

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
  \"platform\": \"linux\",
  \"architecture\": \"$(uname -m)\"
}"

    if ! $compiler $extra_flags -o "$output_file" "$source_file"; then
        error "Failed to compile $source_file with $compiler"
        return 1
    fi
    chmod +x "$output_file"
}

build_native_variants() {
    local source_file="$1" lang="$2" basename
    basename="$(basename "$source_file" .${lang})"

    # Choose drivers based on language
    local cc=gcc
    local cxx=g++
    local clang=clang
    local clangxx=clang++
    if [[ "$lang" == "cpp" ]]; then
        cc="$cxx"
        clang="$clangxx"
    fi

    # GCC variants
    for opt in O0 O1 O2 O3; do
        compile_binary "$source_file" "$cc" "$BINARIES_DIR/native/gcc/$opt" \
            "${basename}-gcc-${opt}" "-$opt -Wall -Wextra" "GCC compiled with -$opt" || warn "gcc $opt failed"
    done
    compile_binary "$source_file" "$cc" "$BINARIES_DIR/native/gcc/debug" \
        "${basename}-gcc-debug" "-O0 -g -Wall -Wextra" "GCC debug build" || warn "gcc debug failed"
    compile_binary "$source_file" "$cc" "$BINARIES_DIR/native/gcc/debug" \
        "${basename}-gcc-stripped" "-O2 -s" "GCC stripped build" || warn "gcc stripped failed"

    # Clang variants
    for opt in O0 O1 O2 O3; do
        compile_binary "$source_file" "$clang" "$BINARIES_DIR/native/clang/$opt" \
            "${basename}-clang-${opt}" "-$opt -Wall -Wextra" "Clang 15 compiled with -$opt" || warn "clang $opt failed"
    done
    compile_binary "$source_file" "$clang" "$BINARIES_DIR/native/clang/debug" \
        "${basename}-clang-debug" "-O0 -g -Wall -Wextra" "Clang 15 debug build" || warn "clang debug failed"
    compile_binary "$source_file" "$clang" "$BINARIES_DIR/native/clang/debug" \
        "${basename}-clang-stripped" "-O2 -Wl,-s" "Clang 15 stripped build" || warn "clang stripped failed"
}

build_cross_variants() {
    local source_file="$1" lang="$2" basename
    basename="$(basename "$source_file" .${lang})"

    # Select C vs C++ drivers where needed
    local gcc_cross="gcc"
    local mingw_cross="x86_64-w64-mingw32-gcc"
    if [[ "$lang" == "cpp" ]]; then
        gcc_cross="g++"
        mingw_cross="x86_64-w64-mingw32-g++"
    fi

    # ARM64 cross-compilation
    if command -v aarch64-linux-gnu-${gcc_cross} &> /dev/null; then
        compile_binary "$source_file" aarch64-linux-gnu-${gcc_cross} "$BINARIES_DIR/cross/arm64" \
            "${basename}-arm64-${gcc_cross}" "-O2 -Wall" "GCC cross ARM64 (${gcc_cross})"
    fi

    # ARM 32-bit cross-compilation
    if command -v arm-linux-gnueabihf-${gcc_cross} &> /dev/null; then
        compile_binary "$source_file" arm-linux-gnueabihf-${gcc_cross} "$BINARIES_DIR/cross/armhf" \
            "${basename}-armhf-${gcc_cross}" "-O2 -Wall" "GCC cross ARM 32-bit (${gcc_cross})"
    fi

    # RISC-V cross-compilation
    if command -v riscv64-linux-gnu-${gcc_cross} &> /dev/null; then
        compile_binary "$source_file" riscv64-linux-gnu-${gcc_cross} "$BINARIES_DIR/cross/riscv64" \
            "${basename}-riscv64-${gcc_cross}" "-O2 -Wall" "GCC cross RISC-V 64 (${gcc_cross})"
    fi

    # 32-bit via multilib if supported
    if command -v ${gcc_cross} &> /dev/null; then
        if echo "int main(){}" | ${gcc_cross} -m32 -x c - -o /dev/null &>/dev/null; then
            compile_binary "$source_file" ${gcc_cross} "$BINARIES_DIR/cross/x86_32" \
                "${basename}-x86_32-${gcc_cross}" "-m32 -O2 -Wall" "${gcc_cross} 32-bit x86"
        else
            warn "${gcc_cross} -m32 unsupported (missing multilib)"
        fi
    fi

    # Windows PE via MinGW-w64
    if command -v ${mingw_cross} &> /dev/null; then
        compile_binary "$source_file" ${mingw_cross} "$BINARIES_DIR/cross/windows-x86_64" \
            "${basename}-${lang}-x86_64-mingw.exe" "-O2 -Wall" "MinGW-w64 PE (x86_64) via ${mingw_cross}"
    fi
}

build_fortran_variants() {
    local source_file="$1" basename
    basename="$(basename "$source_file" .f90)"
    if command -v gfortran-11 &> /dev/null; then
        for opt in O0 O1 O2 O3; do
            compile_binary "$source_file" gfortran-11 "$BINARIES_DIR/fortran" \
                "${basename}-gfortran-${opt}" "-$opt -Wall -Wextra" "GFortran 11 -$opt" || warn "gfortran $opt failed"
        done
        compile_binary "$source_file" gfortran-11 "$BINARIES_DIR/fortran" \
            "${basename}-gfortran-debug" "-O0 -g -Wall -Wextra -fbacktrace" "GFortran 11 debug" || warn "gfortran debug failed"
    else
        warn "gfortran-11 not found, skipping Fortran"
    fi
}

build_java_variants() {
    local source_file="$1" basename
    basename="$(basename "$source_file" .java)"
    if command -v javac &> /dev/null; then
        ensure_dir "$BINARIES_DIR/java"
        local class_file="$BINARIES_DIR/java/${basename}.class"
        write_metadata "$METADATA_DIR/${basename}-javac.json" "{
  \"source_file\": \"$source_file\",
  \"compiler\": \"javac\",
  \"output_file\": \"$class_file\",
  \"compilation_flags\": \"\",
  \"description\": \"Java compiled to bytecode\",
  \"timestamp\": \"$(date -Iseconds)\",
  \"platform\": \"linux\",
  \"architecture\": \"$(uname -m)\"
}"
        if ! javac -d "$BINARIES_DIR/java" "$source_file"; then
            error "javac failed"
            return 1
        fi
        local jar_file="$BINARIES_DIR/java/${basename}.jar"
        echo "Main-Class: ${basename}" > "$BINARIES_DIR/java/manifest.txt"
        if command -v jar &> /dev/null; then
            (cd "$BINARIES_DIR/java" && jar cfm "$jar_file" manifest.txt "${basename}.class")
            write_metadata "$METADATA_DIR/${basename}-jar.json" "{
  \"source_file\": \"$source_file\",
  \"compiler\": \"javac+jar\",
  \"output_file\": \"$jar_file\",
  \"compilation_flags\": \"\",
  \"description\": \"Java JAR\",
  \"timestamp\": \"$(date -Iseconds)\",
  \"platform\": \"linux\",
  \"architecture\": \"$(uname -m)\"
}"
        fi
    else
        warn "javac not found, skipping Java"
    fi
}

build_python_variants() {
    local source_file="$1" basename
    basename="$(basename "$source_file" .py)"
    ensure_dir "$BINARIES_DIR/python"
    if command -v python3 &> /dev/null; then
        local pyc_file="$BINARIES_DIR/python/${basename}.pyc"
        write_metadata "$METADATA_DIR/${basename}-python.json" "{
  \"source_file\": \"$source_file\",
  \"compiler\": \"python3\",
  \"output_file\": \"$pyc_file\",
  \"compilation_flags\": \"\",
  \"description\": \"Python bytecode\",
  \"timestamp\": \"$(date -Iseconds)\",
  \"platform\": \"linux\",
  \"architecture\": \"$(uname -m)\"
}"
        python3 -m py_compile "$source_file"
        # Move generated pyc from __pycache__ to deterministic path
        local cache
        cache=$(python3 - "$source_file" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
print(next(p.parent.glob('__pycache__/' + p.stem + '.*.pyc')))
PY
)
        cp "$cache" "$pyc_file"

        local opt_pyc_file="$BINARIES_DIR/python/${basename}.opt.pyc"
        python3 -O -m py_compile "$source_file"
        cache=$(python3 - "$source_file" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
print(next(p.parent.glob('__pycache__/' + p.stem + '.*.opt-*.pyc')))
PY
)
        cp "$cache" "$opt_pyc_file"
        write_metadata "$METADATA_DIR/${basename}-python-opt.json" "{
  \"source_file\": \"$source_file\",
  \"compiler\": \"python3 -O\",
  \"output_file\": \"$opt_pyc_file\",
  \"compilation_flags\": \"-O\",
  \"description\": \"Python optimized bytecode\",
  \"timestamp\": \"$(date -Iseconds)\",
  \"platform\": \"linux\",
  \"architecture\": \"$(uname -m)\"
}"
    else
        warn "python3 not found, skipping Python"
    fi
}

main() {
    log "Starting Linux sample builds"
    log "Source: $SOURCE_DIR"
    log "Output: $BINARIES_DIR"

    ensure_dir "$METADATA_DIR"
    ensure_dir "$BINARIES_DIR/native/gcc/O0"; ensure_dir "$BINARIES_DIR/native/gcc/O1"
    ensure_dir "$BINARIES_DIR/native/gcc/O2"; ensure_dir "$BINARIES_DIR/native/gcc/O3"
    ensure_dir "$BINARIES_DIR/native/gcc/debug"
    ensure_dir "$BINARIES_DIR/native/clang/O0"; ensure_dir "$BINARIES_DIR/native/clang/O1"
    ensure_dir "$BINARIES_DIR/native/clang/O2"; ensure_dir "$BINARIES_DIR/native/clang/O3"
    ensure_dir "$BINARIES_DIR/native/clang/debug"
    ensure_dir "$BINARIES_DIR/cross/arm64"; ensure_dir "$BINARIES_DIR/cross/armhf"
    ensure_dir "$BINARIES_DIR/cross/x86_32"; ensure_dir "$BINARIES_DIR/cross/riscv64"
    ensure_dir "$BINARIES_DIR/cross/windows-x86_64"; ensure_dir "$BINARIES_DIR/fortran"

    # Build C/C++ samples
    [ -f "$SOURCE_DIR/c/hello.c" ] && build_native_variants "$SOURCE_DIR/c/hello.c" c && build_cross_variants "$SOURCE_DIR/c/hello.c" c
    [ -f "$SOURCE_DIR/cpp/hello.cpp" ] && build_native_variants "$SOURCE_DIR/cpp/hello.cpp" cpp && build_cross_variants "$SOURCE_DIR/cpp/hello.cpp" cpp

    # Build other languages
    [ -f "$SOURCE_DIR/fortran/hello.f90" ] && build_fortran_variants "$SOURCE_DIR/fortran/hello.f90"
    [ -f "$SOURCE_DIR/java/HelloWorld.java" ] && build_java_variants "$SOURCE_DIR/java/HelloWorld.java"
    [ -f "$SOURCE_DIR/python/hello.py" ] && build_python_variants "$SOURCE_DIR/python/hello.py"

    log "Linux builds completed successfully"
}

main "$@"
