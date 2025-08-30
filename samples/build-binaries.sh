#!/bin/bash

# Build script for creating binary artifacts for integration tests
# Compiles sources with various compilers/options, cross-targets, and collects system binaries.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/source"
BINARIES_DIR="$SCRIPT_DIR/binaries"
METADATA_DIR="$BINARIES_DIR/metadata"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}" >&2; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }

ensure_dir() { [ -d "$1" ] || mkdir -p "$1"; }

write_metadata() {
  # args: path-to-json, json-contents
  local meta_file="$1"; shift
  ensure_dir "$(dirname "$meta_file")"
  cat > "$meta_file" << EOF
$*
EOF
}

compile_binary() {
    local source_file="$1" compiler="$2" output_dir="$3" basename="$4" extra_flags="$5" description="$6"
    local output_file="$output_dir/${basename}"
    ensure_dir "$output_dir"

    log "Compiling $source_file with $compiler -> $output_file"

    write_metadata "$METADATA_DIR/${basename}.json" "{\n  \"source_file\": \"$source_file\",\n  \"compiler\": \"$compiler\",\n  \"output_file\": \"$output_file\",\n  \"compilation_flags\": \"$extra_flags\",\n  \"description\": \"$description\",\n  \"timestamp\": \"$(date -Iseconds)\",\n  \"hostname\": \"$(hostname)\"\n}"

    if ! $compiler $extra_flags -o "$output_file" "$source_file"; then
        error "Failed to compile $source_file with $compiler"
        return 1
    fi
    chmod +x "$output_file"
}

build_variants() {
    local source_file="$1" lang="$2" basename
    basename="$(basename "$source_file" .${lang})"

    # Choose drivers based on language
    local cc=gcc
    local cxx=g++
    local clang=clang-20
    local clangxx=clang++-20
    if [[ "$lang" == "cpp" ]]; then
        cc="$cxx"
        clang="$clangxx"
    fi

    if command -v "$cc" &> /dev/null; then
        for opt in O0 O1 O2 O3; do
            compile_binary "$source_file" "$cc" "$BINARIES_DIR/native/gcc/$opt" \
                "${basename}-gcc-${opt}" "-$opt -Wall -Wextra" "GCC compiled with -$opt" || warn "gcc $opt failed"
        done
        compile_binary "$source_file" "$cc" "$BINARIES_DIR/native/gcc/debug" \
            "${basename}-gcc-debug" "-O0 -g -Wall -Wextra" "GCC debug build" || warn "gcc debug failed"
        compile_binary "$source_file" "$cc" "$BINARIES_DIR/native/gcc/debug" \
            "${basename}-gcc-stripped" "-O2 -s" "GCC stripped build" || warn "gcc stripped failed"
        # Extra variants
        compile_binary "$source_file" "$cc" "$BINARIES_DIR/native/gcc/O2" \
            "${basename}-gcc-O2-nofp" "-O2 -g -fno-omit-frame-pointer" "GCC O2 with frame pointers" || warn "gcc O2 nofp failed"
        compile_binary "$source_file" "$cc" "$BINARIES_DIR/native/gcc/O3" \
            "${basename}-gcc-O3-lto" "-O3 -flto" "GCC O3 with LTO" || warn "gcc O3 LTO failed"
    else
        warn "GCC not found, skipping GCC variants"
    fi

    if command -v "$clang" &> /dev/null; then
        for opt in O0 O1 O2 O3; do
            compile_binary "$source_file" "$clang" "$BINARIES_DIR/native/clang/$opt" \
                "${basename}-clang-${opt}" "-$opt -Wall -Wextra" "Clang 20 compiled with -$opt" || warn "clang $opt failed"
        done
        compile_binary "$source_file" "$clang" "$BINARIES_DIR/native/clang/debug" \
            "${basename}-clang-debug" "-O0 -g -Wall -Wextra" "Clang 20 debug build" || warn "clang debug failed"
        compile_binary "$source_file" "$clang" "$BINARIES_DIR/native/clang/debug" \
            "${basename}-clang-stripped" "-O2 -Wl,-s" "Clang 20 stripped build" || warn "clang stripped failed"
        # Extra variants
        compile_binary "$source_file" "$clang" "$BINARIES_DIR/native/clang/O2" \
            "${basename}-clang-O2-nofp" "-O2 -g -fno-omit-frame-pointer" "Clang O2 with frame pointers" || warn "clang O2 nofp failed"
        compile_binary "$source_file" "$clang" "$BINARIES_DIR/native/clang/O3" \
            "${basename}-clang-O3-lto" "-O3 -flto" "Clang O3 with LTO" || warn "clang O3 LTO failed"
    else
        warn "Clang-20 not found, skipping Clang variants"
    fi
}

build_cross_variants() {
    local source_file="$1" lang="$2" basename
    basename="$(basename "$source_file" .${lang})"

    if command -v aarch64-linux-gnu-gcc &> /dev/null; then
        compile_binary "$source_file" aarch64-linux-gnu-gcc "$BINARIES_DIR/cross/arm64" \
            "${basename}-arm64-gcc" "-O2 -Wall" "GCC cross ARM64"
    fi
    if command -v riscv64-linux-gnu-gcc &> /dev/null; then
        compile_binary "$source_file" riscv64-linux-gnu-gcc "$BINARIES_DIR/cross/riscv64" \
            "${basename}-riscv64-gcc" "-O2 -Wall" "GCC cross RISC-V 64"
    fi
    # 32-bit via multilib if supported
    if command -v gcc &> /dev/null; then
        if echo "int main(){}" | gcc -m32 -x c - -o /dev/null &>/dev/null; then
            compile_binary "$source_file" gcc "$BINARIES_DIR/cross/x86_32" \
                "${basename}-x86_32-gcc" "-m32 -O2 -Wall" "GCC 32-bit x86"
        else
            warn "gcc -m32 unsupported (missing multilib)"
        fi
    fi
    # Windows PE via MinGW-w64 if available
    if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        compile_binary "$source_file" x86_64-w64-mingw32-gcc "$BINARIES_DIR/cross/windows-x86_64" \
            "${basename}-x86_64-mingw.exe" "-O2 -Wall" "MinGW-w64 PE (x86_64)"
    fi
}

build_fortran_variants() {
    local source_file="$1" basename
    basename="$(basename "$source_file" .f90)"
    if command -v gfortran-15 &> /dev/null; then
        for opt in O0 O1 O2 O3; do
            compile_binary "$source_file" gfortran-15 "$BINARIES_DIR/fortran" \
                "${basename}-gfortran-${opt}" "-$opt -Wall -Wextra" "GFortran 15 -$opt" || warn "gfortran $opt failed"
        done
        compile_binary "$source_file" gfortran-15 "$BINARIES_DIR/fortran" \
            "${basename}-gfortran-debug" "-O0 -g -Wall -Wextra -fbacktrace" "GFortran 15 debug" || warn "gfortran debug failed"
    else
        warn "gfortran-15 not found, skipping Fortran"
    fi
}

build_java_variants() {
    local source_file="$1" basename
    basename="$(basename "$source_file" .java)"
    if command -v javac &> /dev/null; then
        ensure_dir "$BINARIES_DIR/java"
        local class_file="$BINARIES_DIR/java/${basename}.class"
        write_metadata "$METADATA_DIR/${basename}-javac.json" "{\n  \"source_file\": \"$source_file\",\n  \"compiler\": \"javac\",\n  \"output_file\": \"$class_file\",\n  \"compilation_flags\": \"\",\n  \"description\": \"Java compiled to bytecode\",\n  \"timestamp\": \"$(date -Iseconds)\",\n  \"hostname\": \"$(hostname)\"\n}"
        if ! javac -d "$BINARIES_DIR/java" "$source_file"; then
            error "javac failed"
            return 1
        fi
        local jar_file="$BINARIES_DIR/java/${basename}.jar"
        echo "Main-Class: ${basename}" > "$BINARIES_DIR/java/manifest.txt"
        if command -v jar &> /dev/null; then
            (cd "$BINARIES_DIR/java" && jar cfm "$jar_file" manifest.txt "${basename}.class")
            write_metadata "$METADATA_DIR/${basename}-jar.json" "{\n  \"source_file\": \"$source_file\",\n  \"compiler\": \"javac+jar\",\n  \"output_file\": \"$jar_file\",\n  \"compilation_flags\": \"\",\n  \"description\": \"Java JAR\",\n  \"timestamp\": \"$(date -Iseconds)\",\n  \"hostname\": \"$(hostname)\"\n}"
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
        write_metadata "$METADATA_DIR/${basename}-python.json" "{\n  \"source_file\": \"$source_file\",\n  \"compiler\": \"python3\",\n  \"output_file\": \"$pyc_file\",\n  \"compilation_flags\": \"\",\n  \"description\": \"Python bytecode\",\n  \"timestamp\": \"$(date -Iseconds)\",\n  \"hostname\": \"$(hostname)\"\n}"
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
        write_metadata "$METADATA_DIR/${basename}-python-opt.json" "{\n  \"source_file\": \"$source_file\",\n  \"compiler\": \"python3 -O\",\n  \"output_file\": \"$opt_pyc_file\",\n  \"compilation_flags\": \"-O\",\n  \"description\": \"Python optimized bytecode\",\n  \"timestamp\": \"$(date -Iseconds)\",\n  \"hostname\": \"$(hostname)\"\n}"
    else
        warn "python3 not found, skipping Python"
    fi
}

collect_system_binaries() {
    log "Collecting system binaries and kernel images"
    local system_dir="$BINARIES_DIR/native/system"
    ensure_dir "$system_dir"
    ensure_dir "$system_dir/libs"

    if [ -d /boot ]; then
        for kernel in /boot/vmlinuz*; do
            [ -f "$kernel" ] || continue
            local base=$(basename "$kernel")
            if cp "$kernel" "$system_dir/$base" 2>/dev/null; then
              write_metadata "$METADATA_DIR/${base}.json" "{\n  \"source_path\": \"$kernel\",\n  \"output_file\": \"$system_dir/$base\",\n  \"type\": \"kernel_image\",\n  \"description\": \"Linux kernel image from /boot\",\n  \"timestamp\": \"$(date -Iseconds)\",\n  \"hostname\": \"$(hostname)\"\n}"
            else
              warn "Cannot read kernel $kernel"
            fi
        done
        for img in /boot/initrd* /boot/config*; do
            [ -f "$img" ] || continue
            local base=$(basename "$img")
            if ! cp "$img" "$system_dir/$base" 2>/dev/null; then
              warn "Cannot read $img"
              continue
            fi
            local kind
            if [[ "$base" == initrd* ]]; then kind=initrd_image; else kind=kernel_config; fi
            write_metadata "$METADATA_DIR/${base}.json" "{\n  \"source_path\": \"$img\",\n  \"output_file\": \"$system_dir/$base\",\n  \"type\": \"$kind\",\n  \"description\": \"$kind from /boot\",\n  \"timestamp\": \"$(date -Iseconds)\",\n  \"hostname\": \"$(hostname)\"\n}"
        done
    else
        warn "/boot not accessible"
    fi

    local bins=(ls cat grep awk sed bash sh python3 gcc clang-20)
    for b in "${bins[@]}"; do
        if command -v "$b" &>/dev/null; then
            local p; p=$(command -v "$b")
            local base; base=$(basename "$p")
            cp "$p" "$system_dir/$base" || true
            chmod +x "$system_dir/$base" || true
            write_metadata "$METADATA_DIR/${base}.json" "{\n  \"source_path\": \"$p\",\n  \"output_file\": \"$system_dir/$base\",\n  \"type\": \"system_binary\",\n  \"description\": \"System binary: $b\",\n  \"timestamp\": \"$(date -Iseconds)\",\n  \"hostname\": \"$(hostname)\"\n}"
            if command -v ldd &>/dev/null; then
                ldd "$p" | awk '/=>/ {print $3} /^[^\t]/ && /\// {print $1}' | while read -r lib; do
                    [ -f "$lib" ] || continue
                    local lbase; lbase=$(basename "$lib")
                    cp -n "$lib" "$system_dir/libs/$lbase" 2>/dev/null || true
                    write_metadata "$METADATA_DIR/${lbase}.json" "{\n  \"source_path\": \"$lib\",\n  \"output_file\": \"$system_dir/libs/$lbase\",\n  \"type\": \"shared_library\",\n  \"description\": \"System library: $lbase\",\n  \"timestamp\": \"$(date -Iseconds)\",\n  \"hostname\": \"$(hostname)\"\n}"
                done
            fi
        fi
    done
}

main() {
    log "Start build"
    log "Source: $SOURCE_DIR"
    log "Out: $BINARIES_DIR"

    ensure_dir "$METADATA_DIR"
    ensure_dir "$BINARIES_DIR/native/gcc/O0"; ensure_dir "$BINARIES_DIR/native/gcc/O1"; ensure_dir "$BINARIES_DIR/native/gcc/O2"; ensure_dir "$BINARIES_DIR/native/gcc/O3"; ensure_dir "$BINARIES_DIR/native/gcc/debug"
    ensure_dir "$BINARIES_DIR/native/clang/O0"; ensure_dir "$BINARIES_DIR/native/clang/O1"; ensure_dir "$BINARIES_DIR/native/clang/O2"; ensure_dir "$BINARIES_DIR/native/clang/O3"; ensure_dir "$BINARIES_DIR/native/clang/debug"
    ensure_dir "$BINARIES_DIR/native/system"; ensure_dir "$BINARIES_DIR/cross/arm64"; ensure_dir "$BINARIES_DIR/cross/x86_32"; ensure_dir "$BINARIES_DIR/cross/riscv64"; ensure_dir "$BINARIES_DIR/cross/windows-x86_64"; ensure_dir "$BINARIES_DIR/fortran"; ensure_dir "$BINARIES_DIR/java"; ensure_dir "$BINARIES_DIR/python"

    [ -f "$SOURCE_DIR/c/hello.c" ] && build_variants "$SOURCE_DIR/c/hello.c" c && build_cross_variants "$SOURCE_DIR/c/hello.c" c || warn "Missing: $SOURCE_DIR/c/hello.c"
    [ -f "$SOURCE_DIR/cpp/hello.cpp" ] && build_variants "$SOURCE_DIR/cpp/hello.cpp" cpp && build_cross_variants "$SOURCE_DIR/cpp/hello.cpp" cpp || warn "Missing: $SOURCE_DIR/cpp/hello.cpp"
    [ -f "$SOURCE_DIR/fortran/hello.f90" ] && build_fortran_variants "$SOURCE_DIR/fortran/hello.f90" || warn "Missing: $SOURCE_DIR/fortran/hello.f90"
    [ -f "$SOURCE_DIR/java/HelloWorld.java" ] && build_java_variants "$SOURCE_DIR/java/HelloWorld.java" || warn "Missing: $SOURCE_DIR/java/HelloWorld.java"
    [ -f "$SOURCE_DIR/python/hello.py" ] && build_python_variants "$SOURCE_DIR/python/hello.py" || warn "Missing: $SOURCE_DIR/python/hello.py"

    collect_system_binaries
    log "Done. Binaries -> $BINARIES_DIR; Metadata -> $METADATA_DIR"
}

main "$@"
