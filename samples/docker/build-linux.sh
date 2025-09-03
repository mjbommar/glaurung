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

    # Additional linker-path variants (ELF): RPATH and RUNPATH
    # GCC variants
    compile_binary "$source_file" "$cc" "$BINARIES_DIR/native/gcc/rpath" \
        "${basename}-gcc-rpath" "-O2 -Wl,-rpath,/opt/test" "GCC with RPATH (/opt/test)" || warn "gcc rpath failed"
    compile_binary "$source_file" "$cc" "$BINARIES_DIR/native/gcc/runpath" \
        "${basename}-gcc-runpath" "-O2 -Wl,-rpath,/opt/test -Wl,--enable-new-dtags" "GCC with RUNPATH (/opt/test)" || warn "gcc runpath failed"
    # Clang variants
    compile_binary "$source_file" "$clang" "$BINARIES_DIR/native/clang/rpath" \
        "${basename}-clang-rpath" "-O2 -Wl,-rpath,/opt/test" "Clang with RPATH (/opt/test)" || warn "clang rpath failed"
    compile_binary "$source_file" "$clang" "$BINARIES_DIR/native/clang/runpath" \
        "${basename}-clang-runpath" "-O2 -Wl,-rpath,/opt/test -Wl,--enable-new-dtags" "Clang with RUNPATH (/opt/test)" || warn "clang runpath failed"
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

    # Discover installed JDKs
    local javac_paths=()
    while IFS= read -r p; do javac_paths+=("$p"); done < <(compgen -G "/usr/lib/jvm/*/bin/javac" || true)
    # Include default if not already present
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

    for javac_bin in "${javac_paths[@]}"; do
        local java_home="$(dirname "$(dirname "$javac_bin")")"
        local version
        version="$($javac_bin -version 2>&1 | awk '{print $2}' | cut -d. -f1)"
        [ -z "$version" ] && version="unknown"
        local outdir="$BINARIES_DIR/java/jdk$version"
        ensure_dir "$outdir"

        local class_file="$outdir/${basename}.class"
        write_metadata "$METADATA_DIR/${basename}-javac-jdk$version.json" "{
  \"source_file\": \"$source_file\",
  \"compiler\": \"$javac_bin\",
  \"java_home\": \"$java_home\",
  \"java_version\": \"$($javac_bin -version 2>&1)\",
  \"output_file\": \"$class_file\",
  \"compilation_flags\": \"\",
  \"description\": \"Java compiled to bytecode (JDK $version)\",
  \"timestamp\": \"$(date -Iseconds)\",
  \"platform\": \"linux\",
  \"architecture\": \"$(uname -m)\"
}"
        if ! "$javac_bin" -d "$outdir" "$source_file"; then
            error "javac (JDK $version) failed"
            continue
        fi
        local jar_bin="$java_home/bin/jar"
        if [ -x "$jar_bin" ]; then
            local jar_file="$outdir/${basename}.jar"
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
  \"platform\": \"linux\",
  \"architecture\": \"$(uname -m)\"
}"
        fi
    done
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

build_csharp_variants() {
    local source_file="$1" basename
    basename="$(basename "$source_file" .cs)"
    if command -v mcs &> /dev/null; then
        ensure_dir "$BINARIES_DIR/dotnet/mono"
        local out_exe="$BINARIES_DIR/dotnet/mono/${basename}-mono.exe"
        write_metadata "$METADATA_DIR/${basename}-mono.json" "{
  \"source_file\": \"$source_file\",
  \"compiler\": \"mcs\",
  \"output_file\": \"$out_exe\",
  \"compilation_flags\": \"-optimize+\",
  \"description\": \"C# compiled with Mono mcs\",
  \"timestamp\": \"$(date -Iseconds)\",
  \"platform\": \"linux\",
  \"architecture\": \"$(uname -m)\"
}"
        if ! mcs -optimize+ -out:"$out_exe" "$source_file"; then
            warn "mcs failed"
        fi
    else
        warn "mcs (Mono) not found, skipping C#"
    fi
}

build_lua_variants() {
    local source_file="$1" basename
    basename="$(basename "$source_file" .lua)"
    ensure_dir "$BINARIES_DIR/lua"
    
    # Build with different Lua versions
    for lua_cmd in lua5.4 lua5.3 lua5.2 lua5.1 luajit; do
        if command -v $lua_cmd &> /dev/null; then
            local version=$($lua_cmd -v 2>&1 | head -1 | awk '{print $2}')
            local compiler="${lua_cmd}c"
            
            # LuaJIT uses different compiler name
            if [[ "$lua_cmd" == "luajit" ]]; then
                compiler="luajit -b"
            elif ! command -v $compiler &> /dev/null; then
                # Try without version suffix
                compiler="luac"
            fi
            
            local output_file="$BINARIES_DIR/lua/${basename}-${lua_cmd}.luac"
            log "Compiling Lua bytecode with $lua_cmd -> $output_file"
            
            write_metadata "$METADATA_DIR/${basename}-${lua_cmd}.json" "{
  \"source_file\": \"$source_file\",
  \"compiler\": \"$compiler\",
  \"lua_version\": \"$version\",
  \"output_file\": \"$output_file\",
  \"compilation_flags\": \"\",
  \"description\": \"Lua bytecode compiled with $lua_cmd\",
  \"timestamp\": \"$(date -Iseconds)\",
  \"platform\": \"linux\",
  \"architecture\": \"$(uname -m)\"
}"
            
            if [[ "$lua_cmd" == "luajit" ]]; then
                luajit -b "$source_file" "$output_file" 2>/dev/null || warn "LuaJIT compilation failed"
            else
                $compiler -o "$output_file" "$source_file" 2>/dev/null || warn "$compiler compilation failed"
            fi
        fi
    done
}

build_go_variants() {
    local source_file="$1" basename
    basename="$(basename "$source_file" .go)"
    
    if command -v go &> /dev/null; then
        ensure_dir "$BINARIES_DIR/go"
        
        # Standard build
        local output_file="$BINARIES_DIR/go/${basename}-go"
        log "Building Go binary -> $output_file"
        write_metadata "$METADATA_DIR/${basename}-go.json" "{
  \"source_file\": \"$source_file\",
  \"compiler\": \"go build\",
  \"go_version\": \"$(go version)\",
  \"output_file\": \"$output_file\",
  \"compilation_flags\": \"-ldflags='-s -w'\",
  \"description\": \"Go binary with stripped symbols\",
  \"timestamp\": \"$(date -Iseconds)\",
  \"platform\": \"linux\",
  \"architecture\": \"$(uname -m)\"
}"
        CGO_ENABLED=0 go build -ldflags="-s -w" -o "$output_file" "$source_file" || warn "Go build failed"
        
        # Static build with CGO disabled
        local static_output="$BINARIES_DIR/go/${basename}-go-static"
        log "Building static Go binary -> $static_output"
        write_metadata "$METADATA_DIR/${basename}-go-static.json" "{
  \"source_file\": \"$source_file\",
  \"compiler\": \"go build\",
  \"go_version\": \"$(go version)\",
  \"output_file\": \"$static_output\",
  \"compilation_flags\": \"CGO_ENABLED=0 GOOS=linux\",
  \"description\": \"Static Go binary without CGO\",
  \"timestamp\": \"$(date -Iseconds)\",
  \"platform\": \"linux\",
  \"architecture\": \"$(uname -m)\"
}"
        CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-s -w" -o "$static_output" "$source_file" || warn "Go static build failed"
        
        # Debug build
        local debug_output="$BINARIES_DIR/go/${basename}-go-debug"
        log "Building Go debug binary -> $debug_output"
        go build -gcflags="all=-N -l" -o "$debug_output" "$source_file" || warn "Go debug build failed"
    else
        warn "go not found, skipping Go"
    fi
}

build_rust_variants() {
    local source_file="$1" basename
    basename="$(basename "$source_file" .rs)"
    
    if command -v rustc &> /dev/null; then
        ensure_dir "$BINARIES_DIR/rust"
        
        # Debug build
        local debug_output="$BINARIES_DIR/rust/${basename}-rust-debug"
        log "Building Rust debug binary -> $debug_output"
        write_metadata "$METADATA_DIR/${basename}-rust-debug.json" "{
  \"source_file\": \"$source_file\",
  \"compiler\": \"rustc\",
  \"rust_version\": \"$(rustc --version)\",
  \"output_file\": \"$debug_output\",
  \"compilation_flags\": \"-g\",
  \"description\": \"Rust debug build\",
  \"timestamp\": \"$(date -Iseconds)\",
  \"platform\": \"linux\",
  \"architecture\": \"$(uname -m)\"
}"
        rustc -g -o "$debug_output" "$source_file" || warn "Rust debug build failed"
        
        # Release build
        local release_output="$BINARIES_DIR/rust/${basename}-rust-release"
        log "Building Rust release binary -> $release_output"
        write_metadata "$METADATA_DIR/${basename}-rust-release.json" "{
  \"source_file\": \"$source_file\",
  \"compiler\": \"rustc\",
  \"rust_version\": \"$(rustc --version)\",
  \"output_file\": \"$release_output\",
  \"compilation_flags\": \"-O\",
  \"description\": \"Rust optimized build\",
  \"timestamp\": \"$(date -Iseconds)\",
  \"platform\": \"linux\",
  \"architecture\": \"$(uname -m)\"
}"
        rustc -O -o "$release_output" "$source_file" || warn "Rust release build failed"
        
        # Static musl build
        if rustup target list | grep -q "x86_64-unknown-linux-musl (installed)"; then
            local musl_output="$BINARIES_DIR/rust/${basename}-rust-musl"
            log "Building Rust musl static binary -> $musl_output"
            rustc --target x86_64-unknown-linux-musl -O -o "$musl_output" "$source_file" || warn "Rust musl build failed"
        fi
    else
        warn "rustc not found, skipping Rust"
    fi
}

build_library_variants() {
    local source_dir="$SOURCE_DIR/library"
    if [[ ! -f "$source_dir/mathlib.c" ]]; then
        return
    fi
    
    ensure_dir "$BINARIES_DIR/libraries/shared"
    ensure_dir "$BINARIES_DIR/libraries/static"
    
    # Build shared library (.so)
    local so_file="$BINARIES_DIR/libraries/shared/libmathlib.so"
    log "Building shared library -> $so_file"
    gcc -shared -fPIC -O2 -o "$so_file" "$source_dir/mathlib.c" -lm || warn "Shared library build failed"
    write_metadata "$METADATA_DIR/libmathlib-so.json" "{
  \"source_file\": \"$source_dir/mathlib.c\",
  \"compiler\": \"gcc\",
  \"output_file\": \"$so_file\",
  \"compilation_flags\": \"-shared -fPIC -O2\",
  \"description\": \"Shared library (.so)\",
  \"timestamp\": \"$(date -Iseconds)\",
  \"platform\": \"linux\",
  \"architecture\": \"$(uname -m)\"
}"
    
    # Build static library (.a)
    local obj_file="/tmp/mathlib.o"
    local a_file="$BINARIES_DIR/libraries/static/libmathlib.a"
    log "Building static library -> $a_file"
    gcc -c -O2 -o "$obj_file" "$source_dir/mathlib.c" && \
    ar rcs "$a_file" "$obj_file" || warn "Static library build failed"
    rm -f "$obj_file"
    
    # Build Windows DLL (cross-compile)
    if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        local dll_file="$BINARIES_DIR/libraries/shared/mathlib.dll"
        log "Building Windows DLL -> $dll_file"
        x86_64-w64-mingw32-gcc -shared -DMATHLIB_EXPORTS -O2 -o "$dll_file" "$source_dir/mathlib.c" || warn "DLL build failed"
    fi
    
    # Build test executable using the library
    if [[ -f "$source_dir/test_mathlib.c" && -f "$so_file" ]]; then
        local test_exe="$BINARIES_DIR/libraries/test_mathlib"
        log "Building test executable -> $test_exe"
        gcc -O2 -o "$test_exe" "$source_dir/test_mathlib.c" -L"$BINARIES_DIR/libraries/shared" -lmathlib -Wl,-rpath='$ORIGIN' || warn "Test executable build failed"
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
    # Suspicious examples: Linux and Windows cross
    [ -f "$SOURCE_DIR/c/suspicious_linux.c" ] && build_native_variants "$SOURCE_DIR/c/suspicious_linux.c" c
    [ -f "$SOURCE_DIR/c/suspicious_win.c" ] && build_cross_variants "$SOURCE_DIR/c/suspicious_win.c" c

    # Build other languages
    [ -f "$SOURCE_DIR/fortran/hello.f90" ] && build_fortran_variants "$SOURCE_DIR/fortran/hello.f90"
    [ -f "$SOURCE_DIR/java/HelloWorld.java" ] && build_java_variants "$SOURCE_DIR/java/HelloWorld.java"
    [ -f "$SOURCE_DIR/python/hello.py" ] && build_python_variants "$SOURCE_DIR/python/hello.py"
    [ -f "$SOURCE_DIR/csharp/Hello.cs" ] && build_csharp_variants "$SOURCE_DIR/csharp/Hello.cs"
    
    # Build new language samples
    [ -f "$SOURCE_DIR/lua/hello.lua" ] && build_lua_variants "$SOURCE_DIR/lua/hello.lua"
    [ -f "$SOURCE_DIR/go/hello.go" ] && build_go_variants "$SOURCE_DIR/go/hello.go"
    [ -f "$SOURCE_DIR/rust/hello.rs" ] && build_rust_variants "$SOURCE_DIR/rust/hello.rs"
    
    # Build libraries
    build_library_variants

    # Build PE with TLS callback (MinGW) if source present
    if [ -f "$SOURCE_DIR/c/pe_tls.c" ] && command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        compile_binary "$SOURCE_DIR/c/pe_tls.c" x86_64-w64-mingw32-gcc "$BINARIES_DIR/cross/windows-x86_64" \
            "pe_tls_callbacks-x86_64-mingw.exe" "-O2 -Wall" "Windows PE with TLS callback (MinGW-w64)"
    fi

    log "Linux builds completed successfully"
}

main "$@"
