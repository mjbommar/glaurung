#!/usr/bin/env bash
# Build the COFF fixtures that prove the archive signature builder works on
# MinGW-w64 `.a` and MSVC-format `.lib` input.
#
# Like the ELF relink fixture one directory up, the OUTPUTS ARE COMMITTED. The
# tests must run on a machine with no MinGW cross-compiler, and the two linked
# images must not silently change identity when someone's toolchain is
# upgraded. Re-run this only when deliberately refreshing the fixture, and
# record the new toolchain and hashes in README.md.
#
# Requires: mingw-w64-x86-64-dev, gcc-mingw-w64-x86-64-win32, binutils-mingw-w64,
# and llvm-lib / llvm-dlltool (Debian/Ubuntu: llvm).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mingwex=/usr/x86_64-w64-mingw32/lib/libmingwex.a
mingw32=/usr/x86_64-w64-mingw32/lib/libmingw32.a

# ---------------------------------------------------------------------------
# 1. The archive fixture: exactly the members a MinGW `hello.exe` links.
#
# Taken from the link map of `x86_64-w64-mingw32-gcc -O2 hello.c`, so every
# function the fixture signs is a function that is actually present in the two
# committed images -- which is what makes "62 of 62 named in both links" a
# measurement rather than a coincidence. Debug sections are stripped from the
# members: they are 60% of the bytes and the builder reads neither.
# ---------------------------------------------------------------------------
mingwex_members=(dmisc gdtoa gmisc mingw_matherr mingw_pformat mingw_printf misc)
mingw32_members=(cinitexe CRT_fp10 crt_handler dllargv gccmain merr mingw_helpers
                 natstart _newmode pesect pseudo-reloc-list pseudo-reloc tlsmcrt
                 tlssup tlsthrd usermatherr wildcard xncommod xthdloc xtxtmode)

mkdir -p "$work/sub"
(
    cd "$work/sub"
    for m in "${mingwex_members[@]}"; do
        x86_64-w64-mingw32-ar x "$mingwex" "lib64_libmingwex_a-$m.o"
    done
    for m in "${mingw32_members[@]}"; do
        x86_64-w64-mingw32-ar x "$mingw32" "lib64_libmingw32_a-$m.o"
    done
    x86_64-w64-mingw32-strip --strip-debug ./*.o
)
rm -f "$here/mingw_crt_subset.a"
# `D` = deterministic: zero timestamps, uid and gid in the member headers.
x86_64-w64-mingw32-ar rcsD "$here/mingw_crt_subset.a" "$work"/sub/*.o

# ---------------------------------------------------------------------------
# 2. The same objects, three of them, in the MSVC archive layout.
#
# An MSVC `.lib` differs from a GNU `.a` in its header members, not in its
# objects: it carries a FIRST and a SECOND linker member (both named `/`) and
# then the `//` longnames member, where GNU has one `/` and one `//`. That is
# the part the reader has to get right, so the fixture is small on purpose --
# the objects are already covered by the archive above.
# ---------------------------------------------------------------------------
rm -f "$here/mingw_crt_three.msvc.lib"
llvm-lib "/OUT:$here/mingw_crt_three.msvc.lib" \
    "$work/sub/lib64_libmingw32_a-pesect.o" \
    "$work/sub/lib64_libmingw32_a-merr.o" \
    "$work/sub/lib64_libmingwex_a-gmisc.o"

# ---------------------------------------------------------------------------
# 3. An import-only library: every member is a short-import record
#    (`IMPORT_OBJECT_HDR_SIG2`), no COFF object anywhere in the file. This is
#    what a Windows SDK `.lib` for a pure DLL looks like, and the builder must
#    return nothing from it rather than fail. Generated from a fictional DLL
#    name, so it carries no third-party bytes at all.
# ---------------------------------------------------------------------------
cat > "$work/import_only.def" <<'DEF'
LIBRARY FICTIONALDEMO.DLL
EXPORTS
DemoAlpha
DemoBeta
DemoGamma
DEF
rm -f "$here/import_only.msvc.lib"
llvm-dlltool -m i386:x86-64 -d "$work/import_only.def" -l "$here/import_only.msvc.lib"

# ---------------------------------------------------------------------------
# 4. Two PE images of the same source, linked two different ways.
#
# Link B puts three extra functions ahead of `main` and moves the image base,
# so every CRT function the linker copied out of the archive lands at a
# different address with different resolved displacements. That is the
# condition an exact-byte signature cannot survive and a relocation-masked one
# must.
# ---------------------------------------------------------------------------
cat > "$work/hello_extra.c" <<'EOF'
/* Filler ahead of main in link B, so the CRT lands somewhere else. */
int filler_one(int a) { return a * 3 + 1; }
int filler_two(int a) { return filler_one(a) ^ 0x5a; }
int filler_three(int a) { return filler_two(a) + filler_one(a); }
EOF

x86_64-w64-mingw32-gcc -O2 -o "$work/a.exe" "$repo/samples/source/c/hello.c"
x86_64-w64-mingw32-gcc -O2 -o "$work/b.exe" \
    "$work/hello_extra.c" "$repo/samples/source/c/hello.c" \
    -Wl,--image-base,0x180000000

# The truth tables come from the UNSTRIPPED images; only the stripped ones are
# committed, because naming functions in a binary with no symbol table is the
# library's whole job and 220 KB of duplicate CRT bytes is not worth carrying.
for side in a b; do
    x86_64-w64-mingw32-nm -n "$work/$side.exe" \
        | awk '$2 == "T" || $2 == "t" { print $1, $3 }' \
        > "$here/hello_link_$side.symbols.txt"
    cp "$work/$side.exe" "$here/hello_link_$side.stripped.x86_64.pe"
    x86_64-w64-mingw32-strip --strip-all "$here/hello_link_$side.stripped.x86_64.pe"
done

echo "toolchain: $(x86_64-w64-mingw32-gcc --version | head -1)"
echo "binutils:  $(x86_64-w64-mingw32-ar --version | head -1)"
echo "llvm-lib:  $(readlink -f "$(command -v llvm-lib)")"
echo "headers:   mingw-w64-x86-64-dev $(dpkg-query -W -f='${Version}' mingw-w64-x86-64-dev 2>/dev/null)"
for f in mingw_crt_subset.a mingw_crt_three.msvc.lib import_only.msvc.lib \
         hello_link_a.stripped.x86_64.pe hello_link_b.stripped.x86_64.pe \
         hello_link_a.symbols.txt hello_link_b.symbols.txt; do
    echo "$f $(sha256sum "$here/$f" | cut -d' ' -f1)"
done
