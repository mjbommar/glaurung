# COFF signature fixtures

The COFF half of `tests/fixtures/flirt/`. The ELF fixtures one directory up
prove a masked signature survives a relink; these prove the same thing for
Windows objects, and additionally that the *builder* reads COFF at all -- which
it did not until 2026-09-03. Before that change,
`glaurung.analysis.flirt_signatures_from_archive_path` returned `raw=0` for
every MinGW archive on the machine.

## What is here

| File | What it is |
|---|---|
| `mingw_crt_subset.a` | 27 unlinked MinGW CRT objects: exactly the `libmingwex.a` and `libmingw32.a` members that a MinGW `hello.exe` links, taken from the link map. Debug sections stripped. Yields **62** signatures. |
| `mingw_crt_three.msvc.lib` | Three of those same objects, rewritten by `llvm-lib` into the **MSVC archive layout** -- a first *and* a second linker member (both named `/`), then `//`. A GNU `.a` has one `/`. |
| `import_only.msvc.lib` | A library whose every member is a short-import record (`IMPORT_OBJECT_HDR_SIG2`), which is what a Windows SDK `.lib` for a pure DLL looks like. Generated from a fictional DLL name, so it contains no third-party bytes at all. The builder must return nothing from it rather than fail. |
| `hello_link_a.stripped.x86_64.pe` | `samples/source/c/hello.c` built with `x86_64-w64-mingw32-gcc -O2`, then `strip --strip-all`. |
| `hello_link_b.stripped.x86_64.pe` | The same source with three filler functions linked ahead of it and `-Wl,--image-base,0x180000000`, so every CRT function lands somewhere else. Stripped. |
| `hello_link_{a,b}.symbols.txt` | `nm -n` of the *unstripped* images: `<va> <name>`, text symbols only. The ground truth. |
| `build.sh` | Rebuilds all of the above. Run only when deliberately refreshing. |
| `LICENSE.mingw-w64.txt` | The mingw-w64 package's copyright notice, carried because several of its licences require it alongside a binary redistribution. |

## Why only the stripped images are committed

Naming functions in a binary with no symbol table is the library's entire job,
so the stripped image is the one the test needs. The unstripped pair is 266 KB
each and carries nothing the 7 KB symbol transcripts do not. The whole
directory is 188 KB.

## Provenance and licence

The objects inside `mingw_crt_subset.a` and `mingw_crt_three.msvc.lib`, and the
CRT code linked into the two PE images, come from **mingw-w64**, Ubuntu package
`mingw-w64-x86-64-dev` version `13.0.0-2ubuntu1` (source package `mingw-w64`),
compiled by `gcc-mingw-w64-x86-64-win32` `13.2.0-6ubuntu1+26.1`.

mingw-w64 is free software and redistributable under permissive terms. Several
of those terms (ZPL-2.1 clause 2, the David Gay `gdtoa` notice) require the
copyright notice to accompany a binary redistribution, so the package's full
notice is committed here verbatim as **`LICENSE.mingw-w64.txt`** -- a copy of
`/usr/share/doc/mingw-w64-common/copyright` from the exact package version
above. The members committed here fall under ZPL-2.1 (`mingw-w64-crt/*`), the
David Gay licence (`gdtoa/*`: `dmisc`, `gdtoa`, `gmisc`, `misc`) and the Keith
Marshall licence (`stdio/mingw_pformat`, `stdio/mingw_printf`); all three are
permissive with a notice requirement and none is copyleft.

No GPL-only runtime is included -- in particular **no `libgcc.a` member is
committed**, even though `libgcc.a` is one of the archives the change was
measured against. Nothing is lost by that: the only libgcc code a MinGW
`hello.exe` pulls is `_chkstk_ms` and the `__gcc_*_frame` pair, and none of
them clears the shipped `min_fixed_bytes` floor.

`hello.c` and the filler functions are this repository's own sources. **No
Microsoft-licensed bytes are committed**: `mingw_crt_three.msvc.lib` is the
MSVC *archive layout* written by LLVM's `llvm-lib` over mingw-w64 objects, not
an MSVC library, and `import_only.msvc.lib` describes a DLL that does not
exist.

## Recorded toolchain

Built 2026-09-03 on Ubuntu:

```
toolchain: x86_64-w64-mingw32-gcc (GCC) 13-win32
binutils:  GNU ar (GNU Binutils) 2.45.90.20260125
llvm-lib:  /usr/lib/llvm-21/bin/llvm-ar   (package: llvm 1:21.x)
headers:   mingw-w64-x86-64-dev 13.0.0-2ubuntu1
mingw_crt_subset.a                 217f5d6a36cc21feb990ca09c199ab1e98ab34d5a3701ff366287f04963f350e
mingw_crt_three.msvc.lib           4c7e84d7b913d7da78cb63f3db077c9e2080c8430f35f9f5a009c6a172fe51f6
import_only.msvc.lib               6afe786d24136cdf8f2923ca33326ff88e1c46b1db7e9aaab4dc16bfb2ace0fb
hello_link_a.stripped.x86_64.pe    9dbbcf76ec075f179ce3251f6e82227e27b0dcb8bfed4cb2d6694fdd8668c74d
hello_link_b.stripped.x86_64.pe    052f63b748919d55aedd1587a4699d138f7b7a3097e7b702d9a05142390cf36e
hello_link_a.symbols.txt           bb562dd733c33c099b89770c97e9fe7015eda6dd2fb3d2ef861b72876fbe9380
hello_link_b.symbols.txt           3f5ce3e618f6e59a6f3e4a9be4d6a4f6690e7e292a403566e82d6bc0c07d78bd
```

As with the ELF fixtures, the tests depend on the two images differing *in the
ways a relink differs*, not on these hashes, so a refresh that changes them is
fine as long as the measurement below still holds.

## What these fixtures measure

`tests/flirt_signature_matching.rs` and `src/flirt/archive.rs`, 2026-09-03:

| Measurement | Result |
|---|---|
| Signatures from `mingw_crt_subset.a` (before the COFF change: 0) | **62** |
| Named in link A / link B by that library | **62 / 62** |
| Named in **both** links, at a **different** address in the two | **62 of 62** |
| Wrong names, against the `nm` truth | **0** |
| Named in both links with `mask_hex` and the CRC stripped | **37** -- the exact-byte matcher's ceiling |
| Signatures from the same three objects in the MSVC layout vs the GNU one | identical |
| Signatures from `import_only.msvc.lib` | **0**, and no error |
