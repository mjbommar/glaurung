# Sample corpus

> **Kind:** reference · **Status:** maintained

The repository ships real binary fixtures so tutorials and regression tests do
not depend on external downloads. This page is a curated map of representative
inputs, not a frozen inventory or a claim that every platform contains every
variant.

For the tree layout, rebuild policy, and inventory-generation caveats, read the
top-level [`samples/README.md`](../../samples/README.md). Resolve a path
against the current checkout before using it in a test or document.

<!-- Fixture paths in the mapping tables are intentionally unwrapped. -->
<!-- markdownlint-disable MD013 -->

## Native ELF learning ladder

| Path | Good for |
| --- | --- |
| `samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug` | First-binary walkthrough with debug-rich native code. |
| `samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug` | Small C project used by the CLI and REPL tours. |
| `samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-c-gcc-O2` | Optimized C idioms and benchmark coverage. |
| `samples/binaries/platforms/linux/amd64/export/native/clang/O2/hello-c-clang-O2` | Comparing compiler-specific optimized output. |
| `samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-cpp-g++-O2` | C++ symbol and optimization behavior. |
| `samples/binaries/platforms/linux/amd64/synthetic/poly-cpp-virtual` | Vtables and RTTI with symbols. |
| `samples/binaries/platforms/linux/amd64/synthetic/poly-cpp-virtual-stripped` | The corresponding stripped C++ recovery case. |

Start with [§B — First binary](../tutorial/01-getting-started/first-binary.md), then use
[the native C walkthrough](../tutorial/03-walkthroughs/01-hello-c-clang.md).

## Language and managed-runtime fixtures

| Path | Good for |
| --- | --- |
| `samples/binaries/platforms/linux/amd64/export/fortran/hello-gfortran-O2` | Fortran runtime and language-detection behavior. |
| `samples/binaries/platforms/linux/amd64/export/rust/hello-rust-release` | Optimized Rust code. |
| `samples/binaries/platforms/linux/amd64/export/rust/hello-rust-debug` | Debug Rust comparison. |
| `samples/binaries/platforms/linux/amd64/export/go/hello-go` | Stripped Go metadata and function-name recovery. |
| `samples/binaries/platforms/linux/amd64/export/go/hello-go-debug` | Unoptimized/debug Go comparison. |
| `samples/binaries/platforms/linux/amd64/export/dotnet/mono/Hello-mono.exe` | Managed .NET metadata inside a PE. |
| `samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class` | JVM classfile parsing. |
| `samples/binaries/platforms/linux/amd64/export/java/HelloWorld.jar` | JVM archive traversal. |
| `samples/binaries/platforms/linux/amd64/export/lua/hello-lua5.3.luac` | Lua 5.3 bytecode recognition. |
| `samples/binaries/platforms/linux/amd64/export/lua/hello-luajit.luac` | LuaJIT header/layout differences. |

Use the [stripped-Go](../tutorial/03-walkthroughs/02-stripped-go-binary.md),
[managed-.NET](../tutorial/03-walkthroughs/03-managed-dotnet-pe.md), and
[JVM](../tutorial/03-walkthroughs/04-jvm-classfile.md) walkthroughs. Recovered function
counts are analyzer results and can change; the tutorial verifier captures the
current output instead of freezing a count here.

## Cross-architecture and Windows fixtures

| Path | Good for |
| --- | --- |
| `samples/binaries/platforms/linux/amd64/export/cross/arm64/hello-arm64-gcc` | AArch64 ELF triage and analysis. |
| `samples/binaries/platforms/linux/amd64/export/cross/riscv64/hello-riscv64-gcc` | RISC-V coverage and current capability boundaries. |
| `samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/hello-c-x86_64-mingw.exe` | Native x86-64 PE and Windows ABI behavior. |
| `samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/suspicious_win-c-x86_64-mingw.exe` | Windows API and risk-summary workflows. |

Do not infer equal feature depth across formats or architectures. Begin with
`triage`, inspect the command-specific help, and keep unsupported or partial
analysis explicit.

## Security-oriented walkthrough fixtures

| Path | Good for |
| --- | --- |
| `samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0` | Malware-style strings, imports, and analyst workflow. |
| `samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/c2_demo-c-x86_64-mingw.exe` | The same source shape compiled as a Windows PE. |
| `samples/binaries/platforms/linux/amd64/synthetic/vulnparse-c-gcc-O0` | Vulnerability-hunting walkthrough on a deliberately unsafe parser. |
| `samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2` | Baseline for function-level binary diffing. |
| `samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2` | Modified sibling for the diff recipe. |

The `vulnparse` and `switchy` fixtures live under `synthetic/`; older exported
paths are not present in the current checkout. See the
[vulnerable-parser](../tutorial/03-walkthroughs/05-vulnerable-parser.md),
[C2](../tutorial/03-walkthroughs/07-malware-c2-demo.md), and
[binary-diff](../tutorial/04-recipes/diffing-two-binaries.md) chapters.

## Packed corpus

`samples/packed/` contains checked-in UPX variants across Fortran, Go, and
Rust. Use a specific path such as:

```bash
uv run glaurung detect-packer samples/packed/hello-go.upx9
```

Packer confidence and entropy are measured outputs, not permanent constants.
The [UPX walkthrough](../tutorial/03-walkthroughs/06-upx-packed-binary.md) and packed
benchmark recipe verify the current behavior.

## Adversarial inputs

`samples/adversarial/` contains bounded malformed files and nested-container
fixtures used to verify error handling. Representative inputs include:

```text
samples/adversarial/elf_truncated_phdr.bin
samples/adversarial/magic_dope_mz_elf.bin
samples/adversarial/pe_bad_optional_header.bin
samples/adversarial/zip_masquerade_exe.exe
samples/adversarial/gzip_truncated.gz
samples/adversarial/embedded/xor_url_in_elf.elf
```

They are parser test fixtures, not arbitrary untrusted corpora. Run their
focused coverage with:

```bash
uv run pytest python/tests/test_adversarial_coverage.py
```

See [`samples/adversarial/README.md`](../../samples/adversarial/README.md)
for the intended invariants.

## System archives

Everything above is a **linked** image. A linked image is the wrong input for a
signature library, and the reason is not a detail: the linker has already
resolved every `call rel32` and every RIP-relative displacement to a value it
chose for that one link, and it kept no record of which bytes those were. Only
a relocatable `.o` carries the relocation table that says which bytes get
rewritten, and masking exactly those is what makes a signature survive a
relink. See
[FLIRT-style signature libraries](function-signature-libraries.md) for the
measurement behind that sentence.

So the input to `python -m glaurung.tools.build_flirt_library --archive` is not
this corpus. It is the distribution's own static archives -- `libc.a`,
`libstdc++.a`, `libssl.a`, the MinGW-w64 CRT -- which live inside the
`samples/docker` build images along with the `dpkg` database that says where
each one came from. `samples/docker/harvest_system_archives.py` exports them
with that provenance attached.

### What is harvested

An allowlist of archive **basenames**, not every `.a` under `/usr/lib`: the
images also carry LLVM, OpenJDK and Mono archives that no analyst wants named,
and MinGW-w64 ships several hundred *import* libraries (`libkernel32.a` and
siblings) that contain no code at all. The list is `ARCHIVE_NAMES` in the
script, in four groups:

- **libc**: `libc.a`, `libm.a`, `libpthread.a`, `librt.a`, `libdl.a`,
  `libcrypt.a`, `libresolv.a`, `libutil.a`, `libanl.a`, `libnsl.a`,
  `libBrokenLocale.a`, `libc_nonshared.a`, `libg.a`, `libmcheck.a`, `libmvec.a`
  -- glibc and musl alike.
- **gcc and language runtimes**: `libstdc++.a`, `libstdc++fs.a`, `libsupc++.a`,
  `libgcc.a`, `libgcc_eh.a`, `libgcov.a`, `libatomic.a`, `libitm.a`,
  `libquadmath.a`, `libgfortran.a`, `libcaf_single.a`, `libssp.a`,
  `libssp_nonshared.a`, and the four sanitizer runtimes.
- **`-dev` packages**: zlib, OpenSSL (`libssl.a` and `libcrypto.a`), bzip2,
  lzma, zstd, SQLite, PCRE2, libxml2, curl, libffi, GMP.
- **MinGW-w64 CRT**: `libmingw32.a`, `libmingwex.a`, `libmsvcrt.a`,
  `libmoldname.a`, `libucrt.a`, `libucrtbase.a`, `libwinpthread.a`,
  `libdelayimp.a`, plus the MinGW `libgcc.a` and `libstdc++.a`.

Search roots are globbed rather than hardcoded, so one script serves every
image: `/usr/lib/<triplet>`, `/usr/lib32`, `/usr/libx32`,
`/usr/lib/gcc/*/*` (and its `32`/`x32` multilib subdirectories),
`/usr/lib/gcc-cross/*/*`, and `/usr/<triplet>/lib`. A multilib subdirectory is
filed under the ABI it actually holds, so
`/usr/lib/gcc/x86_64-linux-gnu/11/32/libstdc++.a` is `i386-linux-gnu` and not a
32-bit file recorded as `x86_64`.

Two files named like archives are not archives, and both were found by running
the harvest rather than by reading about them. glibc ships
`/usr/lib/<triplet>/libm.a` as a **GNU ld script** reading
`GROUP ( libm-2.35.a libmvec.a )`; `libmcheck.a` is a single ELF relocatable
object. `resolve_archive` follows the script to the versioned archives it names
-- without that, libm is missing from every triplet, because no allowlist of
unversioned basenames can reach `libm-2.35.a` -- and skips the bare object,
which the builder can only reject. An archive reached through a script records
the script's path in `resolved_from`.

`linux/Dockerfile.amd64` installs `libc6-dev-{arm64,armhf,riscv64,i386}-cross`,
so that one image exports every triplet's `libc.a` and no emulated build is
needed to get cross-architecture coverage.

### Running it

The step is **off by default**. A plain image build produces exactly the
`export/` tree it produced before; nothing under
`samples/binaries/platforms/` changes.

```bash
docker build --target base -t glaurung-harvest-linux-amd64 \
  -f samples/docker/linux/Dockerfile.amd64 samples/
docker run --rm -v "$HOME/.cache/glaurung/system-libs/linux-amd64:/out" \
  glaurung-harvest-linux-amd64 \
  /usr/local/bin/build-platform.sh --harvest-only /out
```

`HARVEST_SYSTEM_ARCHIVES=1` in the environment makes a full
`build-platform.sh` run do the harvest as well, into
`$BINARIES_DIR/system-libs/`. With rootless Docker, container root maps to the
invoking host uid, so do **not** pass `--user`: it maps to a subuid that cannot
write the bind mount.

Then index the images and build a library per archive:

```bash
uv run python samples/docker/harvest_system_archives.py \
  --index-root "$HOME/.cache/glaurung/system-libs"
uv run python tools/build_signature_set.py \
  --harvest-root "$HOME/.cache/glaurung/system-libs" \
  --output "$HOME/.cache/glaurung/system-libs/sigs"
```

### Manifest schema

One `manifest.json` per triplet, plus an `index.json` per image and one over
all images. Every file is written with sorted keys, two-space indent and a
trailing newline, so re-harvesting an unchanged image diffs to nothing.

```jsonc
{
  "schema_version": "1",
  "generated_utc": "2026-09-03T12:34:56Z",
  "triplet": "x86_64-linux-gnu",
  "arch": "x86_64",                       // the --arch tag a library is keyed by
  "image": {
    "name": "linux-amd64", "base": "ubuntu:22.04",
    "os_id": "ubuntu", "os_version_id": "22.04",
    "target_os": "linux", "target_arch": "amd64",
    "dpkg_architecture": "amd64", "uname_machine": "x86_64"
  },
  "compiler": {                           // the image driver targeting this triplet
    "driver": "x86_64-linux-gnu-gcc",
    "path": "/usr/bin/x86_64-linux-gnu-gcc",
    "version": "x86_64-linux-gnu-gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0",
    "package": "gcc-11", "package_version": "11.4.0-1ubuntu1~22.04.3"
  },
  "compiler_note": "...",
  "archives": [{
    "name": "libc.a",
    "relative_path": "lib/libc.a",
    "source_path": "/usr/lib/x86_64-linux-gnu/libc.a",
    "resolved_from": "",                  // set when a GNU ld script named it
    "size": 6028194,
    "sha256": "163c936ba8f41ddfb3ca64c9d372fec2150b12d5891e62d41094b71e50335e7d",
    "package": "libc6-dev",
    "package_version": "2.35-0ubuntu3.14",
    "package_architecture": "amd64",
    "triplet": "x86_64-linux-gnu", "arch": "x86_64",
    "compiler": "x86_64-linux-gnu-gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0",
    "compiler_driver": "x86_64-linux-gnu-gcc"
  }],
  "totals": {"archives": 46, "bytes": 56545940}
}
```

`compiler` is the image's driver for the triplet. It **is** the builder for a
gcc-owned archive; for a distribution `-dev` archive `dpkg` records the package
version but not the compiler that produced it, so the manifest reports the two
side by side and never conflates them. That is what `compiler_note` says in the
file itself.

`python/tests/test_system_archive_harvest.py` validates real manifests
(committed under `python/tests/fixtures/system_libs/`, provenance only, no
archive bytes) against this schema and checks the index is canonical.

### Licence

**The archives are not redistributed.** They are Debian and Ubuntu packages
under their own licences -- glibc under LGPL-2.1+, libstdc++ under GPL-3 with
the runtime exception, OpenSSL under Apache-2.0, and so on -- and nothing in
this harvest is checked in. It writes to a cache directory you name.

What may be redistributed is the derived signature file, and the reason is
structural rather than a judgement call: a FLIRT signature splits a pattern
from a mask, and the masked-out bytes are never compared, so a signature file
carries no reproducible copy of the library's code. What it carries is a
32-byte window with the relocated bytes blanked, a CRC-16 of the following
bytes, a length, and **names** -- which is exactly the information IDA's own
`.sig` files have been distributed as since 1996. Treat the names as the
licensed content and attribute them: every entry in the index below records the
package and version it came from.

### Measured

First real run, 2026-09-03, on this repository's own hardware. Three images
were built with `docker build --target base` and harvested with
`build-platform.sh --harvest-only`. The `linux/arm64` image was built and run
under qemu-user emulation, which is why its build and harvest are slower; the
archives it exports are native aarch64 packages either way.

| Image | Base | Cold build | Harvest |
| --- | --- | ---: | ---: |
| `linux-amd64` | `ubuntu:22.04` | 316 s | 1 s |
| `windows-amd64` | `ubuntu:22.04` | 295 s | under 1 s |
| `linux-arm64` | `arm64v8/ubuntu:22.04`, qemu-user | 551 s | 29 s |

Cold build is the first build, dominated by `apt-get`. Changing only the
harvester and rebuilding takes **1 second** per image: it invalidates one
`COPY` layer, so the harvest is cheap to iterate on once the images exist.

**The harvest is reproducible.** Two consecutive harvests of the same
`linux-amd64` image produced byte-identical output in all 9 JSON files apart
from `generated_utc`.

Signatures were built with
`uv run python tools/build_signature_set.py`, one
`build_flirt_library --archive` subprocess per archive, against a
`maturin develop --release` extension. Nineteen `(image, triplet)` pairs over
**11 distinct triplets** and **37 distinct packages**:

**Re-measured 2026-09-03 against `5e2e0c68`** (the `identity-integration` /
`siglib/docker-archive-harvest` merge, which carries `5e882019`, "flirt:
build signatures from COFF archives"). Same harvested archives, same
allowlist, same `maturin develop --release` build discipline -- only the
extension changed. This replaces the table below it, which was built from
`935b7db1` (pre-COFF) and had every MinGW-w64 row at zero.

| Image | Triplet | Arch | Archives | Archive bytes | Packages | Libraries with signatures | Raw | Unique | Dropped ambiguous | Signature bytes |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `linux-amd64` | `aarch64-linux-gnu` | aarch64 | 24 | 22.3 MB | 3 | 16 | 14527 | 8391 | 732 | 11.2 MB |
| `linux-amd64` | `arm-linux-gnueabihf` | arm | 21 | 14.2 MB | 3 | 14 | 14237 | 7865 | 700 | 10.8 MB |
| `linux-amd64` | `i686-linux-gnu` | i386 | 11 | 7.0 MB | 1 | 5 | 6215 | 3341 | 230 | 3.9 MB |
| `linux-amd64` | `i686-w64-mingw32` | i386 | 20 | 19.3 MB | 3 | 16 | 6158 | 3592 | 395 | 4.0 MB |
| `linux-amd64` | `riscv64-linux-gnu` | riscv64 | 20 | 68.1 MB | 3 | 11 | 7917 | 4241 | 386 | 16.1 MB |
| `linux-amd64` | `x86_64-linux-gnu` | x86_64 | 46 | 56.5 MB | 17 | 38 | 39041 | 26678 | 1840 | 32.3 MB |
| `linux-amd64` | `x86_64-linux-musl` | x86_64 | 7 | 2.6 MB | 1 | 1 | 1644 | 1325 | 41 | 1.0 MB |
| `linux-amd64` | `x86_64-w64-mingw32` | x86_64 | 20 | 20.7 MB | 3 | 16 | 6035 | 3554 | 367 | 3.9 MB |
| `linux-arm64` | `aarch64-linux-gnu` | aarch64 | 44 | 47.8 MB | 17 | 36 | 32624 | 22974 | 1526 | 27.2 MB |
| `linux-arm64` | `aarch64-linux-musl` | aarch64 | 7 | 2.4 MB | 1 | 1 | 1560 | 1228 | 41 | 1.0 MB |
| `linux-arm64` | `arm-linux-gnueabihf` | arm | 21 | 14.2 MB | 3 | 14 | 14237 | 7865 | 700 | 10.8 MB |
| `linux-arm64` | `i686-w64-mingw32` | i386 | 20 | 19.3 MB | 3 | 16 | 6158 | 3592 | 395 | 4.0 MB |
| `linux-arm64` | `riscv64-linux-gnu` | riscv64 | 20 | 68.1 MB | 3 | 11 | 7917 | 4241 | 386 | 16.1 MB |
| `linux-arm64` | `x86_64-linux-gnu` | x86_64 | 25 | 26.3 MB | 3 | 17 | 17860 | 10143 | 947 | 13.5 MB |
| `linux-arm64` | `x86_64-w64-mingw32` | x86_64 | 20 | 20.7 MB | 3 | 16 | 6035 | 3554 | 367 | 3.9 MB |
| `windows-amd64` | `i686-w64-mingw32` | i386 | 20 | 19.3 MB | 3 | 16 | 6158 | 3592 | 395 | 4.0 MB |
| `windows-amd64` | `x86_64-linux-gnu` | x86_64 | 46 | 56.5 MB | 17 | 38 | 39041 | 26678 | 1840 | 32.3 MB |
| `windows-amd64` | `x86_64-linux-musl` | x86_64 | 7 | 2.6 MB | 1 | 1 | 1644 | 1325 | 41 | 1.0 MB |
| `windows-amd64` | `x86_64-w64-mingw32` | x86_64 | 20 | 20.7 MB | 3 | 16 | 6035 | 3554 | 367 | 3.9 MB |
| **total** | 19 rows, 11 distinct | | **419** | **508.6 MB** | 37 | **299** | **235043** | **147733** | **11696** | **201.0 MB** |

Full re-run: `uv run python tools/build_signature_set.py` over all 419 rows
took **39.5 s** (0 failures). **299 of 419 archives
now produce at least one signature** (up from 203), all 120 of them the
MinGW-w64 rows. The nine non-MinGW `(image, triplet)` groups also moved by a
handful of signatures each (+1 to +27 raw per group): `archive.rs`'s
size-derivation fix is not COFF-specific -- "extent = next symbol in the
section, or the section end" applies to *any* format that reports
`size() == 0`, and a few ELF assembly symbols with no `.size` directive newly
qualify. The two `libc.a`/`libmathlib.a` A/B controls in
[FLIRT-style signature libraries](function-signature-libraries.md) already
established those ELF paths are otherwise untouched (zero-line diff on the
shipped library and the `libmathlib.a` control); this is that same effect
showing up at corpus scale on symbols the earlier, targeted A/B did not happen
to include.

The twelve largest libraries, deduplicated on `(archive, package, version,
arch)` -- 245 of the 419 rows are distinct under that key, the rest being the
same package harvested from two images. Ranked by unique signatures; no
MinGW-w64 library reaches this list (`libstdc++.a` under
`g++-mingw-w64-i686-posix` tops out at 1,843 unique, below `libxml2.a`'s
2,085):

| Archive | Package | Version | Arch | Archive bytes | Raw | Unique | Dropped ambiguous | Build s |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| `libcrypto.a` | `libssl-dev` | `3.0.2-0ubuntu1.29` | x86_64 | 9113168 | 8264 | 6042 | 435 | 0.26 |
| `libcrypto.a` | `libssl-dev` | `3.0.2-0ubuntu1.29` | aarch64 | 9102826 | 7398 | 5276 | 417 | 0.28 |
| `libc.a` | `libc6-dev-i386-cross` | `2.35-0ubuntu1cross3` | i386 | 5027870 | 4571 | 2726 | 177 | 0.15 |
| `libc.a` | `libc6-dev` | `2.35-0ubuntu3.14` | x86_64 | 6028194 | 4127 | 2563 | 101 | 0.14 |
| `libc.a` | `libc6-dev-amd64-cross` | `2.35-0ubuntu1cross3` | x86_64 | 6007420 | 4124 | 2560 | 101 | 0.12 |
| `libc.a` | `libc6-dev-armhf-cross` | `2.35-0ubuntu1cross3` | arm | 3334034 | 3896 | 2440 | 114 | 0.33 |
| `libsqlite3.a` | `libsqlite3-dev` | `3.37.2-2ubuntu0.7` | x86_64 | 2297592 | 2338 | 2269 | 28 | 0.12 |
| `libc.a` | `libc6-dev` | `2.35-0ubuntu3.14` | aarch64 | 4983048 | 3720 | 2265 | 98 | 0.11 |
| `libsqlite3.a` | `libsqlite3-dev` | `3.37.2-2ubuntu0.7` | aarch64 | 2287672 | 2313 | 2233 | 32 | 0.15 |
| `libc.a` | `libc6-dev-arm64-cross` | `2.35-0ubuntu1cross3` | aarch64 | 4939918 | 3662 | 2223 | 97 | 0.16 |
| `libxml2.a` | `libxml2-dev` | `2.9.13+dfsg-1ubuntu0.12` | x86_64 | 2847428 | 2350 | 2163 | 63 | 0.28 |
| `libxml2.a` | `libxml2-dev` | `2.9.13+dfsg-1ubuntu0.12` | aarch64 | 2870708 | 2243 | 2085 | 54 | 0.19 |

The 120 MinGW-w64 rows, by triplet (six `(image, triplet)` groups, since each
of the three images exports both `i686-w64-mingw32` and `x86_64-w64-mingw32`,
and `i686-w64-mingw32`/`x86_64-w64-mingw32` are identical archives across the
three images so their per-triplet totals repeat):

| Triplet | Archives | Libraries with signatures | Raw | Unique | Dropped ambiguous | Signature bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `i686-w64-mingw32` (each image) | 20 | 16 | 6158 | 3592 | 395 | 4.0 MB |
| `x86_64-w64-mingw32` (each image) | 20 | 16 | 6035 | 3554 | 367 | 3.9 MB |

The same four archives are empty in both `i686-w64-mingw32` and
`x86_64-w64-mingw32`: `libdelayimp.a` (8 bytes -- an empty archive, no
members), `libm.a`, `libmoldname.a` and `libssp_nonshared.a` (800-1,462 bytes
each -- import-alias archives with no function-carrying object inside). "16
of 20" above is the ceiling for this allowlist, not a shortfall, matching the
`import_only.msvc.lib` fixture's zero row in
[FLIRT-style signature libraries](function-signature-libraries.md).

Two smaller things the first run found, both now fixed in the harvester:

- glibc's `/usr/lib/<triplet>/libm.a` is a **GNU ld script** reading
  `GROUP ( libm-2.35.a libmvec.a )`, not an archive. Taking the name at face
  value lost libm from every triplet. `resolve_archive` follows the script.
- `libmcheck.a` is a single ELF relocatable wearing an archive's name. It is
  skipped rather than handed to a builder that can only report
  `not an ar archive`.

The archives and the signature files live under
`$HOME/.cache/glaurung/system-libs/`; nothing here is checked in except the
manifests used as test fixtures.

## Benchmark matrices

The canonical matrix definitions live in
[`python/glaurung/bench/__main__.py`](../../python/glaurung/bench/__main__.py).
Query the current runner rather than copying its list into automation:

```bash
uv run python -m glaurung.bench --help
```

The default matrix is deliberately small and spans native C/C++, Fortran,
debug/stripped comparisons, and polymorphic C++. A separate packed matrix uses
the UPX fixtures.

## Exact inventory and metadata

The checked-in `samples/binaries/index.json` is a generated snapshot with paths,
sizes, hashes, file-type output, and generation provenance. Its absolute `root`
and `host` describe the machine that generated it; they are not paths that must
exist on your system. Because a snapshot can lag the filesystem, verify both:

```bash
test -f samples/binaries/platforms/linux/amd64/export/go/hello-go
uv run python -c \
  'import json; d=json.load(open("samples/binaries/index.json")); print(len(d["files"]))'
```

Do not regenerate the index just to inspect it: the indexer rewrites the file.
Follow the intentional regeneration workflow in
[`samples/README.md`](../../samples/README.md).

See also the [CLI cheatsheet](cli.md) and
[`set_by` precedence](provenance.md).
