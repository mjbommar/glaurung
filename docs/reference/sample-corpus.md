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
