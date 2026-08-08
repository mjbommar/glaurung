# Glaurung sample corpus

The `samples/` tree contains source programs and checked-in binaries used by
the tutorials, tests, demonstrations, and regression tooling. You do not need
to rebuild the corpus to learn or use Glaurung.

## Run a sample now

From the repository root, after the supported source install:

```bash
SAMPLE=samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2

uv run glaurung triage "$SAMPLE"
uv run glaurung kickoff "$SAMPLE"
uv run glaurung decompile "$SAMPLE" --func main --style c
```

The [first-binary tutorial](../docs/tutorial/01-getting-started/first-binary.md)
explains the output and shows how to retain analysis in a `.glaurung` project.
The [sample-corpus reference](../docs/tutorial/reference/sample-corpus.md) maps
tutorial chapters to their fixtures.

## What is in this tree

```text
samples/
├── source/                     source programs by language
├── binaries/
│   ├── platforms/              checked-in platform and architecture builds
│   ├── metadata/               build metadata
│   └── index.json              generated file inventory
├── adversarial/                malformed and edge-case fixtures
├── packed/                     checked-in UPX examples
├── containers/                 archive and compression examples
├── docker/                     platform Dockerfiles and build helpers
├── build-multiplatform.sh      Docker image build orchestrator
├── build-packed.sh             regenerate UPX samples from existing binaries
├── build-compressed.sh         regenerate archive/compression samples
└── docker-compose.yml          optional platform build services
```

The main exported corpus follows this shape:

```text
samples/binaries/platforms/<os>/<arch>/export/
├── native/        native C, C++, and assembly variants
├── cross/         cross-compiled ARM, RISC-V, and Windows variants
├── fortran/       Fortran binaries
├── go/            Go binaries
├── java/          JVM class files and JARs
├── dotnet/        managed .NET/Mono assemblies
├── lua/           Lua bytecode
├── rust/          Rust binaries
├── libraries/     shared and static libraries
└── metadata/      per-artifact build records
```

Not every platform export has every directory. Availability depends on the
toolchains used when that checked-in platform corpus was produced.

## Representative checked-in artifacts

- Small optimized x86-64 ELF:
  `samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2`
- Debug-symbol x86-64 ELF:
  `samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug`
- Stripped x86-64 ELF:
  `samples/binaries/platforms/linux/amd64/export/native/gcc/debug/hello-gcc-stripped`
- Go executable:
  `samples/binaries/platforms/linux/amd64/export/go/hello-go`
- Java class file:
  `samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class`
- Mono PE assembly:
  `samples/binaries/platforms/linux/amd64/export/dotnet/mono/Hello-mono.exe`
- Native Windows PE:
  `samples/binaries/platforms/windows/amd64/export/windows/x86_64/O2/hello-c-mingw64-O2.exe`
- UPX-packed executable: `samples/packed/hello-go.upx9`

Use `find` or the checked-in `samples/binaries/index.json` when you need an
exact inventory. The index contains paths, sizes, SHA-256 digests, file-type
output, and a snapshot of the tool versions that generated it. The host and
absolute root fields are provenance from that generation run, not required
paths on your machine.

## Source layout and naming

Source programs live under `samples/source/` in language-specific directories:
`asm`, `c`, `cpp`, `csharp`, `fortran`, `go`, `java`, `library`, `lua`,
`python`, and `rust`.

Common filename patterns include:

- `hello-gcc-O0` through `hello-gcc-O3` for optimization variants;
- `hello-clang-debug` and `hello-gcc-stripped` for symbol variants;
- `hello-arm64-gcc` and `hello-riscv64-gcc` for cross-architecture builds;
- `hello-c-mingw64-O2.exe` for Windows PE builds;
- `HelloWorld.class` and `HelloWorld.jar` for JVM fixtures; and
- `hello-go`, `hello-rust-release`, and `hello-gfortran-O2` for language
  recovery fixtures.

Resolve a name against the filesystem before putting it into a test or guide;
the corpus is intentionally heterogeneous and some platform layouts differ.

## Rebuilding samples

Rebuilding is for corpus maintainers. It can require Docker, Buildx/QEMU,
cross-compilers, language toolchains, an Apple SDK for Darwin targets, or UPX.
Inspect the orchestrator's current options with:

```bash
samples/build-multiplatform.sh --help
```

Examples accepted by the current orchestrator are:

```bash
# Build the default linux/amd64 image.
samples/build-multiplatform.sh

# Build selected platform images.
samples/build-multiplatform.sh linux/amd64 linux/arm64

# Use Buildx for a platform set.
samples/build-multiplatform.sh \
  --multiplatform --platforms linux/amd64,linux/arm64
```

The orchestrator currently builds Docker images; it does not copy the built
artifacts back into `samples/binaries/platforms/`. Do not use it with `--clean`
on a shared checkout: that option removes the existing platform corpus before
building. Export from the built image into a separate directory, review the
result, and replace checked-in fixtures only as an intentional corpus update.

The Compose file offers the same platform images as named services. Its current
supported use is image construction, not artifact export:

```bash
docker compose -f samples/docker-compose.yml build linux-amd64
```

The bind mounts apply only when a container runs; the built final images do not
currently include a runtime export command. Building or starting a service
therefore does not populate the host corpus by itself.

Treat full corpus regeneration as a reviewable data change. Toolchain upgrades
can change bytes, symbols, debug information, metadata, and expected analysis
results even when the source program is unchanged.

## Derived fixtures

Generate packed examples from existing Linux executables with:

```bash
samples/build-packed.sh
```

This requires `upx` on `PATH` and writes into `samples/packed/`.

Generate compression and archive examples with:

```bash
samples/build-compressed.sh
```

That script uses the compression tools available on the host and skips missing
optional tools. It writes into `samples/containers/`.

The Python bytecode helper, `samples/test_python_multi_version.sh`, uses Python
interpreters discoverable through `uv` and writes transient output beneath
`samples/test_output/`. It is a maintainer utility, not part of installation.

## Regenerating the inventory

`scripts/index_samples.py` rewrites `samples/binaries/index.json` immediately;
it does not implement a dry-run or `--help` mode. Run it only when you intend to
review and commit a new corpus inventory:

```bash
uv run python scripts/index_samples.py
```

Review changes to paths, hashes, host/tool provenance, and unexpected additions
before committing the result.

## Adding or changing a fixture

1. Add or update the real source under `samples/source/` when source is
   available.
2. Build with a recorded toolchain and retain the exact command or container.
3. Add the binary and metadata without overwriting unrelated corpus entries.
4. Regenerate and review `samples/binaries/index.json` intentionally.
5. Add a fixture-backed test or tutorial step that proves why the sample is
   needed.
6. Run the focused test, then the relevant broader project gates.

Never substitute invented bytes or mocked analysis output for a real fixture.
