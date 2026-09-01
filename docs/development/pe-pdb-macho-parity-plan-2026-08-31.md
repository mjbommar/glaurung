# PE/PDB and Mach-O parity plan — 2026-08-31

This plan turns roadmap R4 into source-grounded fixture lanes with explicit
format, identity, body, type, structure, and refusal contracts. It updates the
older test-estate Phase 4 against the live repository rather than repeating its
stale assumptions.

## Current evidence

### Available toolchains

The current host has:

* `clang-cl` and `lld-link` 21.1.8 targeting Windows MSVC;
* Zig 0.15.2;
* MinGW-w64 GCC 13 for x86-64 and i686; and
* no Wine installation.

Static source-grounded lanes are therefore immediately feasible. Windows
execution is not a current contract and must not be represented as one.

### PE/PDB estate

The sample tree contains 98 files detected as PE and includes MinGW i686 and
x86-64 variants plus 30 internal vendor binaries. This is useful parser,
discovery, and robustness breadth, but it is not a coherent semantic matrix.

`tests/fixtures/msvc-pdb/MANIFEST.json` identifies eight Windows 11 x64
PE/PDB pairs with hashes, CodeView identities, symbol-server URLs, and
provenance. None of their PE or PDB bytes is present locally; only the
manifest, README, fetcher, and ignore file exist. Tests frequently use
`pytest.skip`, `skipif`, or an early Rust `return` when these files are absent.
The README says CI fetches and caches them, but no corresponding workflow was
found. An early-return Rust test is especially weak: Cargo reports it as a
pass, not a skip.

The complete DecBench taxonomy gives format-specific evidence without being a
fixture source: all 171 PE missing-body rows are identity/accounting problems,
partitioned into 33 decorated local stdcall symbols, 63 imports with no local
body, and 75 manifest-only PE aliases. That makes identity disposition the
first PE semantic contract.

### Mach-O estate

The sample tree has one 16,832-byte x86-64 Mach-O, built without an SDK using
`clang` and `ld64.lld`. It has reachable Rust and Python tests for imports,
stubs, lazy pointers, ordering, and evidence-bundle integration. The older
claim that Mach-O implementation files have zero reachable tests is no longer
true.

This one sample does not cover decompilation semantics, ARM64, DWARF-in-Mach-O,
non-lazy pointers beyond its observed layout, chained fixups, export tries,
Objective-C metadata, universal/fat containers, malformed load commands, or
source-level body/structure truth.

## Trust boundary

Three asset classes remain separate:

1. **Hermetic source-grounded fixtures** support identity, body, type,
   structure, compile, and—where a compatible runner exists—execution claims.
2. **Fetched Microsoft PE/PDB pairs** support producer-specific PDB and MSVC
   codegen claims. Network absence is a typed environment state, not a pass.
3. **Internal vendor binaries** support parser/discovery/boundedness and
   determinism only. They do not establish semantic ground truth and are not
   redistributed without license review.

No Ghidra output, DecBench body, PDB public symbol, or nearest symbol is treated
as proof that a requested address owns a local function body.

## Common oracle stack

Every format cell declares applicable oracles:

* **container** — exact format, architecture, image base, sections/segments,
  executable ranges, and malformed-input disposition;
* **identity** — source function to immutable VA/RVA, producer spelling,
  aliases, decorated names, imports, thunks/stubs, exports, and external-only
  records;
* **body** — each expected local function returns a body or typed refusal;
* **type** — calling convention, parameter/return types, aggregate layout,
  fields, and provenance from PDB/DWARF/linker map;
* **structure** — declared loop/switch/call/TLS/SEH/signal predicates;
* **compile** — rendered C compiles for the declared ABI when meaningful;
* **execute** — only on an explicitly pinned compatible runner;
* **resource/determinism** — bounded phases and identical repeated results.

Reports keep `local_body`, `import`, `thunk`, `alias`, `stub`, `forwarder`,
`runtime_entry`, and `absent` distinct. Counting an import slot or Mach-O stub
as a recovered local body is a contract failure.

## Canonical lane record

Extend the inventory schema with:

* source and binary hashes, exact build command, tool versions, container
  digest, format/arch/ABI/producer/optimization;
* PE CodeView GUID/age, PDB hash/name, linker-map hash, image base, section and
  exception-directory facts;
* Mach-O UUID, CPU type/subtype, file type, slice identity, load-command facts,
  DWARF/debug-map identity, and fixup/bind/export-trie mode;
* expected local symbols/RVAs, imports, thunks/stubs, aliases, TLS/runtime
  entries, calling conventions, type/field facts, and structure predicates;
* runner, gate, applicability, structured skip/refusal, and runtime class.

Generated fixture bytes and metadata are atomic. `--check` rebuilds on the
pinned toolchain and rejects hash, oracle, or orphan-runner drift.

## PE/PDB implementation

### P1 — minimal clang-cl identity lane

Start with four tiny DLLs, not the full fixture corpus:

* PE32 i686 `/Od` and `/O2`;
* PE32+ x86-64 `/Od` and `/O2`;
* `/Z7`, `lld-link /debug /dll`, a linker map, explicit exports, and no SDK
  dependency beyond a committed compatibility header.

Sources include cdecl, i386 stdcall, fastcall where supported, an exported
worker routine, a private helper, one import, and a colliding spelling case.
The map/PDB/source triple independently proves exact RVAs and whether each name
is local or external.

RED first: `_name@N` resolves to its unique local code RVA; a collision is
reported rather than guessed; an import yields an external disposition rather
than a body. This independently guards F1a/F1b.

Exit: four cells account for every requested source identity and decompile all
local bodies without stealing an import, thunk, or collision.

### P2 — PE runtime and loader shapes

Add one source fixture per distinct loader contract:

* TLS callback and ordinary entry point;
* `.pdata`/unwind/SEH-protected x64 function;
* ordinary, delay, and ordinal import;
* export alias and forwarded export;
* import thunk and tail-call worker;
* overlay data and malformed-but-loadable section layout.

Do not combine all shapes into one opaque binary. Each fixture carries a
negative control and exact expected directory/RVA facts. A TLS callback is a
runtime entry identity, not evidence that it was a source-manifest function.

Exit: discovery provenance names the seeding mechanism, and every entry is
classified before body recovery is scored.

### P3 — PDB identity and type lane

Use clang-cl PDBs for hermetic baseline behavior:

* public and private symbols, overloaded C++ names, line/module records;
* primitive, pointer, array, enum, struct, union, nested aggregate, bitfield,
  base-class, and function-type records;
* x86/x64 calling conventions and field-offset use in recovered memory
  expressions; and
* precedence/collision between PDB, exports, linker map, and manual facts.

Assertions compare source declarations and linker/PDB records to recovered
facts, not string snapshots. Exact type provenance must survive into the
decompiler report.

Exit: identity, prototype, aggregate layout, and field-use oracles work without
network access.

### P4 — real MSVC producer quirks

Retain the eight fetched pairs only for behavior clang-cl cannot prove. Add a
single session fetch/verify mechanism under a cache directory, with explicit
offline and hash/CodeView failure states. Correct the README and inventory to
name the actual runner.

Audit every dependent test:

* migrate generic PE/PDB assertions to hermetic fixtures;
* keep MSVC/PDB producer-specific assertions opt-in or in a provisioned lane;
* replace Rust early returns with a harness-visible skipped/unsupported result;
* fail the provisioned release lane if expected fetched inputs did not run.

Exit: a default fresh checkout has meaningful hermetic PDB coverage; the
producer-specific lane cannot claim green after executing zero pairs.

### P5 — PE semantic and resource ratchets

Apply the optimized structural schema to PE O0/O2 cells. Since Wine is absent,
initial contracts are static: body accounting, compile for Windows target,
type/structure predicates, def-use, deterministic output, and performance/RSS.
Add execution only with a pinned Wine or Windows runner and cross-check its ABI
and exception limitations first.

Exit: PE parity does not depend on pretending Linux can execute a DLL.

## Mach-O implementation

### M1 — reproducible thin-binary matrix

Extend the existing generator into four thin cells:

* x86-64 O0/O2;
* ARM64 O0/O2;
* committed portable source, pinned Zig/LLVM linker, exact hashes; and
* ordinary local functions plus multiple imports/stubs and exported symbols.

Record whether the binary contains conventional dyld info or chained fixups;
do not assume the linker produced the intended encoding. Use LLVM inspection
tools as an independent container oracle.

Exit: both architectures have source-to-VA identity and local-body coverage,
not merely stub-map tests.

### M2 — DWARF, bindings, and fixups

Add focused fixtures for:

* DWARF-in-Mach-O function/type facts and stripped twin;
* lazy/non-lazy binding and symbol stubs;
* export trie, rebase/bind data, and authenticated/chained fixups where the
  available linker can emit them;
* constructor/mod-init runtime entry; and
* indirect calls through resolved pointers.

If Zig/LLVM cannot emit a required modern fixup shape, use a small legally
redistributable producer fixture with pinned bytes and an independent parser
oracle; do not fabricate parser results.

Exit: stubs/external identities remain distinct from local bodies and binding
facts feed call annotation without symbol snapping.

### M3 — universal binaries and slice identity

Create a universal container from the two already validated thin slices using
a small committed deterministic builder. Validate magic, endianness, offsets,
alignments, bounds, CPU/subtype, overlapping-slice rejection, and explicit
slice selection.

Every downstream function identity includes slice identity. The same VA in two
slices is not the same function. Reports never silently analyze the first slice
when the caller requested another.

Exit: x86-64 and ARM64 requests return their own bodies and architecture facts;
malformed or ambiguous slice requests fail closed.

### M4 — malformed and bounded parser corpus

Add real mutated binaries derived deterministically from the owned thin/fat
fixtures: truncated load commands, integer overflow, out-of-bounds string or
symbol tables, bad indirect-symbol indices, overlapping slices, and invalid
fixup chains. Assert typed errors, time/RSS bounds, and no partial-success body
claim.

Exit: parser robustness is measured separately from semantic quality.

## Sequencing and cost control

Implementation order:

1. P1 minimal PE identity lane;
2. M1 thin Mach-O x86-64/ARM64 lane;
3. P2 loader/runtime shapes;
4. P3 hermetic PDB types;
5. M2 fixups/DWARF and M3 universal slices;
6. P4 fetched MSVC rescope;
7. PE/Mach-O structural/performance expansion; then
8. optional execution after a pinned compatible runner exists.

Each new format cell lands alone with its measured runtime and refreshed
inventory/baselines. Do not multiply the whole 200-fixture matrix by six new
lanes before the minimal cells prove distinct value.

## TDD verification

Focused commands are introduced with the implementation, but the intended
shape is:

```bash
tools/dectest.py <fixture> --arch windows-i686 --show
tools/dectest.py <fixture> --arch windows-x64 --show
tools/dectest.py <fixture> --arch macos-x64 --show
tools/dectest.py <fixture> --arch macos-arm64 --show
uv run pytest python/tests/test_macho_stubs.py -xvs
cargo test --features python-ext --test pe_format_parity
```

Names are contracts to implement, not claims that these selectors/tests exist
today. Product changes run the complete gates from `CLAUDE.md`. Fixture
generation and checks must never fetch from the network implicitly.

## Completion evidence

R4 is complete only when:

1. PE32, PE32+, Mach-O x86-64, and Mach-O ARM64 have hermetic O0/O2 cells;
2. every requested identity is classified as local body, import/stub/thunk,
   alias/runtime entry, or typed absence;
3. PDB and Mach-O DWARF type/layout oracles reach decompiler output;
4. PE TLS/SEH/import/export and Mach-O binding/fixup/universal shapes have
   independent source/container assertions;
5. missing fetched fixtures cannot produce a green provisioned lane;
6. body, structure, def-use, determinism, performance, and refusal ratchets run
   over stable denominators; and
7. one retained internal report binds source, bytes, toolchains, build revision,
   oracle results, and explicit unsupported execution cells.

Nothing in this plan publishes binaries, opens a PR/issue, sends email, or
submits benchmark data.

