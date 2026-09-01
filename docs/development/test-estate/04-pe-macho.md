# Phase 4 — PE and Mach-O become real fixture lanes

## The problem

Windows is the project's **active frontier** (`CLAUDE.md`), with a broad PE
estate but many tests waiting on gitignored `msvc-pdb/*.exe|dll` binaries that
nothing fetches automatically. The original audit also found
`symbols_macho.rs` unwired. That part has since landed: the tracked Mach-O
sample now has reachable triage, Rust stub-resolver, and Python integration
tests. It remains only one x86-64 sample and provides no decompiler-semantic,
ARM64, DWARF, chained-fixup, or universal-binary matrix.

The current evidence and implementation contract superseding the rough counts
in this phase are in
[`../pe-pdb-macho-parity-plan-2026-08-31.md`](../pe-pdb-macho-parity-plan-2026-08-31.md).

Both are fixable on this Linux box with tools already installed and verified
present:

* `clang-cl` / `lld-link` **21.1.8** — compile and link PE/COFF **with PDB**
  natively on Linux (`clang-cl /Z7`, `lld-link /debug`). No MSVC license, no
  Windows machine.

  > **Measured 2026-09-01, and the claim needs three caveats.** The link step
  > does *not* work as written: `lld-link` fails with
  > `could not open 'libcmt.lib'` / `'oldnames.lib'` because the MSVC runtime
  > import libraries are not on this box. `clang-cl /c` compiles PE/COFF
  > happily without them; only linking needs them.
  >
  > 1. **`/nodefaultlib` is required**, which makes every fixture in this lane
  >    freestanding: no CRT, so no `printf`/`malloc`/string functions. Most
  >    decompiler fixtures are self-contained arithmetic and control flow and
  >    are fine; any fixture that calls the CRT needs the skip list, alongside
  >    the gcc-asm ones. (`xwin` could fetch the SDK import libs and lift this,
  >    at the cost of a network dependency and an EULA acceptance in the build.)
  > 2. **`__declspec(thread)` does not link** without the CRT — it references
  >    `_tls_index`. Defining `unsigned long _tls_index = 0;` in the fixture
  >    resolves it.
  > 3. **lld-link emits no TLS data directory** for such a DLL even then
  >    (`TLSTableRVA: 0x0`), so this lane cannot produce a TLS-identity
  >    fixture at all.
  >
  > Verified working: a PE32+ DLL plus a real PDB, with a valid CodeView debug
  > directory entry (GUID, age, PDB path) that `llvm-readobj` reads back.
  >
  > **For entry/TLS/import identity, prefer the committed real samples.**
  > `samples/binaries/platforms/windows/vendor/realworld/win10-dismcore.dll`
  > carries all three structures at once — no COFF symbol table (stripped), a
  > CodeView entry naming `DismCore.pdb`, and a TLS directory at RVA 0x30088 —
  > and five other vendor DLLs have TLS directories too. They are already in
  > the tree, they are real MSVC output rather than clang-cl's, and they cost
  > no build. `python/tests/test_symbol_summary_fields.py` uses them, and
  > finding two real defects that way (`pdb_path` never exposed, and an RSDS
  > scan reading 199,416 bytes short of the record) is the argument for it.
* `zig` **0.15.2** — `zig cc -target x86_64-macos` / `aarch64-macos` produces
  real Mach-O with its bundled darwin linker.

## 4.1 A `windows` lane in the fixture matrix

Extend `tools/fixture_harness.py` with a cross lane the way
`tools/arch_roundtrip.py` added `i386` / `armv7` / `aarch64` /
`x86_64_gcc15`:

* Toolchain: `clang-cl /O2` and `/Od` (the O2/O0 analogues), `/Z7`,
  linked `lld-link /debug /dll` → a PE DLL plus a PDB per fixture.
* Target the existing C fixtures first — the sources are already portable C
  with `__attribute__` annotations; add a small compat header mapping
  `__attribute__((noinline))` → `__declspec(noinline)` etc., and **skip-list
  rather than fork** any fixture that cannot be expressed both ways (the
  gcc-asm fixtures like `208` go on the skip list with a reason).
* **Scope honestly: no execution.** The differential dlopens on the host, so
  PE cells are decompile-only — scored by the structural predicates, the
  recovered-prototype checks and the def-use census, recorded in
  `arch_baseline.json` alongside the other cross lanes. (Wine-based execution
  is a possible later extension; it is not in this phase, and the lane's
  docs say so.)

What this buys: every MSVC-ABI recovery problem — callee-saved conventions,
`__fastcall`/`__thiscall`, SEH scaffolding, PDB-vs-DWARF type ingestion —
gets fixtures with **source-level ground truth**, which the fetched
`msvc-pdb` binaries can never provide.

## 4.2 The msvc-pdb 142

With 4.1 in place, re-scope the fetched fixtures to what they are uniquely
good for: real MSVC codegen (not clang-cl's) and real PDB producer quirks.

* Wire `fetch.sh` into a session-scoped pytest fixture with a cache dir under
  `~/.cache/glaurung/` and a **visible** skip when offline (Phase 1.6's `-ra`
  makes visible mean visible).
* Correct the fixture README, which claims CI fetches and caches — it does
  not.
* Audit the 142 for overlap with 4.1 lanes; tests that only need *a* PE with
  *a* PDB migrate to the hermetic clang-cl fixtures and stop depending on the
  network.

## 4.3 Mach-O fixtures via zig

* Build the same portable-C fixture subset with
  `zig cc -target x86_64-macos -O2 / -O0` and `aarch64-macos`, `-g` for
  DWARF-in-Mach-O (and the `.dSYM`-less debug-map shape that real macOS
  builds have).
* Static-analysis-only lane, same honesty as 4.1: format parsing, symbols,
  chained-fixups/stubs handling (`src/analysis/macho_stubs.rs` — currently
  zero tests), function discovery, decompile-and-predicate. Recorded in
  `arch_baseline.json`.
* Preserve the now-wired `tests/triage/symbols_macho.rs` and existing stub-map
  integration tests, then add triage/format tests for fat (universal) binaries
  — `lipo`-style fat headers can be assembled by a tiny committed script even
  without Apple tools.

## 4.4 Hermeticity

Both lanes build in Docker (extend the `glaurung-fixture-toolchain` image
with `zig` and the llvm tools; it is already how the other lanes stay
byte-stable). Version-pin in the image, record versions in the lane manifest.

## Acceptance

* `tools/dectest.py <fixture> --arch windows-x64` and `--arch macos-arm64`
  decompile real PE/Mach-O built from committed source.
* `arch_baseline.json` carries verdicts for both lanes; the census runs over
  them.
* Every Mach-O parser/discovery/decompiler path names a reachable test and
  source-grounded oracle; existing stub coverage alone is not parity.
* The 142 fetched-fixture tests either run (cache hit), skip visibly
  (offline), or have migrated to hermetic fixtures.

## Effort

The compat-header + clang-cl lane is two days (expect a tail of
fixture-portability decisions). Mach-O lane one day. msvc-pdb rescope one
day. Baseline refreshes per the standing six-side-file discipline.
