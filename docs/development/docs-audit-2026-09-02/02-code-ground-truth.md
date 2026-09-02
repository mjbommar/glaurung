# Glaurung — Ground-Truth Map of the Code

> **Kind:** record · **Date:** 2026-09-02

Generated 2026-09-02 from a read-only sweep of `/home/mjbommar/projects/personal/glaurung`
at `master` = `b8884687`. Every number here comes from the source tree or git, not from
`docs/` or `CLAUDE.md`. Where the docs disagree with the tree, the tree wins and the
discrepancy is recorded in §10.

Scale at a glance:

| | count | LOC |
|---|---|---|
| Rust `src/**/*.rs` | 489 files | 290,841 |
| Python `python/glaurung/**/*.py` | 389 files | 158,845 |
| Python tests `python/tests/` | see §7 | |
| Commits (all time) | 1,669 | first commit 2025-08-29 |

**Contents**
1. [Rust crate map](#1-rust-crate-map) — features, per-directory LOC, reachability, benches, fuzz
2. [The decompiler pipeline as built](#2-the-decompiler-pipeline-as-built) — the ordered pass list from `python_bindings/ir.rs`
3. [Python package map](#3-python-package-map) — modules, the `.glaurung` schema, `set_by` provenance
4. [CLI surface](#4-cli-surface) — 40 subcommands, global flags
5. [LLM subsystem](#5-llm-subsystem) — config, agents, 219 tools, L1–L5, F1–F7
6. [Environment variables](#6-environment-variables) — every reader, with defaults
7. [Tests, fixtures, and gates](#7-tests-fixtures-and-gates) — baselines, scripts, tools, CI
8. [Samples corpus and fixtures](#8-samples-corpus-and-fixtures)
9. [Git history themes](#9-git-history-themes) — workstreams, hot files, real vs stated frontier
10. [In the docs but not in the code](#10-in-the-docs-but-not-in-the-code)

---

## 1. Rust crate map

### 1.1 `Cargo.toml` `[features]` — complete table

`[package] name = "glaurung"`, `edition = 2021`, `crate-type = ["cdylib", "rlib"]`.

| feature | pulls in | what it actually gates in `src/` |
|---|---|---|
| `default` | `["triage-core"]` | — |
| `triage-core` | (empty) | **nothing.** Zero `cfg(feature = "triage-core")` in `src/`. A no-op marker feature. |
| `triage-heuristics` | (empty) | **nothing.** Zero occurrences in `src/`. |
| `triage-containers` | (empty) | **nothing.** Zero occurrences in `src/`. |
| `triage-parsers-extra` | `goblin`, `pelite` | 4 sites, all in `src/triage/parsers.rs` (the goblin/pelite secondary parsers). |
| `python-ext` | `pyo3`, `pyo3/extension-module`, `exec` | **167 `cfg` sites across 46 files** — all of `src/python_bindings/` (10,511 LOC), `src/disasm/py_api.rs`, plus per-type `#[pyclass]`/`#[pymethods]` blocks scattered through `src/core/`, `src/triage/`, `src/strings/`. |
| `exec` | (none) | `src/exec/` (10 files, 3,591 LOC) + `src/python_bindings/exec.rs`. **Included in `python-ext`,** so the shipped wheel has the concrete emulator. |
| `symbolic` | `exec` | `src/symbolic/` (26 files, **21,459 LOC**) — one `cfg` in `src/lib.rs`. NOT in `default` and NOT in `python-ext`. |
| `dev-oracle` | `exec`, `dep:unicorn-engine` | `src/exec/oracle.rs`. Dev-only differential test against system libunicorn; never shipped. |
| `solver-z3` | `symbolic`, `dep:z3` | 15 sites in `src/symbolic/solver/`. |
| `solver-axeyum` | `symbolic`, `dep:axeyum-solver`, `dep:axeyum-ir` | 22 sites. Pure-Rust QF_BV solver pinned to git rev `c38a9515`. |
| `solver-bitwuzla` | `symbolic` | 19 sites. Benchmark-only C-API cell, explicitly *not* in production backend selection. |
| `solver-axeyum-text` | `solver-axeyum`, `axeyum-solver/full` | 8 sites. Legacy SMT-LIB text bridge. |

Also 19 `cfg(all(feature = "solver-z3", feature = "solver-axeyum"))` sites (the differential
comparison harness) and 5 bare `cfg(feature = "pyo3")`.

**Reachability summary.** A plain `cargo build`/`cargo test` (default = `triage-core`, which
gates nothing) compiles *everything* except: `src/python_bindings/`, `src/disasm/py_api.rs`,
`src/exec/`, `src/symbolic/`, and the goblin/pelite arms of `src/triage/parsers.rs`.
`cargo test --features python-ext` adds the bindings and `exec`, but **still never compiles
`src/symbolic/` (21,459 LOC) or the four solver backends**. This matches the CLAUDE.md
warning and is confirmed here from `src/lib.rs` line-by-line.

`[tool.maturin]` in `pyproject.toml` builds the wheel with `features = ["pyo3/extension-module", "python-ext"]`
→ **the shipped wheel contains `exec` but no `symbolic` and no solver.**

Notable deps: `pyo3 0.26`, `object 0.37`, `gimli 0.33`, `pdb 0.8`, `iced-x86 1.20`,
`capstone 0.12`, `goblin 0.10`/`pelite 0.10` (optional), `rayon`, `memmap2`, `blake3`,
`cpp_demangle`/`rustc-demangle`/`msvc-demangler`, `windows-metadata 0.60`, `whatlang`,
`flate2`, and **`mimalloc` wired as `#[global_allocator]` in `src/lib.rs`** (the allocator
was 26% of a release decompile profile).

### 1.2 `src/lib.rs` — the declared module list

Unconditional: `core`, `error`, `logging`, `timeout`, `target`, `triage`, `symbols`,
`demangle`, `similarity`, `strings`, `entropy`, `analysis`, `debug`, `flirt`, `disasm`,
`ir`, `decompile`, `formats`, `winmd`, `program`, `unpack`.
Gated: `exec` (`exec`), `symbolic` (`symbolic`), `python_bindings` (`python-ext`),
`testing` (`cfg(test)`).

`src/lib.rs` also defines three top-level `#[pyfunction]`s directly: `symbol_address_map`,
`symbol_table_entries`, `pe_export_entries`.

**Dead directories (tracked in git, never declared as modules, therefore never compiled in
any configuration):**
- `src/io/` (`mod.rs`, `error.rs`, 335 LOC) — a `SafeReader` with mmap + limits.
- `src/hashing/` (`mod.rs`, 62 LOC).
- `src/data/tlds.txt` — no `include_str!` or other reference anywhere in `src/`.

### 1.3 Per-directory map

LOC = `wc -l` over `*.rs`. A `foo.rs` + `foo/` pair is the Rust-2018 layout: the file is the
module, the directory holds its submodules; both rows are counted separately.

| dir | files | LOC | purpose (from `//!`) | feature |
|---|---|---|---|---|
| `src/ir/` | 202 | **164,779** | LLIR + AST + all decompiler passes. See §1.4. | default |
| `src/analysis/` | 57 | 28,334 | CFG/function discovery, xrefs, jump tables, IOCTL surfaces, format-specific resolvers. See §1.5. | default |
| `src/symbolic/` | 26 | 21,459 | Symbolic/concolic execution over the same `Domain` the emulator uses; hash-consed BV `Expr` IR + solver layer. | **`symbolic` only** |
| `src/core/` | 34 | 16,924 | The fundamental data model: `Address`, `AddressRange`, `AddressSpace`, `Binary`, `Section`/`Segment`, `Symbol`, `Function`, `BasicBlock`, `ControlFlowGraph`, `CallGraph`, `Instruction`/`Operand`, `Register`, `Relocation`, `DataType`, `Variable`, `StringLiteral`, `Pattern`, `Reference`, `Artifact`, `ToolMetadata`, `Id`. Plus `src/core/triage/` (10 files, 1,911 LOC) holding the triage result envelope types. | default |
| `src/python_bindings/` | 20 | 10,511 | PyO3 surface, organized per subsystem. See §1.6. | **`python-ext`** |
| `src/formats/` | 38 | 10,477 | Binary format parsers. See §1.7. | default (goblin/pelite arms gated) |
| `src/program/` | 23 | 8,951 | Program-scoped image/target/environment/session ownership — `ProgramImage`, `ProgramSession`, `SymbolStore`, `ReferenceResolver`, type env, call graph, spans. This is what the decompiler entry points load a binary through. | default |
| `src/triage/` | 21 | 8,008 | Bounded, deterministic file triage: format/sniffer detection, header validation, entropy, packers, Rich header, overlays, compiler/language detection, recursion into containers, confidence scoring. | default |
| `src/symbols/` | 13 | 4,645 | Symbol extraction: `elf.rs`, `pe.rs`, `macho.rs`, `pdb.rs` (1,629 LOC — the biggest), `types.rs`, plus `analysis/` (7 files, 898 LOC). | default |
| `src/exec/` | 10 | 3,591 | Concrete emulator over LLIR. `domain.rs` is the keystone trait; `interp.rs` (1,298) is the single interpreter shared with the symbolic backend; `state.rs`, `memory.rs` (softmmu), `helpers.rs`, `simproc.rs`, `budget.rs`, `oracle.rs` (Unicorn diff, `dev-oracle`). | **`exec`** (⊂ `python-ext`) |
| `src/strings/` | 11 | 3,260 | Bounded string scanning, IOC classification, language detection (`whatlang`), similarity, fast SIMD detect path. | default |
| `src/debug/` | 3 | 2,423 | DWARF ingestion — `dwarf.rs` (1,539) function discovery/ranges/types, `dwarf_signatures.rs` (864). PDB lives in `src/symbols/pdb.rs`, not here. | default |
| `src/disasm/` | 5 | 1,751 | Decoder adapters + registry. `iced.rs` → x86/x86-64; `capstone.rs` → ARM, ARM64, MIPS/MIPS64, PPC/PPC64, RISCV/RISCV64. `registry.rs` picks the backend. `py_api.rs` is `python-ext`. | default |
| `src/unpack/` | 3 | 1,269 | Static recovery of the original image from a packed one: `upx.rs` (834), `nrv.rs` (NRV decompressor). | default |
| `src/target/` | 5 | 956 | One validated `TargetSpec`: architecture, ABI, width, register roles, code mode. `conformance_tests.rs` is 602 of the 956. | default |
| `src/entropy/` | 4 | 840 | Shannon entropy + sliding-window analysis, perf-tuned. | default |
| `src/similarity/` | 1 | 336 | CTPH fuzzy hashing (BLAKE3-XOF based, deliberately non-ssdeep to avoid GPL). | default |
| `src/flirt/` | 1 | 322 | FLIRT-style prologue matching from a JSON library built by `glaurung.tools.build_flirt_library`. | default |
| `src/decompile/` | 2 | 235 | `profile.rs` — run/function profilers and `parse_object`. Small but load-bearing: every entry point opens the image through it. | default |
| `src/demangle/` | 1 | 123 | Itanium + Rust demangling wrappers; MSVC detected but passed through. | default |
| loose files | 6 | 1,250 | `lib.rs` (265), `timeout.rs` (238), `winmd.rs` (203, Windows metadata), `logging.rs` (188), `testing.rs` (190, `cfg(test)`), `error.rs` (166). | |

### 1.4 `src/ir/` — the decompiler, one level down

Subdirectories:

| subdir | files | LOC | |
|---|---|---|---|
| `ast/` | 18 | 12,519 | AST lowering + **all renderers**: `c_render.rs`, `ctx_render.rs` (plain + typed), `decbench_render.rs`, `dec_render/`, plus `lower_region.rs`, `lower_conds.rs`, `lower_ops.rs`, `declaration_plan.rs`, `return_ctype.rs`, `param_spills.rs`, `float_gate.rs`, `width_semantics.rs`, `abi_widths.rs`, `dwarf_render_types.rs`, `named_calls.rs`, `prepare.rs`, `return_folds.rs` |
| `lift_x86/` | 11 | 5,455 | x86/x86-64 lifter submodules (`lift_x86.rs` itself is another 9,556) |
| `mir/` | 9 | 4,550 | Verified typed mid-level IR: `builder`, `model`, `memory`, `query`, `verify`, `verify_objects`. Built on demand (`PreparedLlir::mir`); **no production consumer yet** — the code says so explicitly |
| `stack_locals/` | 10 | 4,522 | stack-slot promotion (+ `stack_locals.rs` 4,928) |
| `copy_prop/` | 9 | 3,298 | copy propagation (+ `copy_prop.rs` 1,536) |
| `call_args/` | 8 | 3,024 | argument reconstruction (+ `call_args.rs` 5,699) |
| `memory_objects/` | 6 | 2,930 | inferred memory objects / affine access paths |
| `structure/` | 8 | 2,604 | `cfg`, `region`, `if_shape`, `loop_shape`, `switch_shape`, `path_predicates`, `fallback`, `verify` (+ `structure.rs` 3,032) |
| `types_recover/` | 5 | 2,506 | `copies`, `float_bank`, `result_hint`, `tagging`, `valued` (+ `types_recover.rs` 5,539) |
| `value_number/` | 7 | 2,065 | SSA value numbering (+ `value_number.rs` 2,692) |
| `lift_arm32/` | 7 | 1,539 | (+ `lift_arm32.rs` 4,030) |
| `lift_arm64/` | 3 | 1,476 | (+ `lift_arm64.rs` 3,598) |
| `abi/` | 2 | 539 | (+ `abi.rs` 1,823) |
| `structured_reaching/`, `readonly_fold/`, `lazy_call_select/`, `ast_tests/` | 1–4 | 111–511 | |

The single largest files in the crate are all here: `lift_x86.rs` (9,556), `ast.rs` (9,710),
`call_args.rs` (5,699), `types_recover.rs` (5,539), `stack_locals.rs` (4,928),
`lift_arm32.rs` (4,030), `lift_arm64.rs` (3,598), `structure.rs` (3,032).

Every top-level `src/ir/*.rs` has a one-line `//!` summary; they are reproduced against the
pass order in §2.

### 1.5 `src/analysis/` — one level down

| subdir | files | LOC | |
|---|---|---|---|
| `cfg/` | 19 | 8,327 | The discovery pipeline, documented as a table in `src/analysis/cfg.rs`: `packed` → `image_view` → `budgets` → `scan`/`entry_shape`/`pe_tables`/`plt`/`seeds` → `worklist` → `body_index` → `walk`/`ctrl_flow`/`extents`/`function_build`/`repair`/`must_dataflow`/`dispatch_flow`/`dispatch_resolution`/`stats` (+ `cfg.rs` 1,992) |
| `java_class/` | 7 | 2,263 | JVM classfile parsing (+ `java_class.rs` 666) |
| `dispatch/` | 3 | 665 | indirect-branch target-set resolution at the dispatch site (+ `dispatch.rs` 2,161) |
| `linux_ioctl/` | 1 | 105 | (+ `linux_ioctl.rs` 340) |

Loose modules of note: `ioctl_taint.rs` (1,511 — **exists**, WDM driver abstract
interpretation), `exception.rs` (1,315, Itanium call sites), `xrefs.rs` (1,304),
`jump_table.rs` (1,026), `linux_symbolic_frontend.rs` (871), `ioctl_surface.rs` (769),
`elf_plt.rs` (701), `pe_iat.rs` (571), `cil_metadata.rs` (447, .NET), `vtable.rs` (435),
`macho_stubs.rs` (401), `java_jar.rs` (353), `lua_bytecode.rs` (279), `gopclntab.rs` (248,
Go), `elf_got.rs` (225), `completeness.rs` (141, turns "a budget fired" into a rendered note).

### 1.6 `src/python_bindings/` — the PyO3 surface

| file | LOC | registers |
|---|---|---|
| `ir.rs` + `ir/` | 2,496 + 4,303 | The decompiler entry points. See §2. |
| `analysis.rs` | 1,908 | CFG/function discovery, xrefs, call graph |
| `strings.rs` | 388 | |
| `debug.rs` | 342 | DWARF |
| `symbols.rs` | 301 | |
| `similarity.rs` | 166 | |
| `triage.rs` | 161 | |
| `exec.rs` | 124 | gated on `exec` |
| `unpack.rs` | 110 | |
| `core_types.rs` | 110 | |
| `mod.rs` | 45 | `register_python_bindings` calls all of the above in a fixed order |
| `disasm.rs` | 34 | |
| `winmd.rs` | 23 | |

Built module is `glaurung._native`; stubs live in `python/glaurung/_native/*.pyi`
(12 files, generated by `tools/gen_native_stub.py`).

### 1.7 `src/formats/`

| subdir | files | LOC | contents |
|---|---|---|---|
| `pe/` | 11 | 4,365 | `headers`, `sections`, `types`, `utils` + `directories/` (`export`, `import`, `resource`, `debug`, `tls`) |
| `elf/` | 13 | 4,172 | `headers`, `sections`, `segments`, `dynamic`, `dynamic_segment`, `relocations`, `packed_relocations`, `notes`, `symbols`, `eh_frame_segment`, `types`, `utils` |
| `axml/` | 5 | 785 | Android binary XML (`manifest`, `strings`, `types`) |
| `dex/` | 4 | 675 | Android DEX |
| `apk/` | 2 | 283 | APK/AAB/JAR member extraction via ZIP central directory + DEFLATE |
| `sepolicy/` | 2 | 189 | SELinux policy |

**There is no `src/formats/macho/`.** Mach-O support lives in `src/symbols/macho.rs`,
`src/analysis/macho_stubs.rs`, and via the `object` crate in `src/decompile/profile.rs`.

### 1.8 `benches/` (Criterion, `harness = false`)

| bench | KB | scope |
|---|---|---|
| `ir_lift.rs` | 49 | lifters x86/ARM32/ARM64/x87, micro → whole object |
| `ir_dataflow.rs` | 23 | 17 dataflow passes isolated + pipeline groups |
| `decompile_pipeline.rs` | 23 | end-to-end + an 8-phase split |
| `ir_structure.rs` | 21 | structuring/render, 14-shape sweep |
| `analysis_cfg.rs` | 20 | CFG discovery, whole-binary `Throughput::Bytes` |
| `lang_detect.rs` | 8 | |
| `emulator.rs` | 7 | `required-features = ["exec"]` |
| `triage.rs` | 5 | |
| `strings.rs` | 1.4 | |
| `entropy.rs` | 0.8 | |

### 1.9 `fuzz/` — a separate crate

`fuzz/Cargo.toml` depends on `glaurung` with `default-features = false,
features = ["triage-core", "triage-heuristics", "triage-containers"]` — i.e. the fuzzers
build a *narrower* configuration than anything else in the repo, and no root-manifest
`cargo check` sees them.

8 targets in `fuzz/fuzz_targets/`: `disasm_decode.rs` (2.1 KB, the biggest),
`demangle_all.rs`, `formats_parse.rs`, `sniffers_sniff.rs`, `entropy_analyze.rs`,
`containers_detect.rs`, `headers_validate.rs`, `parsers_parse.rs`.
`fuzz/seed_corpus.py` seeds them from the repo's own binaries.

### 1.10 `examples/` (21 files)

Rust examples driving the symbolic/solver stack, most `required-features`-gated in
Cargo.toml: `ioctl_scan`, `ioctlance`, `linux_symbolic_cve`, `ordered_native_replay`,
`axeyum_diff`, `axeyum_sweep`, `axeyum_incremental`, `axeyum_bench_primitives`,
`axeyum_infeasible_path_proof`. Ungated: `ast_demo`, `check_canary`, `check_prologue`,
`test_classifier`, `ioctl_surface_scan`, `linux_symbolic_frontend`.
Plus 5 Python examples (IOC validation, iterative analysis, triage).

---

## 2. The decompiler pipeline as built

Entry point of record: `/home/mjbommar/projects/personal/glaurung/src/python_bindings/ir.rs`
and its submodule tree `src/python_bindings/ir/`.

### 2.1 The four Python entry points

All in `src/python_bindings/ir.rs`:

| `#[pyfunction]` | line | |
|---|---|---|
| `decompile_at(path, func_va, …)` | 108 | one function |
| `decompile_range_at(path, …)` | 510 | an explicit `[start, end)` range |
| `decompile_all(path, …)` | 942 | whole binary |
| `decompile_many(path, vas, …)` | 1222 | a VA list |
| `take_render_verification()` | 1639 | drains render-verification diagnostics |

Plus `lift_bytes` / `lift_window_at` in `src/python_bindings/ir/lift.rs` (raw LLIR-as-dicts,
no pipeline).

The four exist to be identical: `src/python_bindings/ir/pipeline.rs` says so in its module
doc — "One copy of the pass list, one copy of the LLIR preparation, so the four Python entry
points cannot drift into different value models." A loop-hoist retry once landed in one copy
and silently did nothing in the other three; that is why `run_ast_passes` is shared.

Signature of `decompile_at`:
```
(path, func_va, max_blocks=4096, max_instructions=200_000, timeout_ms=5000,
 types=True, style="", pdb_cache="", max_functions=1,
 analyst_names=None, analyst_locals=None, analyst_prototype=None)
```

### 2.2 Lifters present

`src/ir/lift_function.rs::supports_arch` is the authority:

```rust
matches!(arch, Arch::X86 | Arch::X86_64 | Arch::AArch64 | Arch::ARM)
```

- `src/ir/lift_x86.rs` (9,556 LOC + `lift_x86/` 5,455) — x86 and x86-64, plus
  `src/ir/x87.rs` (1,700) for x87 floating point.
- `src/ir/lift_arm64.rs` (3,598 + `lift_arm64/` 1,476) — AArch64.
- `src/ir/lift_arm32.rs` (4,030 + `lift_arm32/` 1,539) — ARMv7 / Thumb-2.

**There is no RISC-V lifter.** RISC-V (and MIPS/PPC) are *disassembly-only* through
`src/disasm/capstone.rs`; `supports_arch` rejects them and `target_calling_convention`
raises `ValueError("LLIR decompiler does not support target …")`.

`validate_code_mode` runs before any byte is decoded and rejects incoherent
(arch, thumb) pairs; `LiftError` distinguishes `UnsupportedArchitecture` /
`IncoherentCodeMode` / `NoLiftableBlocks` so a caller can tell a capability gap from data
loss (`affected_ranges()` names the lost VA ranges).

### 2.3 Stage 0 — image, discovery, naming (in `decompile_at`, before the IR stages)

In source order:

1. `RunProfiler::from_env("decompile_at")` — opt-in phase profiling.
2. `ProgramSession::from_path` → `ProgramImage` (`src/program/`).
3. `image.normalize_function_entry(func_va)` — strips the ARM32 Thumb bit
   (`src/analysis/arm32_mode.rs`).
4. `image.exception_call_sites()` — Itanium LSDA call sites (`src/analysis/exception.rs`).
5. `dwarf_output_contracts(&image)` + `session.debug_types()` → `DwarfTypeEnv`
   — **only when `style=="decbench" && types`**.
6. `Budgets { max_blocks, max_instructions, max_functions, timeout_ms }`.
7. `py.detach(|| session.discover_functions(&budgets, &[func_va]))` — whole-binary CFG
   discovery (`src/analysis/cfg/`), released from the GIL so Ctrl-C works.
8. `target_calling_convention(&image)` → `CallConv` (`SysVAmd64` | `Win64` | `Arm` |
   `ArmHardFloat` | `Aarch64`).
9. `name_resolve::collect_address_map_with_pdb_cache_and_data_symbols` — one image parse
   yielding both call-target names (symbols + PDB cache + PE exports/IAT) and named static
   storage; then `add_discovered_function_names` / `add_referenced_function_names`.
10. `lift_function_from_image` → raw `LlirFunction`.
11. `inline_soft_helper_calls_in` (`src/ir/soft_helpers.rs`) — libgcc division helpers
    expanded to arithmetic. **Must be on raw LLIR, before ABI annotation and before SSA.**
12. `annotate_calls_in` = `ir::abi::annotate_calls` then
    `ir::call_contracts::apply_known_llir_call_contracts` — call effects recorded on the
    call itself so it participates in def/use.
13. `function_tables::collect_function_pointer_tables` (relocation-proven fn-ptr tables).
14. `session.call_graph_for(...)` + `recover_direct_callee_layouts` — bounded demand-driven
    interprocedural callee layout/prototype recovery (`ir/callee_contracts.rs`, 37 KB).
15. **Analyst overlay applied here and not earlier** (`apply_analyst_names`,
    `SymbolEnv::rename_display`) — deliberately after every name-keyed analysis, because
    renaming before them makes callee lookups miss.

### 2.4 Stage 1 — LLIR preparation (`prepare_llir_for_lowering`, `src/python_bindings/ir/pipeline.rs`)

Ordered, as code has it:

1. `normalize_definedness_and_compute_ssa`:
   `exception::with_exceptional_successors` → `ssa::compute_ssa` →
   `definedness::BitDemandOracle::analyze` → `definedness::erase_unobserved_masked_inputs`;
   if anything was erased, rebuild the graph and **recompute SSA**.
2. Provisional parameter slots: `value_number::value_number_with_parameter_slots` (semantic
   mode) or `value_number::live_in_arg_slots_llir`.
3. `recover_decbench_prototype` — prototype recovery from SSA + parameter evidence +
   declared DWARF contract + type env.
4. Registration-API `FunctionPrototypeFact` merged **only where local/debug recovery did not
   already lock** arity or output (fail-closed on conflicting evidence).
5. `types_recover::materialize_return_values` — if it changed anything, **recompute SSA a
   second time** (the prototype→return feedback edge).
6. `indirect_targets::resolve_indirect_jumps` against `image.relocated_symbol_slots()`.
7. **Structuring:** `structure::recover_verified_with_health_and_destinations(function, &ssa,
   &indirect_destinations)` → `(Region, CfgHealth)`.
8. `value_number::value_number_with_parameter_slots_and_lifetimes` (with DWARF source
   register lifetimes) → the *numbered* LLIR, definition widths, parameter slots.
9. `lock_parameter_slots_from_prototype`.

Returns `PreparedLlir { region, cfg_health, numbered, definition_widths, parameter_slots,
prototype }`. `PreparedLlir::mir()` builds verified typed MIR on demand
(`ir::mir::lower_verified_with_image`) — it is `#[allow(dead_code)]`; nothing consumes it,
because building it eagerly measured +13% on a whole-binary decompile.

### 2.5 Stage 2 — the ordered AST pass list (`run_ast_passes`, `src/python_bindings/ir/pipeline.rs:82`)

This is the canonical list. Each pass is wrapped in a `pass!` macro that (a) times it via
`FunctionProfiler`, (b) calls `ir::health::trace_pass`, and (c) prints the rendered body when
`GLAURUNG_DUMP_PASSES` is set.

Before the loop: `lower(&lf, &region, outer_name)` (`ir/ast.rs`) produces the AST, then
`exception_recover::mark_landing_pads`, then `strings_fold::collect_string_pool_from_image`
and `elf_got::elf_got_target_map`.

| # | `pass!` name | calls | file | one line |
|---|---|---|---|---|
| 0 | *(trace)* `ast_pipeline_entry` | `health::trace_pass` | `ir/health.rs` | stable health counters |
| 1 | `recover_wide_copies` | `vector_copy::recover_wide_copies` | `ir/vector_copy.rs` | rejoin 4-lane XMM load/store into one 128-bit copy, before copy-prop erases it |
| 2 | `reconstruct` | `expr_reconstruct::reconstruct` | `ir/expr_reconstruct.rs` | fold lifter temporaries into their single consumer |
| 3 | `fold_constants` | `const_fold::fold_constants` | `ir/const_fold.rs` | algebraic identity folding |
| 4 | `fold_boolean_masks` | `select_fold::fold_boolean_masks` | `ir/select_fold.rs` | collapse proven assignment diamonds into pure selects |
| 5 | `prune_dead_flags` | `dce::prune_overwritten_flags`, `dce::prune_dead_flags` | `ir/dce.rs` | per-definition first, then per-name |
| 6 | `fold_got_pointer_loads` | `got_fold::fold_got_pointer_loads` | `ir/got_fold.rs` | a GOT load becomes the address the slot will hold — **before** name resolution |
| 7 | `recover_resolved_tail_calls` | `name_resolve::resolve_names`; `function_tables::resolve_function_table_entries`; `call_args::recover_resolved_direct_tail_calls`; `call_args::recover_resolved_tail_calls` | `ir/name_resolve.rs`, `ir/function_tables.rs`, `ir/call_args.rs` | names in, then symbol-backed terminal jumps become tail calls |
| 8 | `reconstruct_args` | `call_args::reconstruct_args_with_layouts` | `ir/call_args.rs` | backward scan for argument setup, using recovered callee layouts (variadic callees deliberately excluded from the fixed-layout folder) |
| 9 | `apply_known_call_contracts` | `call_contracts::apply_recovered_callee_prototypes`, `::apply_known_call_contracts` | `ir/call_contracts.rs` | an authoritative library prototype outranks ABI liveness (Ghidra's locked FuncProto model) |
| 10 | `split_call_result_lifetimes` | `call_result_split::split_call_result_lifetimes` | `ir/call_result_split.rs` | give consumed ABI results distinct source identities |
| 11 | `canary+strings` | `strings_fold::fold_string_literals`; `canary::recognise_canary` | `ir/strings_fold.rs`, `ir/canary.rs` | |
| — | *(pre-pass)* | `aapcs64_indirect_result::indirect_result_buffer_hints` | `ir/aapcs64_indirect_result.rs` | AAPCS64 `x8` result buffer, undescribed by DWARF at -O2, declared by the ABI |
| 12 | `promote_stack_locals` | `stack_locals::promote_stack_locals_with_facts` | `ir/stack_locals.rs` | **before** naming, so `stack_N`/`local_N` cannot collide with `arg0`/`ret`/`varN`. Returns `StackLocalFacts` |
| 13 | `bind_indirect_result_buffers` | `aapcs64_indirect_result::bind_indirect_result_buffers` | same | make the promoted buffer the call's destination |
| 14 | `recognise_machine_frame` | dispatch on `CallConv` → `x86_prologue::recognise_x86_prologue` / `arm32_prologue::recognise_arm32_frame`; then `dead_stores::prune_callee_saved_spills` for *every* convention | `ir/x86_prologue.rs`, `ir/arm32_prologue.rs`, `ir/dead_stores.rs` | AArch64 has no dedicated recogniser in this match |
| 15 | `materialize_direct_output` | `direct_output::materialize_prototype_output`; `callee_return_pair::compose_pair_returns` | `ir/direct_output.rs`, `ir/callee_return_pair.rs` | only when `RecoveredOutputKind::Direct`; while the raw ABI output register still exists |
| — | *(decision)* | `value_split::should_split_unspilled_dual_role` | `ir/value_split.rs` | made here, not at entry, because widths are only explicit now |
| 16 | `split_argument_storage_reuse` | `value_split::split_argument_storage_reuse` | `ir/value_split.rs` | |
| 17 | `apply_role_names` | `naming::apply_role_names_with_parameter_roles` | `ir/naming.rs` | `arg0`, `ret`, `varN` |
| 18 | `eliminate_dead_stores` | `canary::collapse_canary_save`; (AArch64 only) `arm64_prologue::recognise_arm64_prologue`; `dead_stores::eliminate_dead_stores` | `ir/dead_stores.rs` | **after** naming so it sees `ret`/`arg0`, which kills the pre-call `%ret = 0` idiom |
| 19 | `stack_idiom+label_prune` | `stack_idiom::rematerialise_stack_ops`; `label_prune::prune_unreferenced_labels` | `ir/stack_idiom.rs`, `ir/label_prune.rs` | |

Returns `(StackLocalFacts, role_names)`.

### 2.6 Stage 3 — post-pipeline, per entry point (in `ir.rs`, after `run_ast_passes`)

- `recognise_machine_frame` again (idempotent; stack-idiom rematerialisation can expose a
  second epilogue spelling).
- `stack_locals::apply_analyst_locals` (analyst overlay on recovered slots).
- `exception_recover::recover_typed_handlers`, `::mark_int_throws_with_address_map`,
  `::recover_throws`.
- `pdb_fields::annotate_function_fields` (when a PDB cache is configured);
  `name_resolve::collect_pdb_public_symbol_map`.
- `completeness::cfg_incompleteness_note(&func, &budgets)` — a rendered note when a
  discovery budget fired, so truncation is visible in the output rather than silent.
- Type-map projection (`ir/type_maps.rs`, 44 KB): type recovery produces facts keyed by
  machine **storage** (`rdi`, a frame offset); the renderer needs them keyed by AST **role**
  (`arg0`, `ret`, `local_8`). `decbench_type_maps` for `style="decbench"`, `remap_type_map`
  for plain `types=True`. Refinements: promoted slot sizes, exact definition widths, DWARF
  source types, per-value SSA evidence, and a float-copy fixed point.
- Note: type recovery deliberately runs on the **raw** (`lf_raw`) LLIR, not the numbered one,
  because value numbering canonicalises `edi`→`rdi` and the sub-register width is *the*
  `-O0` type signal.

### 2.7 Render styles

Native `style` token (the CLI maps `plain`→`""`):

| style | renderer | file |
|---|---|---|
| `""` (plain) | `ast::render` / `ast::render_with_types` | `src/ir/ast/ctx_render.rs:639,733` |
| `"c"` | `ast::render_c` | `src/ir/ast/c_render.rs:51` |
| `"decbench"` | `render_decbench` and five progressively richer variants: `render_decbench_typed`, `…_with_output`, `…_and_prototype`, `…_and_dwarf_types`, `…_and_local_types` | `src/ir/ast/decbench_render.rs:45-130` |

Plus `src/ir/ast/dec_render.rs` + `dec_render/stmt.rs`.
`src/python_bindings/ir/decbench_render.rs` (28 KB) does the *preparing, verifying and
rendering* of one function as DecBench C, including render verification
(`take_render_verification`).

CLI: `glaurung decompile --style {plain,c,decbench}`
(`python/glaurung/cli/commands/decompile.py:226`).
`style == "decbench"` is the only mode that turns on DWARF output contracts, the DWARF type
env, the program environment, and the semantic prototype recovery — a substantial behaviour
fork, not a formatting switch.

### 2.8 Structuring and type recovery

- **Structuring:** `src/ir/structure.rs` (3,032) + `structure/` (2,604). Region tree of
  `Seq` / if-then / if-then-else / `While` / `DoWhile`, with anything unmatched preserved as
  `Region::Unstructured` carrying raw block indices — "no control flow is ever silently
  dropped". Shapes are split into `if_shape.rs`, `loop_shape.rs`, `switch_shape.rs`,
  `path_predicates.rs`, `fallback.rs`, `verify.rs`. Accounting lives in
  `structure_accounting.rs` (1,405): does the region tree account for the whole graph?
  Loop *form* recovery (for/while/do) is a separate AST-level pass in `loop_form.rs` (2,571),
  with `latch_predicate.rs`, `terminal_loop.rs`, `effectful_loop.rs`.
  Switches: `switch_ladder.rs` (1,621, the gcc -O0 comparison ladder) and
  `guarded_switch.rs` (1,263).
- **Type recovery:** `src/ir/types_recover.rs` (5,539) + `types_recover/` (2,506), feeding
  `high_variables.rs` (957), `widen.rs`, `typed_simplify.rs`, `prototype_width.rs`,
  `return_class.rs`, `expression_width.rs`. Debug-info sources: `dwarf_fields.rs` (1,502),
  `dwarf_type_env.rs`, `pdb_fields.rs`, `winapi_prototypes.rs`.
- **Verification:** `ir/verify.rs` (LLIR well-formedness), `ir/verify_defs.rs` (1,493,
  definition-before-use over the AST), `ir/health.rs` + `health_tests.rs`,
  `ir/effect_census.rs`, `ir/structure_accounting.rs`, `ir/definedness.rs`.

---

## 3. Python package map

`python/glaurung/` — 389 `.py` files, 158,845 LOC, plus the built
`_native.cpython-314-x86_64-linux-gnu.so` (47 MB; a **debug** `maturin develop` build —
release is ~1 MB).

| module / package | files | LOC | purpose |
|---|---|---|---|
| `llm/` | 313 | 133,841 | **84% of the Python package.** See §5. |
| `cli/` | 57 | 19,980 | The `glaurung` console script. See §4. |
| `windows_analysis.py` | 1 | 1,361 | Windows PE analysis helpers over structured facts |
| `bench/` | 4 | 1,215 | Deterministic no-LLM regression harness (`python -m glaurung.bench`): `harness.py` (598), `metrics.py` (374), `__main__.py` (214) |
| `types/` | 2 | 604 | Windows API prototype-bundle sync (`sync.py`, opt-in; normal analysis uses the checked-in bundle) |
| `triage.py` | 1 | 425 | Python-friendly re-exports of the Rust triage types |
| `__init__.py` | 1 | 402 | Wraps `glaurung._native`, provides Python-friendly entry points |
| `tools/` | 2 | 234 | `build_flirt_library.py` (233) — builds the FLIRT JSON library from named functions in debug binaries |
| `logging.py` | 1 | 204 | structlog configuration |
| `pdb_fetch.py` | 1 | 161 | Microsoft symbol-server PDB fetcher |
| `java/` | 2 | 143 | Java helper integration (shells to `java/` at repo root) |
| `java_classfile_policy.py` | 1 | 130 | |
| `windows_config.py` | 1 | 79 | Shared Windows pipeline config (CFG, decompile, view, project) |
| `similarity.py` | 1 | 60 | CTPH clustering helpers over the native module |
| `__main__.py` | 1 | 6 | |
| `_native/*.pyi` | 12 | — | **Generated** stubs for the extension (`tools/gen_native_stub.py`) |
| top-level `*.pyi` | 8 | — | `analysis`, `debug`, `disasm`, `engine`, `ir`, `similarity`(no), `winmd` — small hand-maintained shims *at package root*, distinct from the generated `_native/` set |

### 3.1 `python/glaurung/kb/` — **does not exist**

```
$ ls -d python/glaurung/kb
ls: cannot access 'python/glaurung/kb': No such file or directory
$ find . -type d -name kb -not -path './.venv/*' -not -path './target/*'
./python/glaurung/llm/kb
```

**CLAUDE.md is wrong.** The knowledge base is `python/glaurung/llm/kb/` — 27 files,
14,835 LOC. This matters for doc writers: the KB is a *subpackage of the LLM subsystem*, not
a peer of it, and importing it drags in the `llm` package `__init__`.

### 3.2 `python/glaurung/llm/kb/` contents

| file | LOC | purpose (from docstring) |
|---|---|---|
| `xref_db.py` | **3,557** | Persistent cross-reference database (Tier-S #154) on top of `persistent.py`'s SQLite file |
| `type_db.py` | 1,238 | Persistent type system (Tier-S #153) — user-defined/recovered structs, enums, typedefs |
| `binary_diff.py` | 834 | Function-level binary diff (#184): `same`/`changed`/added/removed |
| `windows_function_chunks.py` | 760 | Windows function chunk / thunk / tailcall facts |
| `function_identity.py` | 635 | Content-derived function identity so annotations survive a recompile |
| `windows_boundaries.py` | 591 | Confidence-ranked Windows function-boundary candidates |
| `persistent.py` | 578 | **SQLite-backed `KnowledgeBase`** — the `.glaurung` file itself |
| `structural_fingerprint.py` | 541 | Per-function fingerprints for BinDiff/Diaphora-style diff |
| `lock_state.py` | 540 | Lock/synchronization-state analysis, CFG-aware |
| `verify_recovery.py` | 521 | Recovered-source verification (#202) |
| `export.py` | 509 | Export a project as JSON / Markdown / `.h` |
| `kickoff.py` | 497 | One-shot first-touch analysis pipeline (#206) |
| `windows_callsite_facts.py` | 436 | Persisted callsite argument + path-condition facts |
| `patch.py` | 366 | Binary patcher (#185) |
| `function_disasm.py` | 364 | KB-aware disassembly with symbol annotation |
| `windows_sysinfo.py` | 284 | `NtQuerySystemInformation` dispatch facts |
| `pe_direct_calls.py` | 276 | Conservative PE direct-call xref recovery |
| `bundle.py` | 270 | One artifact carrying a binary's structure *and* annotation |
| `packer_detect.py` | 248 | Deterministic file-only packer/obfuscator heuristics (#187) |
| `windows_memory_operands.py` | 248 | Persisted memory-operand facts |
| `module_group.py` | 204 | Cross-binary / module-group reasoning for driver families |
| `provenance.py` | 121 | **The `set_by` ladder.** See §3.4 |
| `store.py` | 112 | |
| `adapters.py` | 85 | |
| `models.py` | 82 | |
| `cfg_db.py` | 928 | Persistent intra-function CFG facts for PE projects |
| `__init__.py` | 10 | |

### 3.3 The `.glaurung` SQLite schema

Schema is created by `CREATE TABLE IF NOT EXISTS` statements spread across six modules —
there is no single schema file. 35 tables:

| module (absolute path) | tables |
|---|---|
| `python/glaurung/llm/kb/persistent.py` | `schema_meta`, `binaries`, `sessions`, `kb_nodes`, `kb_edges`, `kb_node_tags`, `stdlib_bundle_loads` |
| `python/glaurung/llm/kb/xref_db.py` | `xrefs`, `function_names`, `function_identity`, `comments`, `xref_index_state`, `data_xref_index_state`, `data_labels`, `function_prototypes`, `evidence_log`, `stack_frame_vars`, `undo_log`, `bookmarks`, `journal` |
| `python/glaurung/llm/kb/cfg_db.py` | `basic_blocks`, `cfg_edges`, `cfg_index_state`, `cfg_dominance`, `cfg_dominance_index_state`, `cfg_branch_facts`, `cfg_branch_index_state` |
| `python/glaurung/llm/kb/type_db.py` | `types`, `type_field_uses` |
| `python/glaurung/llm/kb/windows_callsite_facts.py` | `callsite_argument_facts`, `callsite_path_conditions` |
| `python/glaurung/llm/kb/windows_boundaries.py` | `function_boundaries` |
| `python/glaurung/llm/kb/windows_function_chunks.py` | `function_chunk_facts` |
| `python/glaurung/llm/kb/windows_memory_operands.py` | `memory_operand_facts` |
| `python/glaurung/llm/kb/windows_sysinfo.py` | `windows_sysinfo_dispatch` |

The `*_index_state` tables are incremental-indexing bookkeeping; `undo_log` backs
`glaurung undo` / `redo`; `evidence_log` and `journal` are the audit trail.

### 3.4 `set_by` provenance — the real ladder

Defined once, in `python/glaurung/llm/kb/provenance.py` as `SET_BY_PRIORITY` (explicitly
"frozen — do not renumber, only insert into gaps"):

| `set_by` | rank |
|---|---|
| `manual` | 100 |
| `dwarf` | 80 |
| `pdb` | 80 |
| `gopclntab` | 80 |
| `stdlib` | 60 |
| `flirt` | 50 |
| `cil` | 50 |
| `ported` | 40 |
| `propagated` | 30 |
| `auto` | 20 (`AUTO_PRIORITY`) |
| `analyzer` | 20 |
| `borrowed` | 20 |

An unrecognised string ranks at `AUTO_PRIORITY`, deliberately (neither zero nor top).
`outranks()` uses `>=` — equal rank replaces, so a later `auto` pass can improve an earlier
one and an analyst can correct their own edit.

**CLAUDE.md lists seven values** (`manual/dwarf/stdlib/flirt/propagated/auto/borrowed`).
The code has **twelve**, adding `pdb`, `gopclntab`, `cil`, `ported`, `analyzer` — and gives
`dwarf`/`pdb`/`gopclntab` *equal* rank rather than an order. The module docstring also
records that before this file existed only `manual` was enforced, so `dwarf→auto`,
`dwarf→propagated`, `stdlib→auto` and `flirt→borrowed` all silently clobbered the stronger
fact.

Other `set_by` strings that appear as literals in code but are not in the priority table
(and therefore rank as `auto`): `section`, `demangled`,
`windows_project_memory_operand_index`.

---

## 4. CLI surface

Entry: `glaurung = glaurung.cli:main` (`pyproject.toml [project.scripts]`) →
`python/glaurung/cli/main.py`.

### 4.1 Global flags

`--version` is the only true global option on the top-level parser. Everything else is added
per-subcommand by `BaseCommand.add_common_arguments`
(`python/glaurung/cli/commands/base.py:49`), so it appears on **every** subcommand:

| flag | |
|---|---|
| `--format {plain,rich,json,jsonl}` | default `plain` |
| `--json` | alias for `--format json` |
| `--no-color` | forces plain |
| `--quiet` / `-q` | |
| `--verbose` / `-v` | also enables the traceback on error |

### 4.2 Lazy registry

`_REGISTRY: dict[str, tuple[str, str, str, str]]` maps
`name -> (command module, command class, formatter module, formatter class)`. Modules are
imported **only for the subcommand being run** — `create_parser(only=…)`. The comment
records why: importing all 40 eagerly cost 1,417 ms of a 1,467 ms
`import glaurung.cli` (all of it `ask` → `pydantic_ai`), making `glaurung --help` take 3.10 s
against 0.11 s for the extension itself. `python/tests/test_cli_startup_is_lazy.py` pins it.

### 4.3 The 40 subcommands

| command | file (`python/glaurung/cli/commands/`) | class | purpose (verbatim `get_help()`) |
|---|---|---|---|
| `ask` | `ask.py` | `AskCommand` | Ask natural language questions about a binary |
| `bookmark` | `bookmark.py` | `BookmarkCommand` | Add / list / delete bookmarks at VAs (the 'come back to this' workflow) |
| `cfg` | `cfg.py` | `CFGCommand` | Discover functions and build a CFG |
| `classfile` | `classfile.py` | `ClassfileCommand` | Parse a Java .class file or .jar and print methods/fields |
| `comment` | `annotate.py` | `CommentCommand` | Set / show / delete a comment at an address in a .glaurung project |
| `decompile` | `decompile.py` | `DecompileCommand` | Decompile one or more functions to pseudocode |
| `detect-packer` | `detect_packer.py` | `DetectPackerCommand` | Detect whether a binary is packed (UPX, Themida, VMProtect, ...) |
| `diff` | `binary_diff.py` | `BinaryDiffCommand` | Diff two binaries function-by-function |
| `disasm` | `disasm.py` | `DisasmCommand` | Disassemble a code window from a file |
| `explain` | `explain.py` | `ExplainCommand` | Rewrite one function via Tool #14 (`rewrite_function_idiomatic`) |
| `export` | `export.py` | `ExportCommand` | Export a .glaurung project file as JSON / Markdown / C header |
| `find` | `find.py` | `FindCommand` | Search across function names, comments, labels, types, strings, disasm |
| `frame` | `frame.py` | `FrameCommand` | List or edit a function's stack frame (slots, types, names) |
| `graph` | `graph.py` | `GraphCommand` | Export DOT/GraphViz for callgraph or function CFG (sub: `callgraph`, `cfg`) |
| `group` | `group.py` | `GroupCommand` | Cross-binary module-group analysis (shared pool tags) |
| `java` | `java.py` | `JavaCommand` | Run Java/JVM agent workflows |
| `java-recovery-report` | `java_recovery_report.py` | `JavaRecoveryReportCommand` | Recover a Java archive and print a ranked daily-use report |
| `journal` | `bookmark.py` | `JournalCommand` | Project-level dated free-form journal entries |
| `kickoff` | `kickoff.py` | `KickoffCommand` | One-shot analysis: detect-packer + triage + analyze + propagate + recover-structs |
| `label` | `annotate.py` | `LabelCommand` | Name a data address in a .glaurung project, with an optional C type |
| `locks` | `locks.py` | `LocksCommand` | Lock-state inventory for a function (primitive-complete, with a coverage footer) |
| `luac` | `luac.py` | `LuacCommand` | Recognise Lua bytecode (.luac / LuaJIT) and surface header info |
| `name-func` | `name_func.py` | `NameFuncCommand` | Suggest a name for a function via LLM + decompiled pseudocode |
| `patch` | `patch.py` | `PatchCommand` | Patch hex bytes at a VA to produce a new binary |
| `pe` | `pe.py` | `PeCommand` | Inspect Windows PE/COFF resources and metadata (sub: `resources`, `manifest`, `version`) |
| `proto` | `annotate.py` | `ProtoCommand` | Set / show a function prototype in a .glaurung project |
| `redo` | `undo.py` | `RedoCommand` | Re-apply the most recent undone analyst KB writes |
| `rename` | `annotate.py` | `RenameCommand` | Name a function in a .glaurung project (reaches `decompile --db`) |
| `repl` | `repl.py` | `ReplCommand` | Interactive analysis session with persistent KB |
| `strings` | `strings.py` | `StringsCommand` | Detailed string extraction, stats, and distributions |
| `strings-xrefs` | `string_xrefs.py` | `StringsXrefsCommand` | List strings with their data_read xref sites (IDA-style strings window) |
| `symbols` | `symbols.py` | `SymbolsCommand` | List symbols from a binary (best-effort) |
| `triage` | `triage.py` | `TriageCommand` | Triage a file for security analysis |
| `types` | `types.py` | `TypesCommand` | Manage generated type/prototype data (sub: `sync`) |
| `undo` | `undo.py` | `UndoCommand` | Revert the most recent analyst KB writes |
| `verify-recovery` | `verify_recovery.py` | `VerifyRecoveryCommand` | Compile-check rewritten source; optionally diff bytes against a target binary |
| `view` | `view.py` | `ViewCommand` | Tri-pane view: hex bytes, disasm, and pseudocode at a VA |
| `windows` | `windows.py` | `WindowsCommand` | Run Windows PE analysis helpers — **4,027 LOC, ~30 subcommands** (see below) |
| `windows-risk` | `windows_risk.py` | `WindowsRiskCommand` | Summarize PE/Windows imports, string xrefs, and risky function shapes (2,652 LOC) |
| `xrefs` | `xrefs.py` | `XrefsCommand` | List xrefs to/from a VA (callers, readers, writers, jumps) |

**Aliases / shared modules:** `rename`/`comment`/`label`/`proto` all live in `annotate.py`;
`undo`/`redo` in `undo.py`; `bookmark`/`journal` in `bookmark.py`. There are **no hidden or
dev-only commands** — the registry is the whole surface, and `--help` lists all 40.

Three commands print directly and use `TriageFormatter` as a no-op placeholder: `repl`,
`graph`, and everything else registered with an empty formatter module.

### 4.4 `glaurung windows` subcommands (from `add_parser(...)` in `windows.py`)

`diff`, `ioctl`, `analyst`, `analyst-loop`, `analyst-notebook`, `corpus-guard`, `preflight`,
`project-facts`, `project-xrefs`, `project-reachability`, `project-callgraph-diff`,
`project-guard-diff`, `project-chunks`, `project-boundary-diff`, `project-start`,
`symbol-ranges`, `memory-access`, `memory-access-diff`, `data-tables`, `data-table-diff`,
`project-proto-diff`, `bootstrap-project`, `blocker-tasks`, `symbol-similarity`,
`function-similarity`, `runner-review`, `promotion-plan`, `promotion-apply`, `pipeline`.

This single command is larger than most of the rest of the CLI put together and is where the
Windows-port work has landed.

### 4.5 Formatters

`python/glaurung/cli/formatters/`: `base.py` (`OutputFormat`), `triage.py` (604),
`strings.py` (470), `disasm.py` (343), `cfg.py` (271), `ask.py` (223), `symbols.py` (185),
`decompile.py` (39, pass-through), `name_func.py` (22).

Support modules: `cli/cache.py` (221), `cli/kb_names.py` (278), `cli/func_ref.py` (113),
`cli/utils/formatting.py` (132), and two large private helpers
`commands/_layer0_prepass.py` (778) and `commands/_kernel_struct_pack.py` (163).


---

## 5. LLM subsystem

Root: `/home/mjbommar/projects/personal/glaurung/python/glaurung/llm/`
**313 `.py` files, 133,841 LOC.** No non-`.py` files anywhere in the tree (no prompt/config data files).

| Subpackage | Files | LOC |
|---|---:|---:|
| `llm/` (top level) | 15 | 3,406 |
| `llm/agents/` | 29 | 15,916 |
| `llm/tools/` | 242 | 99,684 |
| `llm/kb/` | 27 | 14,835 |

### 5.1 Module tree

#### `llm/` top level (15 files, 3,406 LOC)

| File | LOC | Purpose (first line of module docstring) |
|---|---:|---|
| `__init__.py` | 74 | "LLM integration for Glaurung. Compatibility exports for legacy tests plus new memory-first APIs." Lazy `__getattr__` exporting only `LLMConfig`, `get_config`, `MemoryContext`, `create_memory_agent`; sets `PYDANTIC_DISABLE_PLUGINS=1`; warns if `pydantic_ai < _PYDANTIC_AI_MIN`. |
| `config.py` | 193 | "Configuration wrapper for LLM providers (compat)." Auto-loads `.env` via `dotenv.find_dotenv(usecwd=True)` at import. |
| `context.py` | 78 | Defines `Budgets` ("Execution and output budgets for tools and evidence collection") and `MemoryContext` ("Context passed to tools/agents"). |
| `coverage.py` | 70 | "Coverage / assumptions footer for analyses." Single class `CoverageFooter`. |
| `cwe_sweep.py` | 330 | "CWE-class-driven discovery sweep (L3)." |
| `evidence.py` | 436 | "Evidence models and builders (compat)." Static annotation of functions/callsites/strings/CFG edges — no LLM call. |
| `finding_critic.py` | 267 | "Self-critique pass for VulnerabilityFinding (L2)." |
| `finding_verifier.py` | 368 | "Cite-or-discard finding verifier (L4)." |
| `findings.py` | 289 | "Structured vulnerability-finding schema for Glaurung's LLM agents." |
| `findings_runner.py` | 276 | "Drive an LLM agent through a vuln-discovery pass that returns a structured `FindingsReport` instead of free-text." |
| `logging.py` | 144 | "Logging integration for LLM operations (compat)." `LLMLogger`, `logged_agent_run` decorator. |
| `runtime_classifier.py` | 206 | "Classify discovered functions as application code vs. compiler runtime." |
| `tool_routing.py` | 260 | "Per-question tool routing for the memory agent (L5)." |
| `usage_limits.py` | 102 | "Build pydantic-ai `UsageLimits` from Glaurung's LLMConfig." |
| `usage_tracker.py` | 313 | "Session-wide LLM usage + cost aggregation (F4)." |

#### `llm/agents/` (29 files, 15,916 LOC)

Only **14 of 29** import `pydantic_ai` at all. The other 15 are deterministic workflows that live in `agents/` by convention.

*Real LLM agents (import `pydantic_ai`):*

| File | LOC | Purpose |
|---|---:|---|
| `memory_agent.py` | 1,849 | (no docstring) The tool registry: `register_analysis_tools`, `_apply_tool_filter`, `_register_analysis_tools_inner`, `create_memory_agent`. |
| `memory_foundation.py` | 56 | (no docstring) `create_foundation_agent(model, output_type=str, system_prompt=None)` — builds the base `Agent[MemoryContext, T]` with the default narrative prompt + a `@agent.system_prompt` KB-context injector. |
| `base.py` | 435 | "Base protocol and shared functionality for analysis agents." Home of `ModelHyperparameters`, `AnalysisResult`, `TerminationReason`, `ExecutionState`, `BaseAnalysisAgent` (Protocol), `AgentMetrics`. **Does not import `pydantic_ai`.** |
| `factory.py` | 259 | "Factory module for creating analysis agents with different strategies." |
| `single_pass.py` | 302 | "Optimized single-pass agent implementation." |
| `iterative.py` | 313 | "Iterative refinement wrapper for agents." |
| `iterative_refinement.py` | 617 | "Iterative refinement agent with safety mechanisms and progressive strategies." |
| `specialized.py` | 367 | "Specialised pydantic-ai agents for common RE workflows." 7 structured agents. |
| `function_name.py` | 170 | "Function naming assistant (memory-first compatible)." |
| `summary_memory.py` | 86 | "Memory-first summarizer agent with BinarySummary output." |
| `ioc_validator.py` | 200 | "IOC validation agent (memory-first compatible)." |
| `ioc_validator_v2.py` | 195 | "IOC validation agent V2 (compat)." |
| `java.py` | 255 | "Specialized pydantic-ai agents for Java/JVM workflows." |
| `java_toolsets.py` | 270 | "Focused Java/JVM toolsets for provider-facing pydantic-ai agents." |
| `windows_pretty_lift_agent.py` | 61 | (no docstring) `create_windows_pretty_lift_agent` + `WINDOWS_PRETTY_LIFT_SYSTEM_PROMPT`. |

*Deterministic workflows in `agents/` that do NOT import `pydantic_ai`* (13 files, 10,655 LOC) — every one's docstring opens "Deterministic Windows … workflow":
`windows_patch_diff_review.py` (1,474), `windows_validation_planning.py` (1,336), `windows_triage_worklist.py` (1,188), `windows_evidence_review.py` (1,074), `windows_target_pipeline.py` (1,005), `windows_corpus_curator.py` (879), `windows_rule_authoring.py` (777), `windows_interactive_analyst.py` (764), `windows_sink_to_gate_review.py` (754), `windows_functionization_review.py` (435), `windows_analyst_notebook_review.py` (313), `windows_analyst_command_loop.py` ("Bounded command-loop wrapper for the Windows interactive analyst", 155), `java_runner.py` ("Convenience runners for Java/JVM pydantic-ai agents", 178 — dispatches into `java.py`, which does call the model).
Plus `__init__.py` (149, pure lazy-export table, 54 `_LAZY_EXPORTS` entries).

#### `llm/tools/` (242 files, 99,684 LOC)

| Group | Files | LOC | Notes |
|---|---:|---:|---|
| `windows_*` | 113 | 57,932 | Deterministic PE/Windows fact extraction, packet composition, project-DB queries. Largest single file in the whole subsystem: `windows_function_pretty_lift.py` (6,046). |
| `java_*` | 57 | 25,383 | JVM/archive indexing, decompile, recovery, ABI compare. Largest: `java_decompile_archive.py` (1,344), `java_recovery_report.py` (1,329), `java_repair_decompiled_source.py` (1,220). |
| `minecraft_*` | 3 | 853 | `detect_archive`, `fetch_mappings`, `extract_bundled_server`. |
| `pe_*` | 3 | 718 | `pe_list_resources`, `pe_decode_version_info`, `pe_view_manifest`. |
| other | 66 | ~14,800 | See below. |

Infrastructure: `base.py` (342, no docstring) defines `ToolMeta`, `MemoryTool[In,Out]` ABC, `tool_to_pyd_ai`, `default_tool_strict_for_model`, `set_default_tool_strict`, `default_tool_strict_for` (context manager). `_llm_helpers.py` (191) — "Shared helpers for LLM-backed tools"; `LLMUnavailable`, `can_call_llm`, `in_running_event_loop`, `run_structured_llm`, `_require_llm_flag`.

**Exactly 28 tool modules actually construct an LLM call** (via `_llm_helpers.run_structured_llm` or a direct `pydantic_ai.Agent`). They carry a numbered "Tool #N" docstring convention:
`classify_string_purpose` (#1), `classify_constant` (#2), `name_string_literal` (#3), `classify_loop_idiom` (#4), `name_local_variable` (#5), `describe_call_site` (#6), `recover_struct_layout` (#7), `recover_enum` (#8), `recover_error_model` (#9), `infer_function_signature` (#10), `hypothesize_protocol` (#11), `recover_cli_grammar` (#12), `classify_function_role` (#13), `rewrite_function_idiomatic` (#14), `synthesize_docstring` (#15), `propose_function_name_post_rewrite` (#16), `verify_semantic_equivalence` (#17), `cluster_functions_into_modules` (#18), `reconcile_function_identity` (#19), `reconcile_global_naming` (#20), `infer_build_system` (#21), `write_readme_and_manpage` (#22), `audit_recovered_source` (#23), `translate_language` (#24), `explain_rewrite_delta` (#25), plus `suggest_function_name`, `propose_types_for_function`, `analyze_recursively` ("Tool 21: recursive-triage orchestrator").

All remaining ~212 tool modules are deterministic: `view_*` (7: disassembly/entropy/entry/function/hex/strings/symbols, all no docstring), `search_*` (4), `map_*` (4: elf_plt/elf_got/pe_iat/symbol_addresses, all no docstring), `list_*` (3), `find_*`/blob scanners (`find_encoded_blobs` 795, `find_structured_blobs` 954, `extract_archive` 590, `find_embedded_executables`), `hash_file`, `import_triage`, `kb_add_note`, `search_kb`, `rename_in_kb`, `xrefs`, `diff_functions`, `detect_crypto_usage`, `identify_compiler_and_runtime`, `decompile_function`, `get_string_xrefs`, `scan_until_byte`, `search_byte_pattern`, `verify_recovery_tool`, `annotate_binary`.

#### `llm/kb/` (27 files, 14,835 LOC) — the SQLite knowledge base; no LLM calls

See §3.2 and §3.3 for the file table and the SQLite schema.

---

### 5.2 `config.py` — actual defaults

`/home/mjbommar/projects/personal/glaurung/python/glaurung/llm/config.py`, 193 LOC. `@dataclass class LLMConfig`:

| Field | Type | Default | Env override (in `__post_init__`) |
|---|---|---|---|
| `default_model` | `str` | `"openai:gpt-5.4-mini"` | `GLAURUNG_LLM_MODEL` |
| `fallback_model` | `str` | `"anthropic:claude-haiku-4-5"` | — |
| `summarizer_model` | `str` | `"openai:gpt-5.4-mini"` | — |
| `risk_scorer_model` | `str` | `"openai:gpt-5.4-mini"` | — |
| `ioc_model` | `str` | `"openai:gpt-5.4-mini"` | — |
| `openai_service_tier` | `str` | `"flex"` | `GLAURUNG_OPENAI_SERVICE_TIER` |
| `openai_api_key` | `Optional[str]` | `None` | `OPENAI_API_KEY` |
| `anthropic_api_key` | `Optional[str]` | `None` | `ANTHROPIC_API_KEY` |
| `google_api_key` | `Optional[str]` | `None` | `GOOGLE_API_KEY` |
| `gemini_api_key` | `Optional[str]` | `None` | `GEMINI_API_KEY` |
| `temperature` | `float` | `0.3` | `GLAURUNG_LLM_TEMPERATURE` |
| `max_tokens` | `Optional[int]` | `None` | — |
| `default_request_limit` | `int` | `12` | `GLAURUNG_REQUEST_LIMIT` |
| `default_input_tokens_limit` | `int` | `400_000` | `GLAURUNG_INPUT_TOKENS_LIMIT` |
| `default_total_tokens_limit` | `int` | `500_000` | `GLAURUNG_TOTAL_TOKENS_LIMIT` |
| `default_max_output_tokens` | `int` | `32_768` | `GLAURUNG_MAX_OUTPUT_TOKENS` |
| `enable_logging` | `bool` | `True` | — |
| `log_level` | `str` | `"INFO"` | — |
| `fallback_on_error` | `bool` | `True` | — |
| `cache_responses` | `bool` | `False` | — |

Methods: `create_agent(system_prompt, model=None, output_type=None, **kwargs)` (writes the resolved key back into `os.environ` before constructing `pydantic_ai.Agent`), `available_models() -> dict[str,bool]`, `preferred_model()`. Module singleton via `get_config()` / `set_config()`.

**Dead / unread fields (grep-verified):** `risk_scorer_model`, `fallback_model`, `fallback_on_error`, and `cache_responses` are defined and never read anywhere in `python/`. `fallback_model` is used only *inside* `preferred_model()` itself. `summarizer_model` has exactly one reader (`agents/summary_memory.py:36`); `ioc_model` has three (`agents/ioc_validator.py:66,143`, `agents/ioc_validator_v2.py:77`). `preferred_model()` has 10 call sites and is the de-facto model resolver for tools and the Java/Windows agents; `create_agent()` is unused by the memory-agent path.

**`ModelHyperparameters` is NOT in `config.py`** — it lives in `/home/mjbommar/projects/personal/glaurung/python/glaurung/llm/agents/base.py:28`, a `pydantic.BaseModel`:

| Field | Default | Constraint |
|---|---|---|
| `temperature` | `0.3` | `ge=0.0, le=2.0` |
| `top_p` | `None` | `ge=0.0, le=1.0` |
| `top_k` | `None` | `ge=1` |
| `max_tokens` | `None` | `ge=1` |
| `presence_penalty` | `None` | `ge=-2.0, le=2.0` |
| `frequency_penalty` | `None` | `ge=-2.0, le=2.0` |
| `seed` | `None` | — |

`to_model_kwargs(*, model_name=None)` (base.py:51) emits only non-`None` fields, then at base.py:76-81:

```python
if model_name and model_name.startswith(("openai:", "openai-responses:")):
    from ..config import get_config
    tier = get_config().openai_service_tier
    if tier and tier != "default":
        existing = kwargs.get("extra_body") or {}
        existing["service_tier"] = tier
        kwargs["extra_body"] = existing
```

`to_model_settings(*, model_name=None)` = `to_model_kwargs` minus `top_k` (not in pydantic-ai's portable `ModelSettings`).

Two other sites build `extra_body` **by hand rather than through `to_model_kwargs`**:
- `/home/mjbommar/projects/personal/glaurung/python/glaurung/llm/finding_critic.py:173-175`
- `/home/mjbommar/projects/personal/glaurung/python/glaurung/llm/tools/_llm_helpers.py:159-161` and `/home/mjbommar/projects/personal/glaurung/python/glaurung/llm/tools/suggest_function_name.py:266-268` (these two check only `openai:`, not `openai-responses:`, and do not exempt `tier == "default"`).

---

### 5.3 Agents

**pydantic-ai constructs used across all of `llm/`** (import-count): `Agent` ×19, `RunContext` ×6, `ModelSettings` ×6, `Tool` ×2, `UsageLimits` ×1, `RunUsage` ×1, `RequestUsage` ×1, `ModelRetry` ×1. No `Toolset`, no `MCPServer`, no graph/`pydantic_graph` usage. `deps_type=MemoryContext` throughout.

**Foundation.** `create_foundation_agent(model=None, *, output_type=str, system_prompt=None)` (`agents/memory_foundation.py:26`) is the single constructor everything routes through. Its default persona (`build_system_prompt()`) is three lines:
> "You are a binary analysis assistant that reasons over a structured knowledge base (KB). / Tools may add nodes and edges to the KB. Prefer using KB search to ground answers. / Provide concise, technical, evidence-based conclusions."

plus a dynamic `@agent.system_prompt` (`inject_kb_context`) emitting `Context: file={path}, kb_nodes={n}, kb_edges={m}`. When no provider key is available it silently constructs with `model="test"`.

**`create_memory_agent(model=None, *, tool_filter=None) -> Agent[MemoryContext, str]`** (`agents/memory_agent.py:1833`) = foundation + `register_analysis_tools`.

**Strategy layer** (`agents/factory.py`): `AgentStrategy` enum `{SINGLE_PASS="single_pass", ITERATIVE="iterative", AUTO="auto"}`; `UnifiedAgentConfig` (`auto_complexity_threshold=3`, `auto_confidence_requirement=0.7`); `AnalysisAgentFactory` with `create_agent`, `create_fast_single_pass_agent`, `create_safe_iterative_agent`, `analyze_with_best_strategy`; `create_analysis_agent(...)`.
- `SinglePassConfig` (`agents/single_pass.py:20`): `optimize_context=True`, `fail_fast=False`, `pre_populate_kb=True`, `include_metadata=True`, `timeout_seconds=60.0`.
- `IterativeConfig` (`agents/iterative_refinement.py:21`): `max_iterations=5` (`le=20`), `min_confidence=0.7`, `max_total_seconds=120.0` (`le=600`), `max_total_tokens=100_000`, `allow_repeated_tools=1`, `detect_state_loops=True`, `pattern_detection_length=3`.

**Structured output types.** `agents/specialized.py` builds 7 agents through `_make_agent`, each its own persona + Pydantic `output_type`:

| Factory | `output_type` |
|---|---|
| `build_function_explain_agent` | `FunctionExplanation` |
| `build_binary_triage_agent` | `BinaryTriageReport` |
| `build_vulnerability_hunt_agent` | `VulnerabilityHuntReport` (of `PotentialVulnerability`) |
| `build_security_posture_agent` | `SecurityPostureReport` |
| `build_call_graph_navigator_agent` | `CallPathFinding` |
| `build_rename_sweep_agent` | `RenameSweepReport` (of `RenameDecision`) |
| `build_string_cluster_agent` | `StringClusterReport` (of `StringCluster`) |
| `build_taint_trace_agent` | `TaintTraceReport` (of `TaintStep`) |

Other structured agents: `SuggestedFunctionName` (`agents/function_name.py`), `BinarySummary` (`agents/summary_memory.py`), `IOCValidationResult` (`ioc_validator.py`) / `IOCValidationOutput` (`ioc_validator_v2.py`), `PrettyLift` (`windows_pretty_lift_agent.py`), `FindingsReport` (`findings_runner.py`), `_CriticVerdict` (`finding_critic.py:63`).

**Java agents** (`agents/java.py`): `build_java_triage_agent` → `JavaTriageAssessment`, `build_java_security_agent` → `JavaSecurityAssessment`, `build_java_recovery_agent` → `JavaRecoveryAssessment` (all containing `JavaFinding`). `_make_java_agent` pre-seeds the system prompt by calling `prime_java_agent_context` inside a dynamic `@agent.system_prompt`, and registers a *profile-scoped* toolset instead of the full catalog.

**Personas defined as named constants:** `WINDOWS_PRETTY_LIFT_SYSTEM_PROMPT` (`windows_pretty_lift_agent.py`, ~20 lines), `_CRITIC_SYSTEM_PROMPT` (`finding_critic.py:34`, "You are a skeptical security-review critic", with an explicit true/partial/false rubric and a ≤200-char critique constraint), `_FINDINGS_SYSTEM_PROMPT` (`findings_runner.py`), `SYSTEM_PROMPT` (`summary_memory.py`). Everything else is an inline `system_prompt=(...)` literal.

---

### 5.4 Tool registration

**`register_analysis_tools`** — `/home/mjbommar/projects/personal/glaurung/python/glaurung/llm/agents/memory_agent.py:580`:

```python
def register_analysis_tools(
    agent: Agent[MemoryContext, AgentOutputT],
    *,
    model_name: str | None = None,
    tool_filter: set[str] | None = None,
) -> Agent[MemoryContext, AgentOutputT]:
```

Flow: resolve strictness (`default_tool_strict_for_model(model_name)` → `False` for `anthropic:`, `True` otherwise; `None` when `model_name` is omitted, which falls back to `GLAURUNG_TOOL_STRICT`), enter `default_tool_strict_for(target)`, call `_register_analysis_tools_inner(agent)`, then `_apply_tool_filter` if a filter was given.

**`_apply_tool_filter(agent, tool_filter)`** (memory_agent.py:627) is a *post-hoc prune*, not a pre-filter: it registers all tools first, then reaches into `agent._function_toolset._tools` (private pydantic-ai API, with `.tools` fallback) and `pop()`s every key not in the filter. Any failure is a `log.warning` and the agent runs with the full surface. **Unmatched names are silently ignored.**

**Actual tool count: 219**, not the ~163/164 the code's own comments claim (`memory_agent.py:667` says "164 `tool_to_pyd_ai` calls"; `tool_routing.py:3`, `tools/base.py:57` and `test_strict_tool_default.py:3` all say "~163 tools"):
- **55** registered via `tool_agent.tool(<local async wrapper>, name="…")` — thin `RunContext`-taking wrappers around `build_tool()`.
- **164** registered via `agent._function_toolset.add_tool(tool_to_pyd_ai(build_X()))`.

The 55 wrapper names (analysis core):
`analyze_recursively, annotate_binary, decompile_function, detect_crypto_usage, diff_functions, enumerate_archive, extract_archive_all, extract_archive_entry, extract_elf_section, extract_pe_overlay, find_base64_blobs, find_compressed_blobs, find_embedded_executables, find_embedded_images, find_hex_blobs, find_ini_blobs, find_json_blobs, find_pem_blocks, find_plist_blobs, find_xml_blobs, get_string_xrefs, hash_file, identify_compiler_and_runtime, import_triage, kb_add_note, kickoff_analysis, list_calls_from_function, list_functions, list_suspicious_imports, list_xrefs_from, list_xrefs_to, map_elf_got, map_elf_plt, map_pe_iat, map_symbol_addresses, name_function, propose_types_for_function, recursive_unpack, rename_in_kb, scan_until_byte, scan_xor_encoded_strings, search_byte_pattern, search_kb, search_strings, search_symbols, try_xor_brute, verify_compile, verify_runtime, view_disassembly, view_entropy, view_entry, view_function, view_hex, view_strings, view_symbols`

The 164 direct registrations are entirely prefix-grouped: **113 `windows_*`**, **46 `java_*`**, **3 `pe_*`** (`pe_list_resources`, `pe_decode_version_info`, `pe_view_manifest`), **3 `minecraft_*`**. There is no per-group registration function and no way to opt a group out other than `tool_filter`.

**Separate registry:** `register_java_agent_tools(agent, *, profile=None, tool_names=None, strict=True)` (`agents/java_toolsets.py:232`) with `JavaAgentToolProfile = Literal["triage","security","recovery","deobfuscation"]` → `JAVA_AGENT_TOOLSETS` sizes **16 / 18 / 19 / 17**. Unlike `_apply_tool_filter`, this one **raises** `ValueError(f"unknown Java agent tool: {name}")` on an unmatched name.

---

### 5.5 Routing — L1…L5

The L-naming **is real in code**, as docstring/comment tags. `grep -rnoP '\bL[1-5]\b' python/glaurung/llm/ python/glaurung/cli/`:

| Tag | Where it appears |
|---|---|
| **L1** | `cli/commands/ask.py:323` only — a single comment `# Optional structured-output side pass (L1) or full L3 sweep.` **There is no L1-named module, class, or function.** CLAUDE.md's "L1 findings runner" corresponds to `llm/findings_runner.py`, whose own docstring never says L1. |
| **L2** | `finding_critic.py` (module docstring "Self-critique pass for VulnerabilityFinding (L2)"), `findings.py` ×4, `findings_runner.py`, `finding_verifier.py`, `cwe_sweep.py`, `ask.py` ×3 |
| **L3** | `cwe_sweep.py` (docstring "CWE-class-driven discovery sweep (L3)"), `findings.py` ×2, `findings_runner.py` ×2, `ask.py` ×2 |
| **L4** | `finding_verifier.py` ("Cite-or-discard finding verifier (L4)"), `finding_critic.py` ×7, `findings.py` ×5, `findings_runner.py` ×2, `cwe_sweep.py`, `ask.py` ×3 |
| **L5** | `tool_routing.py` ("Per-question tool routing for the memory agent (L5)"), `memory_agent.py` ×3, `agents/factory.py` ×2, `findings_runner.py`, `ask.py` ×3 |

**Router implementation** — `/home/mjbommar/projects/personal/glaurung/python/glaurung/llm/tool_routing.py`. Deterministic substring matching, no LLM call.
- `@dataclass(frozen=True) class Intent(name, tools, keywords, keyword_re=None)`
- `_INTENTS: tuple[Intent, ...]` — 6 intents in priority order: `vuln_discovery` (24 keywords), `triage_summary` (13), `function_walk` (7), `import_audit` (6), `string_audit` (6), `broad_discovery` (0 keywords = fallback, must be last by construction).
- Tool groups: `_CORE_TRIAGE_TOOLS` (7), `_DECOMPILE_TOOLS` (3), `_GRAPH_TOOLS` (7), `_VULN_FACT_TOOLS` (6 `windows_project_*`).
- Public API: `route_for_question(question) -> Intent`, `select_tools_for_question(question) -> tuple[str,...]`, `list_intents()`, `intent_summary()` (for `--show-routing`).

**Two groups are dead code:** `_GRAPH_TOOLS` and `_VULN_FACT_TOOLS` are defined but referenced by no `Intent` — `vuln_discovery` and `broad_discovery` inline their own 5-tuple instead.

**The router's tool names largely do not match the registry.** Grep-verified against both the 55 wrapper names and every `ToolMeta(name=…)` in `llm/tools/`:

| Router name | Exists as a tool? | Registered on the memory agent? |
|---|---|---|
| `hash_file`, `annotate_binary`, `list_functions`, `decompile_function`, `analyze_recursively`, `map_pe_iat`, `map_elf_plt`, `map_elf_got`, `map_symbol_addresses` | yes | yes |
| `describe_call_site` | yes (`tools/describe_call_site.py`, Tool #6) | **no** |
| `extract_strings`, `list_imports`, `list_exports`, `detect_packer`, `list_basic_blocks`, `list_callers`, `list_callees` | **no — not a tool name anywhere in the repo** | no |
| 6 × `windows_project_*` in `_VULN_FACT_TOOLS` | yes | yes (but no intent uses them) |

Because `_apply_tool_filter` drops unmatched names silently, the effective surviving tool count per intent is:

| Intent | names listed | tools that actually survive |
|---|---:|---:|
| `vuln_discovery` | 15 | **7** |
| `triage_summary` | 7 | **3** |
| `function_walk` | 12 | **5** |
| `import_audit` | 4 | **2** (`annotate_binary`, `map_pe_iat`) |
| `string_audit` | 2 | **1** (`annotate_binary`) |
| `broad_discovery` | 15 | **7** |

`findings_runner.py:110-113` comments "the broad-discovery subset (~17 tools) is enough for vuln hunting" — the real number is 7.
The routing test does not catch this: `python/tests/test_tool_routing.py:147` asserts `surviving <= {"list_imports","annotate_binary"}` (a *subset* check) plus `assert surviving`, so it passes with only `annotate_binary` present.

**Two entry points apply routing:**
1. `cli/commands/ask.py:512-542` — opt-in via `--route`, escape via `--all-tools`.
2. `llm/findings_runner.py:99-118` — `--route`/`--all-tools`, **plus an unconditional fallback**: if no filter was set and `model_name.startswith(("openai:","openai-responses:"))`, routing is forced on regardless, to stay under the 128-tool cap. Since the project default is `openai:gpt-5.4-mini`, **the findings pass is always routed by default**, and therefore always runs with ≤7 tools.

**`GLAURUNG_AGENT_ROUTE` does not exist.** `grep -rn GLAURUNG_AGENT_ROUTE` over `*.py`, `*.rs`, `*.md` returns exactly one hit: `CLAUDE.md:368`. There is likewise **no `--tools t1 t2` flag**, despite `tool_routing.py:11` documenting one.

---

### 5.6 Cost guards — F1…F7

`F1`–`F7` are comment tags, not identifiers. All seven are present:

| Tag | Meaning in code | Location |
|---|---|---|
| **F1** | Per-`Agent.run()` budget defaults on `LLMConfig` + their env parsing | `config.py:63`, `config.py:98` |
| **F2** | Per-call `request_limit` / `tool_calls_limit` caps | `findings_runner.py:184` (`request_limit=8`), `finding_critic.py:176` (`request_limit=2, tool_calls_limit=0, total_tokens_limit=50_000`), `agents/iterative.py:103`, `kb/binary_diff.py:96,317,804` |
| **F3** | `max_tokens` sizing | `findings_runner.py:160` (4096 → `default_max_output_tokens()` = 32_768), `finding_critic.py:163` (512 → 4_096), `usage_limits.py:101` |
| **F4** | Session-wide cost telemetry via `usage_tracker` | `usage_tracker.py:1`, `findings_runner.py:199`, `finding_critic.py:193`, `agents/single_pass.py:212`, `agents/iterative_refinement.py:423` |
| **F5** | Cost-budget circuit breaker | `usage_tracker.py:20,109` (`CostBudgetExceeded(RuntimeError)`), `cwe_sweep.py:188,197,227,273,284`, `kb/binary_diff.py:796` |
| **F6** | Skip the critic when L4 already demoted the finding | `finding_critic.py:237,250`, `kb/binary_diff.py:788` |
| **F7** | Incremental partial-result writes so a killed sweep leaves recoverable state | `cwe_sweep.py:185,201,229,269,303` |

**Named artifacts:**
- `build_usage_limits(model_name=None, *, request_limit, input_tokens_limit, output_tokens_limit, total_tokens_limit, tool_calls_limit, count_tokens_before_request=False)` and `default_max_output_tokens()` — `usage_limits.py`. `model_name` is explicitly documented as informational only (no per-provider branching).
- `usage_tracker.py`: `PRICE_PER_MILLION_USD` (USD/M `(input, output)`: `openai:gpt-5.4-mini` `(0.15, 0.60)`, `openai:gpt-5.5` `(5.00, 15.00)`, `openai:gpt-5.5-mini` `(0.25, 1.00)`, `anthropic:claude-haiku-4-5` `(1.00, 5.00)`, `anthropic:claude-sonnet-4-6` `(3.00, 15.00)`, `anthropic:claude-opus-4-7` `(15.00, 75.00)`, `test` `(0.0, 0.0)`); `estimate_cost_usd`, `UsageRecord`, `UsageTracker` (`budget_usd=None`, `set_budget_usd`, `record` which raises `CostBudgetExceeded`, `total_cost_usd`, `per_model_breakdown`), `get_tracker()`, `reset_tracker()`. Explicitly opt-in — call sites must call `.record(...)`.
- `context.py` `Budgets` (non-token execution budgets): `max_functions=5`, `max_blocks=2048`, `max_instructions=50_000`, `timeout_ms=200`, `max_read_bytes=10_485_760`, `max_file_size=104_857_600`, `max_disasm_window=4096`, `max_results=200`.
- `agents/base.py`: `TerminationReason.TOKEN_LIMIT`, `AgentMetrics.count_tokens`, `ExecutionState.get_repeat_count` / `has_pattern_loop` / `is_making_progress` (loop guards).

**`max_parallel`** exists in exactly one place: `sweep_binary(binary_path, args, *, classes=None, applies_to_filter=None, max_parallel=1, partial_dir=None)` — `cwe_sweep.py:176`, implemented as `asyncio.Semaphore(max_parallel)` at line 195. **No CLI flag exposes it**; `--max-parallel` does not exist anywhere in `python/glaurung/cli/`.

`DEFAULT_CWE_CLASSES` (`cwe_sweep.py:50`) holds 7 `CWEClassSpec(id, title, prompt, applies_to="any")` entries: **CWE-121, CWE-134, CWE-190, CWE-416, CWE-401, CWE-476, CWE-787**, filtered by `_select_classes(classes, applies_to_filter)` on `applies_to ∈ {"any","userland","kernel"}`.

---

### 5.7 Environment variables read under `llm/`

| Variable | File | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | `config.py:83` (read), `create_agent` (written back) | OpenAI credential |
| `OPENAI_API_KEY` | `agents/summary_memory.py:40` | second, independent check — forces `model="test"` when absent |
| `ANTHROPIC_API_KEY` | `config.py:84` / `create_agent` | Anthropic credential |
| `GOOGLE_API_KEY` | `config.py:85` / `create_agent` | Gemini credential |
| `GEMINI_API_KEY` | `config.py:86` / `create_agent` | Gemini credential (alt) |
| `GLAURUNG_LLM_MODEL` | `config.py:87` | overrides `default_model` |
| `GLAURUNG_OPENAI_SERVICE_TIER` | `config.py:89` | `flex` \| `default` \| `priority` |
| `GLAURUNG_LLM_TEMPERATURE` | `config.py:92` | float; bad value → `logger.warning`, ignored |
| `GLAURUNG_REQUEST_LIMIT` | `config.py:99` | F1 |
| `GLAURUNG_INPUT_TOKENS_LIMIT` | `config.py:100` | F1 |
| `GLAURUNG_TOTAL_TOKENS_LIMIT` | `config.py:101` | F1 |
| `GLAURUNG_MAX_OUTPUT_TOKENS` | `config.py:102` | F1 |
| `PYDANTIC_DISABLE_PLUGINS` | `llm/__init__.py` | **written** (`setdefault("1")`), never read — suppresses pydantic's logfire plugin loader at import |
| `GLAURUNG_TOOL_STRICT` | `tools/base.py:146` | `"0"` globally relaxes pydantic-ai strict tool schemas; default `"1"` |
| `GLAURUNG_REQUIRE_LLM` | `tools/_llm_helpers.py:56` | truthy turns silent heuristic fallbacks into `LLMUnavailable` |
| `GLAURUNG_TYPES_DIR` | `kb/type_db.py:1004` | first search location for bundled stdlib type JSON |
| `ASB_REPO` | `tools/windows_surface_metadata.py:150` | root for ASB `data/kg/pe-sources.yaml` / `pe-gates.yaml` |
| `WINDOWS_CORPUS_ROOT` | `tools/windows_build_corpus.py:133` | corpus root fallback for `--corpus-root` |
| `GLAURUNG_PROJECT_ROOT` | `tools/windows_build_corpus.py:134` | project root fallback for `--project-root` |

`.env` is auto-loaded at `config.py` import time via `dotenv.find_dotenv(usecwd=True)` + `load_dotenv(path, override=False)`; a missing `python-dotenv` degrades to environment-only mode.

---

### 5.8 LLM-invoking CLI commands

Only **5** of the 41 files in `python/glaurung/cli/commands/` actually reach a model:

| File | LOC | Subcommand | LLM entry points |
|---|---:|---|---|
| `ask.py` | 752 | `ask` | `AnalysisAgentFactory.create_fast_single_pass_agent` / `create_safe_iterative_agent` / `analyze_with_best_strategy`; `cwe_sweep.sweep_binary`; `findings_runner.run_findings_pass`; `tool_routing.route_for_question`; `usage_tracker.get_tracker` |
| `explain.py` | 623 | `explain` | Tool #10 `infer_function_signature`, #13 `classify_function_role`, #14 `rewrite_function_idiomatic`, + `_layer0_prepass.run_layer0_prepass` (which calls `name_local_variable`, `name_string_literal`, `classify_constant`) |
| `name_func.py` | 249 | `name-func` | `SuggestFunctionNameTool.run(use_llm=True)`; exits 2 if neither `OPENAI_API_KEY` nor `ANTHROPIC_API_KEY` is set |
| `java.py` | 209 | `java {triage,security,recovery}` | `agents.java_runner.run_java_agent_analysis` → `agent.run_sync` |
| `repl.py` | 941 | `repl` | only the interactive `ask` verb: `create_memory_agent()` + `agent.run_sync` |

`ask.py` LLM/guard flags (exact argparse strings): `--agent`, `--strategy`, `--max-iterations`, `--min-confidence`, `--timeout`, `--show-tools`, `--show-plan`, `--model`, `--max-read-bytes`, `--max-file-size`, `--quick`, `--max-functions`, `--max-instructions`, `--disasm-window`, `--findings-json PATH`, `--skip-critique`, `--cwe-sweep`, `--cwe-sweep-applies {any,userland,kernel}`, `--route`, `--show-routing`, `--all-tools`, `--max-cost-usd USD` (F5), `--usage-log` (F4 JSONL). There is **no `--critic`**, **no `--tools`**, and **no `--max-parallel`**.

`explain.py`: `--func`, `--range-start/-end`, `--style {c,rust,go}`, `--no-types`, `--no-roles`, `--with-layer0`/`--no-layer0` (help: "10-30 LLM calls per function (~$0.20-$0.50)"), `--timeout-ms`, `--pdb-cache`, `--cache-dir`, `--fidelity {tldr,annotated}`, `--suspicious-va`, `--require-llm`. No `--model`.

**`windows.py` (4,027 LOC) and `windows_risk.py` (2,652 LOC) make no LLM call.** `windows.py` imports four `llm.agents.windows_*` modules and ~25 `llm.tools.windows_*` modules; none of the four agent modules imports `pydantic_ai` or calls `run_sync`, their docstrings read "Deterministic Windows … workflow", and there is no `--model` flag in the file. **CLAUDE.md's "`windows analyst`" is a deterministic pipeline, not an LLM code path.**

---

### 5.9 Names in CLAUDE.md not found in `llm/` code

| CLAUDE.md name | Verdict | Exact grep |
|---|---|---|
| `GLAURUNG_AGENT_ROUTE=1` | **Does not exist.** Only hit in the whole repo is `CLAUDE.md:368`. | `grep -rn "GLAURUNG_AGENT_ROUTE" --include="*.py" --include="*.md" --include="*.rs" .` |
| "L1 findings runner" | **No L1 identifier.** `L1` appears once, as a comment in `cli/commands/ask.py:323`. | `grep -rnoP '\bL1\b' python/glaurung/llm/ python/glaurung/cli/` |
| `risk_scorer_model` | **Defined, never read.** | `grep -rn "risk_scorer_model" --include="*.py" python/` → 1 hit |
| "`--route` … ≤30 tools/question" | `--route` exists; the ≤30 bound is asserted only on the *declared* tuple length (`test_tool_routing.py:31`), and the largest intent declares 15. Effective surviving counts are 1–7. | — |
| "Anthropic's 4M-tokens/min ceiling" | **Not represented in code.** No rate-limit constant, retry-after handling, or 4M literal. | `grep -rni "tokens/min\|rate.limit\|4_000_000" python/glaurung/llm/` |
| "`--tools t1 t2`" | **No such flag** (documented in `tool_routing.py:11` too). | `grep -rn '"--tools"' python/glaurung/cli/` → 0 |
| "lower `max_parallel` in `sweep_binary`" | Parameter exists with default `1`, **not reachable from any CLI flag**. | `grep -rn "max_parallel" python/glaurung/` → 4 hits, all `llm/cwe_sweep.py` |
| "128-tool cap" / "~163 tools" | Cap logic exists; the count is stale — the real registered surface is **219**. | 55 + 164 |
| `ModelHyperparameters.to_model_kwargs` "wired in `LLMConfig`" | Method exists and does add `extra_body`, but lives in `llm/agents/base.py:28`, **not** `config.py`. | `grep -rn "class ModelHyperparameters" python/` |
| `openai:gpt-5.4-mini`, `anthropic:claude-haiku-4-5`, `flex`, `GLAURUNG_LLM_MODEL`, `GLAURUNG_OPENAI_SERVICE_TIER`, `tool_filter=`, `register_analysis_tools` | **All confirmed present and matching.** | — |

---

## 6. Environment variables

Exhaustive inventory of environment variables **read** anywhere in the tree (`python/`, `src/`, `tools/`, `scripts/`, `benches/`, `fuzz/`, `tests/`, `build.rs`, `conftest.py`). Sorted alphabetically; ASCII order puts `_NT_SYMBOL_PATH` last.

Two mechanisms are indirect and easy to miss:

- **`.env` loading.** `/home/mjbommar/projects/personal/glaurung/python/glaurung/llm/config.py:22-33` calls `find_dotenv(usecwd=True)` + `load_dotenv(..., override=False)` at *module import*. Any variable in the table can therefore arrive from a `.env` file found by walking up from the cwd, but a real environment variable always wins (`override=False`). `python-dotenv>=1.0.0` is a hard dependency (`pyproject.toml:38`).
- **Whole-environment snapshot.** `/home/mjbommar/projects/personal/glaurung/src/symbolic/ordered_trace.rs:1177` calls `std::env::vars()` and records *every* variable whose name starts with `GLAURUNG_`, `IOCTLANCE_` or `BITWUZLA_` into the ordered-trace manifest. That is a recording, not a branch.

| var | read in (absolute `file:line`) | default | purpose |
|---|---|---|---|
| `ANGR_PYTHON` | `tools/roundtrip3.py:109` | unset → angr column silently empty | Interpreter that can `import angr`, used to shell out to `tools/angr_decompile.py`. |
| `ANTHROPIC_API_KEY` | `python/glaurung/llm/config.py:85`, `:143`; `python/tests/test_java_agents_live.py:27`; `python/tests/test_llm_naming_live.py:32` | unset | Anthropic credential. Also **written back** at `config.py:124` into `os.environ` before constructing a pydantic-ai `Agent`. |
| `ASB_REPO` | `python/glaurung/llm/tools/windows_surface_metadata.py:150` | unset → sibling `agentic-security-bot/`, then `../agentic-security-bot/` | Root of the external `agentic-security-bot` checkout holding Windows surface metadata. |
| `BITWUZLA_LIB_DIR` | `build.rs:23`, `:34` | none — **panics** if `solver-bitwuzla` is on and `GLAURUNG_BITWUZLA_TYPECHECK_ONLY` is unset | Directory holding pinned Bitwuzla 0.9.1; emits `rustc-link-search`/`rustc-link-lib`. |
| `BITWUZLA_RUNTIME_LIB_DIRS` | `build.rs:52` | `BITWUZLA_LIB_DIR` | `PATH`-style list of runtime library dirs baked into the rpath. |
| `CARGO_FEATURE_SOLVER_BITWUZLA` | `build.rs:8` | set by cargo | Early-return guard: `build.rs` does nothing unless `solver-bitwuzla` is enabled. |
| `CARGO_MANIFEST_DIR` | compile-time `env!()` at ~70 sites (`src/testing.rs:96`, `src/analysis/cfg.rs:293`, `benches/ir_lift.rs:683`, …) | provided by cargo | Repo root for fixture/sample path resolution in Rust tests and benches. Baked in at compile time. |
| `CARGO_TARGET_DIR` | `scripts/decbench-local-gate.sh:74`; `scripts/feature-build-gate.sh:54,103,104` | `$PWD/target` | Build output directory the gates probe. |
| `DECBENCH_COLUMN` | `tools/decbench_evaluate_sharded.py:77`; `tools/decbench_redecompile_tree.py:60` | `glaurung-<sha>` | Which decompiler column an evaluation writes into. **Written** at `decbench_evaluate_sharded.py:96`. |
| `DECBENCH_DIR` | `tools/decbench_holdout.py:68`; `tools/decbench_matrix.py:136`; `python/tests/test_decbench_glaurung_backend.py:42`; `scripts/decbench-local-gate.sh:114` | `/nas4/data/workspace-infosec/decbench` | Where the out-of-tree DecBench fork is checked out. Gate of the `decbench` pytest marker. |
| `DECBENCH_PYTHON` | `tools/decbench_matrix.py:152,165` | `<DECBENCH_DIR>/.venv/bin/python`, then `.../python3` | Interpreter with DecBench and its backend deps installed. |
| `DECBENCH_SAMPLE_TREE` | `tools/decbench_redecompile_tree.py:49` | `~/projects/personal/decbench-sample-set-glaurung-tree` | Root of the DecBench sample-set tree to re-decompile. |
| `EXTBENCH_GHIDRA` | `tools/extbench/config.py:32` | `~/.cache/ghidra-releases/ghidra_12.1.2_PUBLIC` | Ghidra install for the external-decompiler bench. |
| `EXTBENCH_GLAURUNG` | `tools/extbench/config.py:31` | `<repo>/.venv/bin/glaurung` | Glaurung CLI under test in the external bench. |
| `EXTBENCH_PYTHON` | `tools/extbench/config.py:26` | `/nas4/data/workspace-infosec/decbench/.venv/bin/python` | Interpreter that can `import angr` and `import pyghidra`. |
| `EXTBENCH_RETDEC` | `tools/extbench/config.py:35` | `~/.local/opt/retdec/bin/retdec-decompiler`, else `which` | RetDec binary for the external bench. |
| `EXTBENCH_SAMPLES` | `tools/extbench/config.py:40` | `/nas4/data/binary-analysis/glaurung/binaries-small` | Sample binaries the external bench runs over. |
| `GEMINI_API_KEY` | `python/glaurung/llm/config.py:87,148`; `python/tests/test_java_agents_live.py:29` | unset | Gemini credential; **written back** at `config.py:128`. |
| `GHIDRA_INSTALL_DIR` | `tools/compare_decompilers.py:165`; `tools/roundtrip3.py:95` | `/opt/ghidra`, then `sorted(/opt/ghidra_*)` | Ghidra install for the three-way comparison. |
| `GHIDRA_PYTHON` | `tools/roundtrip3.py:94` | unset → Ghidra column empty | Interpreter with `pyghidra`. |
| `GLAURUNG_ACCOUNT_STRUCTURE` | `src/ir/structure.rs:165`; `src/python_bindings/ir/session.rs:208` | unset | Presence-only. `[account] <va>: N finding(s)` structuring-accounting diagnostics to stderr. Presence also **disables the render cache**. |
| `GLAURUNG_ALLOW_MISSING_SOLVERS` | `scripts/feature-build-gate.sh:146` | unset → missing solver libs fail the gate | Waiver: accept shipping a solver feature unbuilt. |
| `GLAURUNG_ALLOW_NO_METRICS` | `scripts/decbench-local-gate.sh:287` | unset → a metrics-less run fails | Waiver: accept shipping unmeasured. |
| `GLAURUNG_ALLOW_STALE` | `tools/build_guard.py:106` | unset → `SystemExit` on a stale `.so` | Equivalent to `--allow-stale`. |
| `GLAURUNG_ARGV_LOG` | wrapper generated in `python/tests/test_decbench_glaurung_backend.py:119` | test-local | Path the fake `glaurung` shim writes `sys.argv[1:]` to. |
| `GLAURUNG_AXEYUM_CNF_SNAPSHOT_DIR` | `src/symbolic/solver/axeyum_backend.rs:680` | unset | Directory for CNF snapshots. |
| `GLAURUNG_AXEYUM_DIRECT_DELTA` | `src/symbolic/solver/axeyum_backend/config.rs:68` | `false` | Direct-delta solving. `src/symbolic/ordered_replay.rs:843` **requires** exactly `1` for native ordered replay. |
| `GLAURUNG_AXEYUM_INTERNAL_AND_FLATTENING` | `.../axeyum_backend/config.rs:204` | `false` | Incremental positive-AND flattening. |
| `GLAURUNG_AXEYUM_PROFILE_DIR` | `src/symbolic/solver/axeyum_backend.rs:674` | unset | Directory for Axeyum backend profiles. |
| `GLAURUNG_AXEYUM_PROGRESS_CHECK_LIMIT` | `src/symbolic/solver/mod.rs:205` | `u64::MAX` | Deterministic work budget for the Axeyum backend. |
| `GLAURUNG_AXEYUM_REPLAY_SAT_CACHE` | `.../axeyum_backend/config.rs:173` | policy string | SAT-cache policy during replay; ordered replay requires `1`. |
| `GLAURUNG_AXEYUM_SOURCE_REPO` | `src/symbolic/ordered_replay.rs:225` | unset | Axeyum source checkout, recorded in the trace's runtime configuration. |
| `GLAURUNG_AXEYUM_WARM_MAX_ASSERTIONS_PER_PATH` | `.../axeyum_backend/config.rs:36` | `512` | Warm-reuse assertion ceiling per path. |
| `GLAURUNG_AXEYUM_WARM_MAX_LIVE_PATHS` | `.../axeyum_backend/config.rs:32` | `9` | Warm-reuse live-path ceiling. |
| `GLAURUNG_AXEYUM_WARM_OWNER_TRANSFER` | `.../axeyum_backend/config.rs:135` | off | Warm-solver owner transfer; ordered replay requires `0`. |
| `GLAURUNG_AXEYUM_WARM_REUSE` | `.../axeyum_backend/config.rs:50` | `Adaptive` | Warm solver-instance reuse policy (`off`/`auto`/`adaptive`/`lineage`/else `Snapshot`). |
| `GLAURUNG_AXEYUM_WARM_SERIAL_SIBLING_REUSE` | `.../axeyum_backend/config.rs:154` | off | Serial sibling reuse; ordered replay requires `1`. |
| `GLAURUNG_AXEYUM_WARM_TIMEOUT_COLD_RETRY` | `.../axeyum_backend/config.rs:72` | `false` | Retry a timed-out warm check cold; ordered replay requires `0`. |
| `GLAURUNG_AXEYUM_WARM_TIMEOUT_CONTINUE` | `.../axeyum_backend/config.rs:83` | **`true`** | Continue a timed-out warm check. |
| `GLAURUNG_BIN` | `tools/build_guard.py:118`; `tools/decbench_glaurung.py:45`; `tools/roundtrip3.py:72`; `tools/decbench_redecompile_tree.py:54` | `<repo>/.venv/bin/glaurung`, then `which glaurung` | Which `glaurung` CLI the harnesses shell out to. |
| `GLAURUNG_BITWUZLA_TERMINATION_POLL_LIMIT` | `src/symbolic/solver/mod.rs:206` | no limit | Deterministic work budget for the Bitwuzla backend. |
| `GLAURUNG_BITWUZLA_TYPECHECK_ONLY` | `build.rs:24` | unset | Build `solver-bitwuzla` **without** linking Bitwuzla so `cargo check` covers the module. A real build then fails at link time. |
| `GLAURUNG_CACHE_DIR` | `python/glaurung/cli/cache.py:204` | unset → caching disabled | Append-only decompile / name-function cache. Precedence: `--cache-dir` > env > disabled. |
| `GLAURUNG_CANONICAL_MODEL_CHOICE` | `src/symbolic/concretization.rs:174` | unset | **Legacy alias** for `GLAURUNG_CONCRETIZATION_POLICY`. |
| `GLAURUNG_CHECK_TIMEOUT_MS` | `src/symbolic/solver/mod.rs:230` | `250`; must be 1..=60000 or **panic** | Per-SMT-check timeout. |
| `GLAURUNG_CONCRETIZATION_POLICY` | `src/symbolic/concretization.rs:173` | `AnyModel`; invalid **panics** | Symbolic-engine concretization policy. |
| `GLAURUNG_DECBENCH_JOBS` | `tools/decbench_matrix.py:713`; `scripts/decbench-local-gate.sh:88` | 4 or available CPUs | Concurrent isolated DecBench cells. |
| `GLAURUNG_DUMP_PASSES` | `src/analysis/exception.rs:124`; `src/ir/exception_recover.rs:133`; `src/ir/high_variables.rs:37`; `src/ir/value_number/coalesce.rs:699`; `src/program/environment.rs:720,801`; `src/program/format_environment.rs:182,573,623,638`; `src/python_bindings/ir.rs:325,338`; `.../ir/callee_contracts.rs:638,716`; `.../ir/decbench_render.rs:224,241`; `.../ir/dwarf_contracts.rs:149,154`; `.../ir/pipeline.rs:101,461,499`; `.../ir/type_maps.rs:610`; `.../ir/session.rs:209` | unset | **The main decompiler diagnostic switch.** Presence-only; dumps the pass list, LLIR stages, prepared AST, rendered C, callee/DWARF contracts, recovered declaration types. Also disables the render cache. |
| `GLAURUNG_DUMP_QUERIES` | `src/symbolic/solver/mod.rs:636` | unset | Dump SMT queries. |
| `GLAURUNG_DUMP_SHADOW_SPLITS` | `src/symbolic/solver/mod.rs:723` | unset | Dump shadow-mode solver splits. |
| `GLAURUNG_ENGINE_CACHE_FACTORIAL_MODE` | `src/symbolic/ordered_replay.rs:839` | parsed by `FactorialMode::parse` | Native ordered-replay factorial mode; pins the required values of seven other `GLAURUNG_*` vars at `:841-857`. |
| `GLAURUNG_ENGINE_CONSTRAINT_CACHE` | `src/symbolic/solver/constraint_cache.rs:53` | `Off` (`off`/`exact`/`structural`) | Engine constraint-cache policy. |
| `GLAURUNG_FAIR_SHADOW` | `src/symbolic/solver/mod.rs:568` | unset | Fair shadow-mode comparison between backends. |
| `GLAURUNG_FIXTURE_GO` | `tools/fixture_harness.py:251` | `"0"` — **off** | Enable the five Go fixtures (176-180). Off because no baseline records those lanes. |
| `GLAURUNG_FIXTURE_JOBS` | `tools/fixture_harness.py:989` | `max(1, min(8, cpu_count()-1))` | Concurrent fixture-matrix workers. |
| `GLAURUNG_FIXTURE_OBSERVED` | `python/tests/test_decompiler_fixture_matrix.py:67` | unset | Dump the observed matrix JSON so a CI failure is actionable. Set in `decompiler-fixtures.yml:134`. |
| `GLAURUNG_FIXTURE_RUST` | `tools/fixture_harness.py:229` | `"1"` — **on** | Include the `.rs` fixture lanes. |
| `GLAURUNG_FIXTURE_TMPDIR` | `tests/decompiler_fixtures/manifest.py:3885` (ahead of `TMPDIR`) | unset → `TMPDIR`, then system default | Writable scratch for isolated fixture build/exec. Its *length* matters — it sits in the worker environment block, which shifts the stack (`tools/diff_decompile.py:2568`). |
| `GLAURUNG_FIXTURE_TOOLCHAIN` | `tools/fixture_toolchain.py:70` | `"docker"`; only `docker`/`host` | Pinned Docker toolchain vs. explicit host-compiler opt-out. Fail-closed. |
| `GLAURUNG_FLIRT_LIB` | `src/flirt/mod.rs:103` | `./data/sigs/glaurung-base.x86_64.flirt.json`, then no-op | Which FLIRT-lite signature library to load. |
| `GLAURUNG_INPUT_TOKENS_LIMIT` | `python/glaurung/llm/config.py:101` | `400_000` | Per-`Agent.run()` input-token ceiling (F1). |
| `GLAURUNG_IOCTL_DEBUG` | `src/analysis/ioctl_surface.rs:370` | unset | Jump-table IOCTL recovery diagnostics. |
| `GLAURUNG_IOCTL_FIXTURES` | `src/analysis/ioctl_surface.rs:723`; `python/tests/test_ioctl_surface.py:15`; `python/tests/test_disasm_operands.py:20` | unset → tests silently return/skip | Directory of reference `.sys` driver fixtures (**not committed**). |
| `GLAURUNG_JVM_TOOLS_JAR` | `python/glaurung/java/helper.py:22` | builds `java/glaurung-jvm-tools` with Maven | Prebuilt JVM helper fat JAR. |
| `GLAURUNG_LIVE_LLM` | `python/tests/test_java_agents_live.py:22`; `test_llm_naming_live.py:28` | unset → both files skip | Must be exactly `"1"` to run live-model tests. |
| `GLAURUNG_LLM_MODEL` | `python/glaurung/llm/config.py:88` | `openai:gpt-5.4-mini` | Default `provider:model`. |
| `GLAURUNG_LLM_TEMPERATURE` | `python/glaurung/llm/config.py:92` | `0.3` | Model temperature. |
| `GLAURUNG_LOWERING_STACK_MB` | `src/ir/ast/lower_region.rs:754` | `LOWERING_STACK_BYTES`; clamps below 16 MB with a warning | Thread stack reserved for `ast::lower` (recursion ~18 KB per region level, worst case 442 levels). |
| `GLAURUNG_MAX_FILE_SIZE` | `python/glaurung/__init__.py:222` | unset; `max(existing, env)` — **raise-only** | Global file-size cap for triage-backed commands. |
| `GLAURUNG_MAX_OUTPUT_TOKENS` | `python/glaurung/llm/config.py:103` | `32_768` | Per-request output ceiling (F1). |
| `GLAURUNG_MAX_READ_BYTES` | `python/glaurung/__init__.py:228` | raise-only | Global read-byte cap. |
| `GLAURUNG_OPENAI_SERVICE_TIER` | `python/glaurung/llm/config.py:89` | `flex` | `flex`/`default`/`priority` → `extra_body={"service_tier": …}`. |
| `GLAURUNG_ORDERED_TRACE_DIR` | `src/symbolic/ordered_trace.rs:148` | unset → no trace | Root for ordered symbolic-execution trace artifacts. |
| `GLAURUNG_PASS_HEALTH` | `src/ir/health.rs:352`; `src/ir/ast/float_gate.rs:317`; `src/python_bindings/ir/session.rs:210` | unset | One schema-versioned JSON pass-health record to stderr. Also disables the render cache. |
| `GLAURUNG_PASS_STATS` | `src/ir/pass_stats.rs:40` | unset | Per-pass attempt/match counters streamed to stderr (no atexit dump, so a killed lane still yields data). |
| `GLAURUNG_PDB_CACHE` | `python/glaurung/pdb_fetch.py:39` | first usable local dir in `_NT_SYMBOL_PATH`, then `~/.cache/glaurung/symbols` | Microsoft-style PDB cache directory. |
| `GLAURUNG_PERF_BASELINE` | `tools/perf_gate.py:62` | `<repo>/bench/perf_baseline.json` | Override the committed perf baseline so the gate's failure states are testable. |
| `GLAURUNG_PIPELINE_PROFILE` | `src/decompile/profile.rs:46,83`; `src/python_bindings/ir/session.rs:211` | unset | Per-stage wall-time profiling. Also disables the render cache. |
| `GLAURUNG_PROJECT_ROOT` | `python/glaurung/llm/tools/windows_build_corpus.py:134,221` | unset → `None`; set-but-missing raises | Default `.glaurung` project root for the Windows build-corpus tool. |
| `GLAURUNG_PYTHON` | `tools/build_guard.py:144,222` | `<repo>/.venv/bin/python` | Synced interpreter for fixture-harness workers, so `dectest` cannot silently run under system Python. |
| `GLAURUNG_REAL_BIN` | wrapper generated at `python/tests/test_decbench_glaurung_backend.py:120` | test-local | Real binary the argv-logging shim `execv`s. |
| `GLAURUNG_REDECOMP_FORCE` | `tools/decbench_redecompile_tree.py:62` | unset; must be exactly `"1"` | Force re-decompilation of already-processed binaries. |
| `GLAURUNG_REQUEST_LIMIT` | `python/glaurung/llm/config.py:99` | `12` | Per-run request ceiling (F1). |
| `GLAURUNG_REQUIRE_LLM` | `python/glaurung/llm/tools/_llm_helpers.py:56` | `False` | Makes a missing model a hard error instead of a silent heuristic fallback. **Written** by `cli/commands/explain.py:380` for `--require-llm`. |
| `GLAURUNG_REQUIRE_TOOLCHAINS` | `src/testing.rs:61,181` | unset → absent compiler is a printed SKIP; `"1"` **panics** | Asserts a provisioned machine is not silently skipping fixture-compiling Rust tests. Set to `"1"` in `test-suite.yml:82,112`. |
| `GLAURUNG_RUN_DECBENCH` | `scripts/decbench-local-gate.sh:53,69,231` | empty → lanes 4-5 skipped | Opt-in to the DecBench/Joern gate lanes; same as `--decbench`. |
| `GLAURUNG_RUN_NETWORK_TESTS` | `python/tests/test_windows_type_sync.py:127` | unset; must be `"1"` | Opt-in to the real NuGet Windows-metadata sync test. |
| `GLAURUNG_SHADOW_DIFF` | `src/symbolic/solver/mod.rs:1167` | unset | Report shadow-mode disagreements between solver backends. |
| `GLAURUNG_SMT_SOLVER` | `src/symbolic/solver/pipe.rs:62` | candidate order `bitwuzla`, `z3`, `cvc5` | Prepend a custom SMT-solver executable to the pipe-backend candidate list. |
| `GLAURUNG_TOOL_STRICT` | `python/glaurung/llm/tools/base.py:146` | `"1"`; only `"0"` relaxes | Whether pydantic-ai tool schemas are registered strict. |
| `GLAURUNG_TOTAL_TOKENS_LIMIT` | `python/glaurung/llm/config.py:102` | `500_000` | Per-run total-token ceiling (F1). |
| `GLAURUNG_TRACE_ORACLE_VERSION` | `src/symbolic/ordered_trace.rs:1218` | `"linked-runtime-unreported"` | Z3 runtime version recorded in the trace's trusted-oracle block. |
| `GLAURUNG_TYPES_DIR` | `python/glaurung/llm/kb/type_db.py:1004` | `./data/types`, then `<package root>/data/types` | Generated type/prototype data directory. |
| `GLAURUNG_VERIFY_DEFS` | `src/python_bindings/ir/decbench_render.rs:597`; `.../ir/session.rs:212` | unset → violation comments **not** spliced | Splices def-before-use violation comments into rendered C. Verification always runs; this only gates the echo (so it cannot leak into benchmark submissions). **Written** by `tests/decompiler_fixtures/defuse.py:123` and `structural.py:65`. |
| `GLAURUNG_VERSION` | `tools/decbench_glaurung.py:58` | `git rev-parse --short=12 HEAD` | Binds metric artifacts to an exact revision. |
| `GLAURUNG_WINDOWS_ANALYSIS_CONFIG` | `python/glaurung/windows_config.py:68` | `--analysis-config` > env > `.glaurung/windows-analysis.yaml` > defaults | Shared PE/PDB analysis YAML. Unknown keys fail closed with `ValueError`. |
| `GLAURUNG_Z3_RLIMIT` | `src/symbolic/solver/mod.rs:204` | no limit | Z3 deterministic rlimit. |
| `GOOGLE_API_KEY` | `python/glaurung/llm/config.py:86,147`; `test_java_agents_live.py:30` | unset | Google credential; **written back** at `config.py:126`. |
| `JAVA_HOME` | *generated Java fixture source*, `python/tests/test_java_agents_live.py:69` | n/a | Not a Glaurung read — the synthesized Java program writes it to `marker.txt`. |
| `OPENAI_API_KEY` | `python/glaurung/llm/config.py:84,142`; `llm/agents/summary_memory.py:40`; `tools/decbench_external_agentic.py:636`; two live tests | unset; `summary_memory.py:40` falls back to `"test"` | OpenAI credential for the project-default model; **written back** at `config.py:122`. |
| `PATH` | `tools/build_guard.py:250-251`; `python/tests/test_decbench_matrix_ratchet.py:370,387` | worker env **pins** `/usr/local/bin:/usr/bin:/bin` | Only read to be deliberately *replaced*: the environment block's size shifts the initial stack and changes what an uninitialised local reads. |
| `PROBE_OUT` | `python/tests/test_cli_startup_is_lazy.py:52` | test-local | Where the lazy-import probe subprocess writes its module list. |
| `TMPDIR` | `tools/scratch.py:66`; `tests/decompiler_fixtures/manifest.py:3885`; `tools/decbench_redecompile_tree.py:63` (**required**, bare `os.environ[...]`) | `tools/scratch.py` **writes** `~/.cache/glaurung/tmp` if unset | Keeps the project off the shared, quota'd 62 GB `/tmp` tmpfs. `tools/scratch.py` is dev tooling and deliberately NOT imported by the `glaurung` package. |
| `XDG_CACHE_HOME` | `python/glaurung/types/sync.py:36` | `~/.cache` | Base for `<cache>/glaurung/windows-api-metadata`. |
| `_NT_SYMBOL_PATH` | `python/glaurung/pdb_fetch.py:42` | `""` | Windows-style symbol path; first `;`/`*`-separated existing local dir becomes the PDB cache when `GLAURUNG_PDB_CACHE` is unset. |

### 6.1 Grouping

**Glaurung-specific (`GLAURUNG_*`) — 56 read.**
*Decompiler diagnostics / instrumentation (presence-only, output-neutral):* `GLAURUNG_ACCOUNT_STRUCTURE`, `GLAURUNG_DUMP_PASSES`, `GLAURUNG_IOCTL_DEBUG`, `GLAURUNG_PASS_HEALTH`, `GLAURUNG_PASS_STATS`, `GLAURUNG_PIPELINE_PROFILE`, `GLAURUNG_VERIFY_DEFS`. (All seven also disable the render cache when set.)
*Decompiler resources / limits:* `GLAURUNG_FLIRT_LIB`, `GLAURUNG_LOWERING_STACK_MB`, `GLAURUNG_MAX_FILE_SIZE`, `GLAURUNG_MAX_READ_BYTES`, `GLAURUNG_CACHE_DIR`, `GLAURUNG_PDB_CACHE`, `GLAURUNG_TYPES_DIR`, `GLAURUNG_JVM_TOOLS_JAR`, `GLAURUNG_WINDOWS_ANALYSIS_CONFIG`, `GLAURUNG_PROJECT_ROOT`.
*LLM:* `GLAURUNG_LLM_MODEL`, `GLAURUNG_LLM_TEMPERATURE`, `GLAURUNG_OPENAI_SERVICE_TIER`, `GLAURUNG_REQUEST_LIMIT`, `GLAURUNG_INPUT_TOKENS_LIMIT`, `GLAURUNG_TOTAL_TOKENS_LIMIT`, `GLAURUNG_MAX_OUTPUT_TOKENS`, `GLAURUNG_REQUIRE_LLM`, `GLAURUNG_TOOL_STRICT`, `GLAURUNG_LIVE_LLM`.
*Symbolic engine (22, all behind the non-default `symbolic` feature):* the twelve `GLAURUNG_AXEYUM_*`, plus `GLAURUNG_CHECK_TIMEOUT_MS`, `GLAURUNG_Z3_RLIMIT`, `GLAURUNG_BITWUZLA_TERMINATION_POLL_LIMIT`, `GLAURUNG_SMT_SOLVER`, `GLAURUNG_ENGINE_CONSTRAINT_CACHE`, `GLAURUNG_ENGINE_CACHE_FACTORIAL_MODE`, `GLAURUNG_CONCRETIZATION_POLICY`, `GLAURUNG_CANONICAL_MODEL_CHOICE`, `GLAURUNG_ORDERED_TRACE_DIR`, `GLAURUNG_TRACE_ORACLE_VERSION`, `GLAURUNG_FAIR_SHADOW`, `GLAURUNG_SHADOW_DIFF`, `GLAURUNG_DUMP_QUERIES`, `GLAURUNG_DUMP_SHADOW_SPLITS`.
*Test/gate/harness plumbing:* `GLAURUNG_ALLOW_MISSING_SOLVERS`, `GLAURUNG_ALLOW_NO_METRICS`, `GLAURUNG_ALLOW_STALE`, `GLAURUNG_ARGV_LOG`, `GLAURUNG_BIN`, `GLAURUNG_BITWUZLA_TYPECHECK_ONLY`, `GLAURUNG_DECBENCH_JOBS`, `GLAURUNG_FIXTURE_GO`, `GLAURUNG_FIXTURE_JOBS`, `GLAURUNG_FIXTURE_OBSERVED`, `GLAURUNG_FIXTURE_RUST`, `GLAURUNG_FIXTURE_TMPDIR`, `GLAURUNG_FIXTURE_TOOLCHAIN`, `GLAURUNG_IOCTL_FIXTURES`, `GLAURUNG_PERF_BASELINE`, `GLAURUNG_PYTHON`, `GLAURUNG_REAL_BIN`, `GLAURUNG_REDECOMP_FORCE`, `GLAURUNG_REQUIRE_TOOLCHAINS`, `GLAURUNG_RUN_DECBENCH`, `GLAURUNG_RUN_NETWORK_TESTS`, `GLAURUNG_VERSION`.

**Third-party / provider keys and external-tool locations.** `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `GEMINI_API_KEY` (all four also **written back** by `llm/config.py:122-128`); `ANGR_PYTHON`, `GHIDRA_PYTHON`, `GHIDRA_INSTALL_DIR`; `ASB_REPO`; `BITWUZLA_LIB_DIR`, `BITWUZLA_RUNTIME_LIB_DIRS`; `DECBENCH_DIR`, `DECBENCH_PYTHON`, `DECBENCH_COLUMN`, `DECBENCH_SAMPLE_TREE`; the five `EXTBENCH_*`.

**Standard / system.** `TMPDIR`, `PATH`, `XDG_CACHE_HOME`, `_NT_SYMBOL_PATH`, `CARGO_TARGET_DIR`, `CARGO_MANIFEST_DIR` (compile-time), `CARGO_FEATURE_SOLVER_BITWUZLA`, `JAVA_HOME` (fixture-internal only). `HOME`, `LC_ALL`, `TZ` are **written, never read** — pinned by `tools/build_guard.py:246-249` (`HOME=/`, `LC_ALL=C`, `TZ=UTC`).

### 6.2 Written but never read

- `GLAURUNG_STACK_PAD` — `tools/build_guard.py:255-257`. Pure padding: a `"0"*N` string sized so the worker's whole environment block is a fixed 4096 bytes, keeping stack offsets constant across checkouts. Nothing reads it.
- `PYDANTIC_DISABLE_PLUGINS` — `python/glaurung/llm/__init__.py:15`. Consumed by pydantic, not by Glaurung.
- `SOME_UNRELATED_EXPORT` — `python/tests/test_decompiler_arch_roundtrip.py:297`, a deliberate junk variable proving the worker env is scrubbed.

### 6.3 Documented but not read anywhere in code

| var | documented at | status |
|---|---|---|
| `GLAURUNG_AGENT_ROUTE` | `CLAUDE.md:368` | **no reader** — routing is only reachable via `--route` or `tool_filter=`. |
| `GLAURUNG_DECBENCH_KIT` | `docs/test-inventory/index.yaml:294,2608,2612`; `index.json:322` | no reader. |
| `GLAURUNG_RUN_HOLDOUT` | `docs/design/decbench-submission-readiness.md:1010` | no reader. |
| `GLAURUNG_RUN_LIVE_AGENT_TESTS` | `docs/agentic-glaurung/implementation/04-acceptance-gates.md:106,126` | no reader; the live tests gate on `GLAURUNG_LIVE_LLM`. |
| `GLAURUNG_LOGFIRE` | `docs/llm/ROADMAP.md:731` | no reader. |
| `GLAURUNG_TRACE_PARSES` | `docs/design/decompiler-roadmap-diary-2026-08-13.md:4793` | removed. |
| `GLAURUNG_DEBUG_HOIST` | `docs/design/value-model-root-cause-and-plan.md:282` | removed. |
| `RUST_LOG` | implied by `tracing_subscriber` | Read *indirectly* via `EnvFilter::try_from_default_env()` at `src/logging.rs:24,47` (default `info`). Reachable only through `glaurung.init_logging()`, which is exposed but called by nothing outside a docstring. **Effectively dead.** |

`CI`, `RUST_BACKTRACE`, `NO_COLOR`, `COLUMNS`, `TERM`, `VIRTUAL_ENV`, `SOURCE_DATE_EPOCH` and `GITHUB_*` are read **nowhere**.

Tokens that look like env vars but are not: `GLAURUNG_NO_SSP` (a C macro in fixture source), `GLAURUNG_STRUCT_<name>_DEFINED` / `GLAURUNG_ABI_TAG_<n>_DEFINED` (emitted C include guards), `GLAURUNG_CMP_FN`, `GLAURUNG_ENC_KEY`, `GLAURUNG_ADAPTER`, `GLAURUNG_IR_PSEUDOCODE`.

**A gate exists for this.** `python/tests/test_src_dependency_boundaries.py:210-330` holds `ENV_VAR_ALLOWLIST` keyed by `(relative_file, argument_token)`; `test_every_env_var_read_in_src_is_a_reviewed_allowlist_entry` fails on any unreviewed `std::env::var`/`var_os`/`vars` under `src/`. Entries are categorized `diagnostic` / `instrumentation` / `resource` / `budget` / `policy` / `pinned-confirmation`, and a companion test forbids the category "semantic gate". Because it is keyed by **file path**, splitting or moving any module that reads an env var breaks it.

---

## 7. Tests, fixtures, and gates

### 7.1 Test inventory

| Surface | Count | Notes |
|---|---|---|
| Python test files (`/home/mjbommar/projects/personal/glaurung/python/tests/*.py`) | **462** `.py` (461 `test_*.py` + `conftest.py`) | flat directory; no test code in subdirs |
| Python test LOC | **108,029** | 4.7 MB on disk |
| `def test_*` functions | **3,241** | plus 128 `@pytest.mark.parametrize` sites |
| `python/tests/` subdirs | `fixtures/` (windows, java corpora), `samples/` | data only — 12 non-`.py` files |
| Rust files under `src/` containing `#[cfg(test)]` | **276** | top dirs: `ir` 103, `analysis` 33, `formats` 27, `core` 23, `triage` 18, `symbolic` 17 |
| `#[test]` attributes in `src/` | **3,022** (+2 `#[tokio::test]`) | `tests/test_census_baseline.json` records 3,187 declared repo-wide, `never_executed_total: 0` |
| Rust integration tests, `/home/mjbommar/projects/personal/glaurung/tests/` | **25** top-level `.rs` targets (auto-discovered; no `[[test]]` in `Cargo.toml`) | e.g. `flirt_signature_matching.rs` (40 KB), `compiler_detection_comprehensive.rs` (23 KB), `similarity_retrieval.rs`, `register_view_semantics.rs`, `overlay_integration.rs`, the four `android_*.rs` |
| …plus module subdirs pulled in by `tests/lib.rs` | `tests/common/` (2 `.rs`), `tests/triage/` (15 `.rs`) | `lib.rs` is `mod common; mod triage;` |
| `#[test]` under `tests/` | **167** | |
| Criterion benches (`benches/`) | 10 targets, all `harness = false` | `triage`, `entropy`, `strings`, `lang_detect`, `emulator` (needs `exec`), `ir_lift`, `ir_dataflow`, `ir_structure`, `analysis_cfg`, `decompile_pipeline` |

Non-`.rs` data corpora also live under `tests/`: `recovered/` (128 files), `fixtures/` (37), `decbench_corpus/` (17), `pe_identity/` (10), `decbench_scoreboard/` (6), `pdb_types/` (5), `macho_lane/` (5), `cortex_m/` (4), `decbench_adapter/` (4), `realistic_corpus/` (4), `decompiler_output_canaries/` (3), `decompiler_profile/` (2), `open_defects/` (2).

### 7.2 `tests/decompiler_fixtures/`

An execution-differential, fail-closed, ratcheting semantic-fidelity gate — 3.3 MB, 244 files.

**Fixture count and shape.** `/home/mjbommar/projects/personal/glaurung/tests/decompiler_fixtures/src/` holds **219 numbered source files**, numbered `01`–`219` (number `200` unused; `09` used twice: `09_memory_effects.c` and `09_nested_dispatch_loop.S`), i.e. 218 distinct numbers. By language: **196 `.c`, 10 `.cpp`, 7 `.rs`, 5 `.go`, 1 `.S`**. `15_*`–`80_*` are the 66-project curriculum.

**Layout** (there is no per-fixture directory — the corpus is flat source + shared oracle):

| Path | Role |
|---|---|
| `.../src/13_loop_early_exit.c` | one fixture = one source file with a long header comment naming the bug class it demonstrates and which cells are expected red |
| `.../manifest.py` (3,966 LOC, 157 KB) | the declarative oracle (below) |
| `.../sets.toml` (11.7 KB) | named `dectest` selections (`@smoke`, `@loops`, `@vector-float`, …); validated by `python/tests/test_dectest_selection.py` — every set must resolve to ≥1 lane, have a description, and `@smoke` must stay ≤6 lanes |
| `.../structural.py` (22 KB) | static predicates the structural lane asserts (switch/goto-free/effects/closure) for functions that can't be executed |
| `.../defuse.py` (8 KB) | definition-before-use census across every lane |
| `.../curriculum_oracle.c` | independently checks canonical curriculum answers for `15_*`–`30_*` |
| `.../invariants/` | `frame_and_arity_shapes.c`, `link_configuration_shapes.c`, `variadic_register_save_area.c` |
| `.../canary/` | 9 committed prebuilt `.so` objects + `MANIFEST.json` (sha256, compiler version, toolchain image digest, `why`); the 13 MB Rust cdylib is explicitly excluded |
| `.../toolchain/Dockerfile` | the pinned compile toolchain |
| `.../build/` | **gitignored**, ~40 min to build; a cache with per-object `*.so.build.json` fingerprint sidecars |
| `.../README.md` | 13 KB explanation of the gate |

**`manifest.py` structure** — pure data, read by `tools/diff_decompile.py`. Top-level names:

```python
INT_MIN / INT_MAX / UINT_MAX
DEFAULT_PTR_LEN = 16          # pointer buffer elements
FIXTURE_FUZZ = 12             # seeded-fuzz trials, shared by generator and gate
DECBENCH_OVERRIDES: dict[tuple[str, str], dict]   # same mechanism for tests/decbench_corpus/
DECBENCH_PROJECTS: dict[str, list[str]]
OVERRIDES: dict[tuple[str, str], dict]            # (fixture, function) -> contract
STRUCTURAL: dict[tuple[str, str], dict]           # (fixture, function) -> structural assertions
CURRICULUM_PROJECTS: dict[str, list[str]]
REQUIRED_FUNCTIONS: dict[str, list[str]]          # fixture -> exported functions that MUST exist
def structural_spec(fixture, func) -> dict
def tmpdir() / override() / scalar_boundaries()
FIXTURE_SRC = <this dir>/src
def assert_fixtures_declared()
```

`OVERRIDES` value fields: `ptr_len` (int), `ptr_elem` (`"int"|"u8"|"cstr"`), `len_args` (`[int]`, clamped to `[0, ptr_len]`), `extra_vectors` (explicit arg tuples, unclamped), `arg_values` (`{i: [v]}`, pins a scalar's domain in both the boundary sweep and the fuzz), `skip_exec` (bool), `skip_exec_lanes` (`("gcc:O2", …)`), `pointer_return_arg` (int), `non_length_args` (`[int]`), `link_chains` (`[[int]]` — node-index walks over a caller-owned array of self-referential structs; validated fail-closed: must start at 0, no repeats, inside `ptr_len`).

Real entries:

```python
("02_integer_widths", "urem64"): {"arg_values": {1: [1,2,3,7,10,100,0xFFFFFFFF,0xFFFFFFFFFFFFFFFF]}},
("14_flag_effects", "countdown"): {"arg_values": {0: [0,1,2,3,7,8,100]}},
("206_aarch64_wide_dispatch", "dense_dispatch"): {"switch": True, "goto_free": True, "nonempty": True},   # STRUCTURAL
"01_conditional_polarity": ["cmp_signed","cmp_unsigned","early_return","early_return_ge",
                            "nested","elseif","ternary","sc_and","sc_or","classify"],                     # REQUIRED_FUNCTIONS
```

Per-function pass/fail expectations are **not** in the manifest — they live in the generated, committed `baseline.json`, so the gate fails only on *new* regressions while known bugs stay visible.

**How fixtures are built.** No Makefile. `/home/mjbommar/projects/personal/glaurung/tools/fixture_harness.py` compiles the matrix and runs the gate; every compiler invocation is routed through `/home/mjbommar/projects/personal/glaurung/tools/fixture_toolchain.py`, which runs it inside the image built from `tests/decompiler_fixtures/toolchain/Dockerfile` (tag `glaurung-fixture-toolchain:1`).

- Image: `ubuntu:22.04@sha256:0e0a0fc6…` (digest-pinned), installing `gcc g++ clang libstdc++-11-dev libc6-dev rustc golang-go` — gcc/g++ 11, clang/clang++ 14, rustc 1.75.0, go 1.18.1, glibc 2.35. Only **compilation** is containerised; objects execute natively (old glibc → runs on any newer host).
- Not bit-reproducible; the gate relies on a **fingerprint** (`gcc/g++/clang/clang++/ld/ldd` version strings) recorded as `__toolchain__` in the baselines and asserted before any verdict is compared. `rustc` and `go` are **not** probed, so images with and without them fingerprint identically.
- Escape hatch `GLAURUNG_FIXTURE_TOOLCHAIN=host` (never silent — records `mode: host`).
- Host matrices in `fixture_harness.py`: `REQUIRED_MATRIX = [(gcc,O0),(gcc,O2),(clang,O0),(clang,O2)]`; `RUST_MATRIX = [(rustc,O0),(rustc,O2)]`; `GO_MATRIX = [(go,O0),(go,O2)]` (Go = plain `go build` vs `-gcflags=all=-N -l`, `-buildmode=c-shared`; **opt-in** via `GLAURUNG_FIXTURE_GO`, off by default because the five Go fixtures appear in none of the four committed baselines). A `O0strip`/`O2strip` suffix means `-g` then `strip`. Lane key is the three-part `fixture:cc:opt`. Missing compiler or failed required-lane compile = FAILURE, not a skip; environment gaps must be declared in `ALLOWED_MISSING`.
- Cross-architecture: `/home/mjbommar/projects/personal/glaurung/tools/arch_roundtrip.py`. `CONTROL_ARCH = "x86_64"`; `REQUIRED_ARCHES = (x86_64, x86_64_gcc15, i386, aarch64, armv7, armv7_a32)` × `REQUIRED_OPTS = (O0, O2)`. Non-host arches execute under `qemu-i386` / `qemu-arm`. Note the vocabulary clash: `fixture_harness` names a lane by compiler (`gcc:O2`), `arch_roundtrip` by architecture (`x86_64:O2`).

### 7.3 Baselines

Every `*baseline*.json` in the repo, plus `bench/`:

| Path | Records | Regenerated / gated by |
|---|---|---|
| `/…/tests/decompiler_fixtures/baseline.json` (146 KB, 839 keys) | per-function `pass`/`fail` for each `fixture:cc:opt` host lane + `__toolchain__` | `tools/fixture_harness.py --write-baseline`; gate `python/tests/test_decompiler_fixture_matrix.py` |
| `/…/tests/decompiler_fixtures/arch_baseline.json` (429 KB, 2,473 keys) | same verdicts keyed `fixture:arch:opt` over 6 arches × O0/O2 | `tools/arch_roundtrip.py --write-baseline` / `--check`; gate `python/tests/test_decompiler_arch_roundtrip.py` |
| `/…/tests/decompiler_fixtures/structural_baseline.json` (634 KB) | keys `closure`, `effects`, `gaps`, `placeholder`, `readability`, `skipped`, `verify` — per-function-per-render-style structural facts | `tools/gen_structural_baseline.py`; gate `python/tests/test_decompiler_fixture_structural.py` |
| `/…/tests/decompiler_fixtures/defuse_baseline.json` (318 KB) | `required`, `lane_totals`, `fixture_lane_totals`, `problems`, `accepted_regressions`, `__toolchain__` — definition-before-use violation counts per lane | `tools/gen_defuse_baseline.py`, guarded by `tools/defuse_ratchet.py`; gate `python/tests/test_decompiler_defuse_census.py` (two-sided ratchet: rises fail, falls fail-until-refreshed) |
| `/…/tests/decompiler_fixtures/stripped_divergences.json` (13 KB, 95 keys) | `{fixture:cc:O2strip:func} -> {debug, stripped, kind}` | `tools/stripped_differential.py`; gate `python/tests/test_decompiler_stripped_lane.py` |
| `/…/bench/perf_baseline.json` (304 B) | `{measures: {binary -> instructions}, runs: 3, unit: "instructions"}` over 3 large sample binaries | `tools/perf_gate.py`; gate `python/tests/test_perf_gate_fails_closed.py`. Fails open on missing/incomparable evidence (exit 3) |
| `/…/tools/fitness_baseline.json` (20 KB) | LOC fitness: `product`/`ir`/`root` file counts, medians, `files_above_1000/2000`, `largest_files`, `oversized_files`, `targets`, `accepted_regressions` | `tools/fitness_report.py`; gates `python/tests/test_fitness_report.py`, `test_large_module_review.py` |
| `/…/tests/test_census_baseline.json` | `total_declared: 3187`, `never_executed_total: 0`, `solver_gated_estimate`, `by_module` — declared `#[test]` per Rust module | `tools/gen_test_census.py`; gate `python/tests/test_test_census.py` |
| `/…/tests/sample_duplication_baseline.json` (20 KB) | `groups: 75`, `redundant_bytes: 22,363,724`, `inventory` — byte-identical files under `samples/` (ratcheted, not deduplicated) | `tools/gen_sample_duplication_baseline.py`; gate `python/tests/test_sample_corpus_duplication.py` |
| `/…/tests/realistic_corpus/discovery_baseline.json` (3 KB) | `schema: 2`, `toolchain` (gcc/strip/sstrip/upx/objcopy/patchelf versions), `ground_truth_count: 83`, `variants` — function-discovery recall on stripped/packed/lying binaries | `tools/gen_realistic_baseline.py` (`--check`); gate `python/tests/test_realistic_corpus.py`; corpus built by `tools/realistic_corpus.py` |
| `/…/tests/decompiler_output_canaries/baseline.json` (19 KB) | `schema: glaurung-output-canary-report-v1`, `git`, `cases[]` with per-function `final_violations` and `first_violation_passes` (which pass first introduced each undefined read) | `tools/decompiler_output_canaries.py`; gate `python/tests/test_decompiler_output_canaries.py` |
| `/…/tests/decompiler_profile/baseline-2026-08-08.json` (17 KB) | cold/warm decompile ns, `max_rss_kib`, `object_parse_count`, `stage_duration_ns`, output sha256; `allocations` marked `unavailable` | `tools/decompiler_profile.py`; gate `python/tests/test_decompiler_profile.py` |
| `/…/tests/decbench_corpus/baseline.json` (5 KB, 57 keys) | per-`project:cc:opt` `{ged, byte_match, type_match}` + `__toolchain__` (gcc 15.2, clang 21.1) | `tools/decbench_matrix.py` (`BASELINE` constant); DecBench lane, opt-in |
| `/…/tests/decbench_scoreboard/baseline-ledger.json` (36 KB) | `baseline_revision`, `metrics`, `dimensions` (per arch/opt/project), `functions`, `canaries.current_perfect`, `head_to_head`, `union` | `tools/decbench_score_ledger.py`; gate `python/tests/test_decbench_score_ledger.py` (fast, no fork needed) |
| `/…/docs/benchmarks/baseline.json` (20 KB) | `glaurung_commit`, `scorecards[]` (per-binary callgraph/decompile/debug-info metrics), `summary` | produced by `uv run python -m glaurung.bench` and committed by hand — **no regenerator script and no test compares against it** |
| `/…/docs/axeyum-integration/capture/lineage-*-v1.json` (4 files) | captured solver-lineage traces for the Axeyum integration | documentation capture artifacts, not gates |

Related non-baseline ratchet: `/…/tests/test_facets.json` (26 KB) — the test-facet classification (see 7.6).

### 7.4 `/home/mjbommar/projects/personal/glaurung/scripts/` (17 files, 6,248 LOC)

| File | Purpose (from its header) |
|---|---|
| `asb_tailcall_augment.py` | ASB-contributed capstone tail-call augmentation of Glaurung's function discovery; feeds `windows_ghidra_parity.py` |
| `build_adversarial_samples.py` | Build the adversarial-sample corpus for the embedded-content tools under `samples/adversarial/embedded/` |
| `build-macho-samples.sh` | Build minimal Mach-O samples for testing the Mach-O stubs resolver (clang + ld64.lld) |
| `decbench-local-gate.sh` | The heavy decompiler gates in one place: fixture lanes 1–3 by default, DecBench lanes 4–5 opt-in |
| `feature-build-gate.sh` | "Does every Cargo feature still COMPILE?" — 12 `cargo check --all-targets` lanes |
| `fetch-reference.sh` | Clone the third-party reference checkouts on demand (were submodules until 2026-08-31) |
| `format-python.sh` | `uvx ruff format python/` |
| `format-rust.sh` | `cargo fmt --all` |
| `harden.sh` | Format + lint Rust and Python, then type check (`cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, ruff, ty) |
| `index_samples.py` | Generate `samples/binaries/index.json` — per-file size, sha256, `file`-type, tool versions |
| `ioctlance_parity.py` | Measure Glaurung's IOCTL analysis parity against the reference ioctlance (angr) fork |
| `lint-python.sh` | `uvx ruff check python/ --fix` |
| `lint-rust.sh` | `cargo fmt --check` + `cargo clippy --all-targets --all-features -- -D warnings` (with `GLAURUNG_BITWUZLA_TYPECHECK_ONLY=1`) |
| `recover_source.py` | End-to-end source-recovery pipeline driver (v2): the 25-tool Layer 0→4 ladder → a recovered source tree |
| `typecheck-python.sh` | `uvx ty check python/glaurung` (package only, ignoring tests) |
| `verify_tutorial.py` | Verify the tutorial track against shipped CLI surfaces; `--check` (default) vs `--capture` against `docs/tutorial/_fixtures/` |
| `windows_ghidra_parity.py` | Compare Glaurung function discovery against Ghidra on vendored Windows PEs |

**`scripts/decbench-local-gate.sh` lanes as actually executed:**

```
1   cargo test --features python-ext --lib --tests
1a  scripts/feature-build-gate.sh
1c  uv run python tools/perf_gate.py
1b  pytest -q -m "not slow" python/tests/  (ignoring the 4 heavy decompiler files)
2   pytest -m slow  test_decompiler_fixture_matrix.py test_decompiler_defuse_census.py
                    test_decompiler_stripped_lane.py test_decompiler_fixture_structural.py
3   tools/arch_roundtrip.py --check
4   tools/decbench_matrix.py --corpus decbench|curriculum --behavior-only --backend glaurung   [opt-in]
5   DecBench per-cell metric ratchet                                                            [opt-in]
```
It refuses to run against a stale build (`tools/build_guard.py`), sets `GLAURUNG_FIXTURE_TMPDIR=$PWD/target/fixture-tmp`, and on the default path prints `GATE: passed (fixture lanes 1-3) — DecBench lanes 4-5 NOT RUN`.

**`scripts/feature-build-gate.sh` lanes** (each `cargo check --all-targets`): `default (triage-core)`, `python-ext`, `exec`, `symbolic`, `solver-axeyum`, `solver-axeyum-text`, `solver-bitwuzla`, `triage-parsers-extra`, `solver-z3` (needs z3), `solver-z3,solver-axeyum` (needs z3), `--all-features` (needs z3), and `--manifest-path fuzz/Cargo.toml`. A skipped z3 lane **exits 1** unless `GLAURUNG_ALLOW_MISSING_SOLVERS` is set.

### 7.5 `/home/mjbommar/projects/personal/glaurung/tools/` (70 files)

| File | Purpose |
|---|---|
| `angr_decompile.py` | Decompile named functions with angr — the third comparator |
| `arch_roundtrip.py` | Execution differential for every architecture the lifters claim to support; `--check` / `--write-baseline` |
| `build_guard.py` | Is the `.so` newer than the Rust it was built from? (plus a second staleness check) |
| `build_test_inventory.py` | Merge the surveyed inventory fragments into the published index |
| `compare_decompilers.py` | Run glaurung, angr and Ghidra over the same function side by side |
| `decbench_audit_full.py` | Independently audit and merge a full-corpus DecBench result column |
| `decbench_compare.py` | Head-to-head DecBench metrics across decompilers, per lane and per program |
| `decbench_compare_full.py` | Score a full-corpus run against DecBench's published numbers |
| `decbench_decompile.py` | Emit one DecBench backend's exact function results as JSON |
| `decbench_evaluate_sharded.py` | Evaluate a DecBench tree by sharding across (opt, project) pairs |
| `decbench_evaluate_verified.py` | Evaluate a DecBench tree and PROVE every binary was actually scored |
| `decbench_external_agentic.py` | Run Glaurung's real LLM pipeline over a blinded DecBench eval kit |
| `decbench_fetch_full.py` | Fetch the DecBench full-config dataset into a materialized evaluation tree |
| `decbench_glaurung.py` | Register Glaurung as an out-of-tree DecBench backend |
| `decbench_holdout.py` | Score the frozen 250-function DecBench holdout and refuse a regression |
| `decbench_matrix.py` | Per-cell DecBench metric ratchet over the committed corpus |
| `decbench_merge_shards.py` | Deterministically merge disjoint `function_results.json` shards |
| `decbench_redecompile_tree.py` | Re-decompile the materialized DecBench tree with the current build |
| `decbench_score_ledger.py` | Build a fail-closed, deterministic ledger from a DecBench gap report |
| `decbench_symbols.py` | Resolve a DecBench function name to a local body address |
| `decompiler_output_canaries.py` | Capture and verify deterministic function-level output canaries |
| `decompiler_profile.py` | Measure cold/warm decompilation, RSS, object parses, shared-pass timings |
| `dectest.py` | Run the smallest slice of the fixture corpus that answers your question (the iteration loop) |
| `defuse_ratchet.py` | Guard that stops `defuse_baseline.json` from ratcheting the wrong way |
| `diff_decompile.py` | Fail-closed execution-differential decompiler correctness gate (the worker) |
| `fitness_report.py` | Measure the "code quality, composition, file-size" fitness program |
| `fixture_harness.py` | Compile the fixture corpus across the toolchain matrix and run the gate |
| `fixture_toolchain.py` | The fingerprinted compile toolchain used by every stage of the fixture gate |
| `gen_defuse_baseline.py` | Regenerate `tests/decompiler_fixtures/defuse_baseline.json` |
| `gen_demangle_corpus.py` | Build a demangler test corpus from real symbols, checked against real tools |
| `gen_fixture_gallery.py` | Emit the JSON the glaurung.dev fixture gallery renders |
| `gen_known_failures.py` | Measure every decompiler failure the fixture corpus can demonstrate |
| `gen_native_stub.py` | Generate type stubs for the compiled `glaurung._native` extension |
| `gen_realistic_baseline.py` | Regenerate the realistic-corpus discovery baseline (`--check`) |
| `gen_sample_duplication_baseline.py` | Record the current byte-duplication in `samples/` |
| `gen_structural_baseline.py` | Regenerate `tests/decompiler_fixtures/structural_baseline.json` |
| `gen_test_census.py` | Record how many tests each module declares, and which are never executed |
| `gen_test_facets.py` | Classify every Python test file by what it NEEDS, and record it |
| `ghidra_decompile.py` | Decompile named functions with Ghidra — the production reference |
| `pass_health_report.py` | Convert Glaurung JSONL pass traces into attributed health reports |
| `perf_gate.py` | A performance number something actually compares against (instructions retired) |
| `pipeline_profile_report.py` | Summarize opt-in pipeline timing and object-parse traces |
| `realistic_corpus.py` | Build realistic binaries — stripped, lying, self-decrypting, packed — from our own sources |
| `recompile_fidelity.py` | Measure how close recompiled recovered C is to the code it came from |
| `roundtrip3.py` | Three-way round trip C → binary → C for glaurung, Ghidra and angr |
| `roundtrip_review.py` | Put source and our decompiled C side by side, with a verdict |
| `scratch.py` | Keep this project's temporary files off the shared `/tmp` tmpfs (imported for side effect) |
| `stripped_differential.py` | The stripped lane: decompile the same compile with debug info removed and diff |
| `fitness_baseline.json` | data (see 7.3) |

`tools/extbench/` — Glaurung against other decompilers on real binaries:

| File | Purpose |
|---|---|
| `README.md` | extbench — Glaurung against other decompilers, on real binaries |
| `build_corpus.sh` | Build the two benchmark corpora and their list files |
| `runall.sh` | Drive every decompiler over every binary in a corpus list |
| `drive.py` | Run every decompiler over one sample binary against a shared function set |
| `config.py` | Where the external decompilers live, and how to override that |
| `gt.py` | Extract ground truth from a sample ELF: DWARF subprograms, `.eh_frame` FDEs, PLT map |
| `run_glaurung.py` | `glaurung cfg` for discovery, `glaurung decompile --vas` for C |
| `run_ghidra.py` / `run_angr.py` / `run_retdec.py` | the three comparator runners, emitting the common JSON |
| `analyze.py` | Score the collected decompiler output |
| `callcheck.py` | Check each tool's emitted call set against the calls actually there |
| `compilable.py` | How much of each tool's output is even syntactically C |
| `discover_only.py` | Function-discovery counts only, for binaries with no sound reference |
| `report.py` | Render the scored results as markdown tables |
| `sidebyside.py` | Print every tool's C for one ground-truth function, with its DWARF signature |
| `ruff.toml` | lint config (the harness deliberately shells out without `check=True`) |

### 7.6 `pytest.ini`, conftest, and facet markers

`/home/mjbommar/projects/personal/glaurung/pytest.ini`:

```ini
[pytest]
testpaths = python/tests
addopts = -q -ra -m "not decbench" --disable-plugin-autoload
          -p anyio.pytest_plugin -p pytest_asyncio.plugin -p pytest_benchmark.plugin
```

`-m "not decbench"` is the **only default deselection** — it keeps ordinary runs away from the out-of-tree DecBench fork; an explicit `-m …` on the command line *replaces* the expression, so opting in is `pytest python/tests/ -m decbench`. `-ra` is there because 176 files call `pytest.skip()` at runtime and silent skips were indistinguishable from passes. Plugin autoload is disabled with three plugins re-enabled explicitly.

Markers declared:

| Marker | Meaning |
|---|---|
| `slow` | end-to-end fixture matrix / structural lane (compiles + executes the corpus) |
| `decbench` | needs `$DECBENCH_DIR`, its venv, or a Joern JVM — **deselected by default** |
| `core` | needs nothing beyond the built extension; the per-push CI floor |
| `fixtures` | needs `tests/decompiler_fixtures/build/` (gitignored, ~40 min) |
| `toolchain` | invokes a compiler at test time (gcc/clang/arm-none-eabi-gcc/…) |
| `lfs` | reads Git LFS sample binaries |
| `docker` | needs the pinned fixture-toolchain image |
| `llm` | needs a live model endpoint and key |

All but `slow` and `decbench` are applied **at collection time**, not by decorators.

- `/home/mjbommar/projects/personal/glaurung/conftest.py` (9 lines) — an empty `pytest_sessionstart`; no shims.
- `/home/mjbommar/projects/personal/glaurung/python/tests/conftest.py` (224 lines) — sample-path helpers anchored via `Path(__file__).resolve().parents[2] / "samples"` (previously CWD-relative, which turned missing files into silent skips), ~20 `sample_*` fixtures, and the facet hook:

```python
_FACETS = json.loads((… / "tests" / "test_facets.json").read_text()).get("files", {})

@pytest.hookimpl(tryfirst=True)          # must beat pytest's own -m deselection
def pytest_collection_modifyitems(config, items):
    for item in items:
        for facet in _FACETS.get(item.path.name, ()):
            item.add_marker(getattr(pytest.mark, facet))
```

`tryfirst=True` is load-bearing: pytest's builtin `mark` plugin performs `-m` deselection inside its own `pytest_collection_modifyitems`, so without it every `-m <facet>` selected only the handful of files with explicit decorators.

`tests/test_facets.json` (generated by `tools/gen_test_facets.py`, never hand-edited; guarded by `python/tests/test_test_facets.py`) classifies **461 files**, 17 of them with more than one facet:

| facet | files |
|---|---|
| `core` | 297 |
| `lfs` | 101 |
| `toolchain` | 28 |
| `fixtures` | 28 |
| `docker` | 18 |
| `llm` | 5 |
| `decbench` | 2 |

Facets are **requirements, not subjects** — the rules are deliberately dumb text patterns; a test whose need the rules cannot see declares an explicit `pytestmark`, and the hook merges both (the JSON only ADDS). Explicit decorators still in the suite: 106 `@pytest.mark.skipif`, 52 `@pytest.mark.slow`, 12 `@pytest.mark.asyncio`, 8 `@pytest.mark.xfail`, 7 `@pytest.mark.decbench`.

### 7.7 `.github/workflows/` — what CI actually executes

Ten workflows. **No `continue-on-error: true` appears anywhere**; all softness comes from `|| true`, `if [ -f … ]` guards, `set +e` + `case`, `--allow-drift` / `--allow-blocked`, and `if-no-files-found: warn|ignore`.

| File | `name` | Triggers |
|---|---|---|
| `CI.yml` | CI | push `main`,`master`,tags `*`; PR; dispatch |
| `decompiler-fixtures.yml` | Decompiler Fixture Gate | push `[main, master]`; PR; dispatch |
| `feature-build-gate.yml` | feature build gate | push `[master]`; PR; dispatch |
| `test-suite.yml` | test suite | push `[master]`; PR; dispatch |
| `samples-docker.yml` | Samples Docker Build | push/PR **paths** `samples/**`; dispatch |
| `fuzz-nightly.yml` | fuzz nightly | `cron 17 4 * * *`; dispatch — **no push/PR** |
| `perf-nightly.yml` | perf nightly | `cron 37 5 * * *`; dispatch — **no push/PR** |
| `windows-corpus-guard.yml` | Windows Corpus Guard | PR (paths); `cron 17 6 * * 1`; dispatch — no push |
| `windows-target-pipeline.yml` | Windows Target Pipeline | PR (27 paths); `cron 47 6 * * 1`; dispatch — no push |
| `windows-ghidra-parity-refresh.yml` | Windows Ghidra Parity Refresh | `cron 23 7 * * 1`; dispatch — no push/PR |

**`test-suite.yml`** — 4 jobs, no `if`, no matrices:

| job | runs-on / timeout | commands |
|---|---|---|
| `rust` | ubuntu-latest / 45m | `apt-get install gcc-arm-none-eabi` (no `\|\| true` — hard), then `cargo test --features python-ext` with `GLAURUNG_REQUIRE_TOOLCHAINS=1` |
| `symbolic` | ubuntu-latest / 45m | `cargo test --features symbolic`; then counts `cargo test --features symbolic -- --list \| grep -c '^symbolic::'` and `exit 1` if `< 50` |
| `python` | ubuntu-latest / 90m | `apt-get install gcc-multilib libc6-dev-i386 \|\| true`; `uv sync --locked --dev`; `uv run maturin develop --release`; `uv run pytest python/tests/ -m "not fixtures and not decbench"` |
| `lint` | ubuntu-latest / 15m | `uvx ruff format --check python/`; `uvx ruff check python/` |

Precisely: the `lint` job is *named* "ruff and ty" but **`ty` is invoked nowhere in `.github/workflows/`** — it does not run in CI. aarch64/armv7 cross compilers are not installed, so those lifter lanes skip. `docker`- and `llm`-facet tests are not deselected and self-skip at runtime.

**`decompiler-fixtures.yml`** — concurrency-cancelled per ref. `changes` (dorny/paths-filter over `src/ir|analysis|disasm|decompiler|exec`, the four fixture tools, `tests/decompiler_fixtures/**`, `python/tests/test_decompiler_fixture_*.py`). `fast` (30m, always) builds the toolchain image, runs `tools/fixture_toolchain.py`, then `pytest test_decompiler_fixture_{harness,toolchain,compile}.py`. `matrix` (180m, `if: decompiler changed || event != pull_request`) builds the image, `maturin develop --release`, then `pytest -m slow test_decompiler_fixture_matrix.py test_decompiler_fixture_structural.py` and `pytest -m fixtures test_known_decompiler_failures.py`. **The `fixtures` facet — including the 1,162-entry known-failure corpus — runs only here.**

**`feature-build-gate.yml`** — one job: `apt-get install libz3-dev`, `scripts/feature-build-gate.sh` (the 12 lanes above), `cargo fmt --all -- --check`. `cargo check` only: no tests run, no bitwuzla linking.

**`CI.yml`** — maturin-generated, **zero `run:` steps**. On ordinary push/PR only `wheel-smoke` runs (one x86_64 `--release` build, no artifact upload). The 15-job wheel matrix (linux ×6, musllinux ×4, windows ×2, macos ×2, sdist) plus `release` (provenance attestation + PyPI upload) are tag/dispatch-only, and the PyPI publish step is gated a second time on `startsWith(github.ref,'refs/tags/')`.

**`fuzz-nightly.yml`** — matrix over 8 targets (`disasm_decode, demangle_all, formats_parse, headers_validate, containers_detect, sniffers_sniff, parsers_parse, entropy_analyze`), `fail-fast: false`: `cargo install cargo-fuzz --locked`; `uv run python fuzz/seed_corpus.py --limit 120`; `cargo fuzz run <target> -- -max_total_time=120 -rss_limit_mb=4096`.

**`perf-nightly.yml`** — `uv sync --locked --dev`, `uv run maturin develop --release`, `uv run python tools/perf_gate.py --json`. Exit **3 ("no comparable evidence") is swallowed as a `::warning::`** — the expected hosted-runner outcome, since `kernel.perf_event_paranoid` blocks instruction counting; a follow-up inline Python step hard-fails only if `report["measures"]` is empty.

**`samples-docker.yml`** — matrix (`native, cross, fortran, java, python`) builds `samples/Dockerfile` targets, `docker-compose --profile <target> up --build`, `python scripts/index_samples.py`. `build-multiplatform` is dispatch-only. `test-samples` is nearly all soft (`if [ -f … ]` guards); `summary` never exits non-zero.

**The three Windows workflows** — `windows-corpus-guard` runs `uv run glaurung windows corpus-guard --format json` (hard `if-no-files-found: error`, but checkout has **no `lfs: true`** despite targeting LFS sample paths). `windows-target-pipeline` runs one test file on PRs (`pytest python/tests/test_windows_target_pipeline_agent.py`); its high-volume job needs a self-hosted `windows-corpus` runner and `/nas4/…` paths and never runs on PRs. `windows-ghidra-parity-refresh` needs a self-hosted `ghidra` runner and `/nas4/data/tools/ghidra_12.1_PUBLIC/…`; it uses `corpus-guard --allow-drift` and applies artifact promotion unconditionally.

**What is declared but not exercised anywhere in CI today:** `ty` type checking; the solver-backed Rust tests (`solver-z3`, `solver-bitwuzla`, `solver-axeyum` — only `cargo check`-ed); the cross-architecture round trip (`tools/arch_roundtrip.py --check` is local-gate-only); the def-use census, stripped lane, and `-m slow` fixture matrix on PRs that touch no decompiler path; every DecBench lane; both self-hosted Windows lanes on a repo without those runners.

---

## 8. Samples corpus and fixtures

### 8.1 `/home/mjbommar/projects/personal/glaurung/samples/` — 817 files, 4.8 MB on disk

**Critical caveat: 360 of the 817 files are unresolved Git-LFS pointer stubs (~130 bytes each).** `git-lfs` is not installed on this machine, so every LFS-tracked path is a text pointer and `file(1)` reports "ASCII text" for 148 `.exe`/`.dll`/`.jar`/`.class`/`.so`/`.a`/`.sys`/`.luac` files. The real corpus is ~40 MB. Repo-wide there are 1,213 LFS pointers: `docs/axeyum-integration` 842, `samples/binaries` 341, `samples/packed` 10, `reference/specifications` 8, `samples/containers` 8, `docs/windows-port` 4. The `lfs` pytest marker exists precisely for this: "a checkout without `lfs: true` sees pointer files."

```
samples/
├── adversarial/        14 files, 148K   (+ embedded/)
├── binaries/          736 files, 4.2M   (+ platforms/)
├── containers/          8 files,  60K   (bzip2 gzip tar xz zip zstd)
├── docker/             15 files, 124K   (darwin linux windows)
├── packed/             10 files,  44K
└── source/             24 files, 168K   (asm c cpp csharp fortran go java library lua python rust)
```

Ten loose root files: `README.md`, `build-all-platforms.sh`, `build-compressed.sh`, `build-msvc.sh`, `build-multiplatform.sh`, `build-packed.sh`, `test-docker.sh`, `test_python_multi_version.sh`, `docker-compose.yml`, `.dockerignore`.

**Only 37 native binaries are actually materialized on disk today** — 4 under `adversarial/` and 33 under `binaries/platforms/` (10 gfortran x86-64, 5 gfortran arm64, 7 `linux/amd64/synthetic/`, 10 hand-written `asm/{gas,nasm}` at O0–O3+debug, 1 Mach-O `darwin/amd64/export/native/multi_import-macho`).

`samples/binaries/` (736) = 342 LFS stubs + 341 `.json` (339 in `*/metadata/` plus `index.json`) + 33 real binaries + 20 other. Extension tally: 341 `.json`, 69 `.exe`, 23 `.dll`, 18 `.txt`, 18 `.jar`, 18 `.class`, 10 `.luac`, 6 `.sys`, 3 `.a`, 1 `.upx9`, 1 `.so`, 1 `.md`, 1 `.cpp`, 226 extensionless.

**The authoritative inventory is `samples/binaries/index.json`** (156,572 B, generated 2025-09-02 on host `mobile4`, with a tool-version snapshot: gcc 14.2.0, clang 20.1.2, gfortran 15.0.1, javac/jar 21.0.8, python3 3.13.3, glibc 2.41, file 5.45). It records **552 entries totalling 40,193,336 bytes** — stale relative to today's 736-file tree. Regenerate with `uv run python scripts/index_samples.py`.

Platform coverage per `index.json`: **137 ELF** (115 pie + 8 exec + 5 32-bit pie + 2 shared object), **60 PE** (27 PE32+ x86-64, 20 PE32 i386, 4+4 stripped-to-external-PDB, 3 PE32 Mono/.NET, 2 PE32+ DLL), **0 Mach-O in the index** (1 exists on disk). Plus 15 Java `.class` + 15 JAR, 16 CPython bytecode across 3.8–3.12+, 4 Lua 5.3 bytecode, 2 `ar` archives.

Architecture coverage: x86-64 (71 pie + 8 exec), **AArch64 37**, PE x86-64 27, PE i386 20, **RISC-V 7**, **ARM 32-bit (armhf) 5**. JVM class-file versions 65.0 / 61.0 / 55.0.

Platform tree counts: `darwin/` 1 (amd64), `linux/` 568 (amd64 467, arm64 101), `windows/` 166 (amd64 68, i386 66, vendor 32). Cross dirs `linux/amd64/{export/,}cross/{arm64,armhf,riscv64,windows-x86_64}`; language dirs `native/{gcc,clang}/{O0,O1,O2,O3,debug,rpath,runpath}`, `native/asm/{gas,nasm}/`, `fortran`, `go`, `rust`, `lua`, `java/{jdk11,jdk17,jdk21}`, `dotnet/mono`, `libraries/{shared,static}`, `metadata`, `synthetic`.

**Packed / obfuscated / adversarial subsets:**
- `samples/packed/` — 10 files, all `.upx9`, **all LFS stubs**: `hello-gfortran-{O0,O1,O2,O3,debug}`, `hello-go`, `hello-go-static`, `hello-rust-{debug,musl,release}`. Rebuilt by `samples/build-packed.sh` (needs `upx`).
- `samples/adversarial/` — 14 hand-crafted byte sequences. Tiny malformed headers: `magic_dope_mz_elf.bin` (44 B), `elf_truncated_phdr.bin` (50 B), `pe_bad_optional_header.bin` (69 B), `zip_masquerade_exe.exe` (46 B), `gzip_truncated.gz` (19 B), plus `ioc_samples.txt`. `embedded/` (7): `b64_payload_in_elf.elf` 37,756 B, `xor_url_in_elf.elf` 16,231 B, `two_hellos.tar` 40,960 B, `recursively_nested.bin` 3,568 B, `pe_with_overlay.exe` 3,105 B, `nested_zip_in_zip.zip` 2,906 B, `hello.elf.gz` 2,538 B. Scoped by its README as "small, hand-crafted byte sequences… no decompression or extraction required."
- `samples/containers/` — 8 LFS stubs: the same program (`hello-cpp-g++-O0`) in `.tar`/`.zip`/`.gz`/`.bz2`/`.xz`/`.zst` plus 2 bare copies. Built by `build-compressed.sh`.
- `samples/binaries/platforms/windows/vendor/realworld/` — 32 files: 30 LFS-stubbed real Win8/Win10/Win11/Windows-Update DLL/SYS/EXE, `MANIFEST.json` (27,522 B), `README.md`. Sourced from `/nas4/data/binary-analysis/...` with reproducible seeds `glaurung-windows-vendor-2026-05-19-v2` (10 small) and `-v3` (+20 high-volume). **Its README warns to review redistribution constraints before publishing outside the repo.**

**`samples/README.md` exists** (plus `adversarial/README.md`, `source/README.md`, and the vendor/realworld one). It: describes the tree as source programs plus checked-in binaries for tutorials, tests, demos and regression tooling, which you do not need to rebuild; documents the export shape `binaries/platforms/<os>/<arch>/export/{native,cross,fortran,go,java,dotnet,lua,rust,libraries,metadata}` (not every platform has every directory); names 8 representative artifacts; declares `index.json` authoritative (paths, sizes, SHA-256, `file` output, tool versions — its `host`/`root` fields being provenance, not required local paths); marks rebuilding maintainer-only (Docker/Buildx/QEMU, cross-compilers, Apple SDK, UPX); warns that `build-multiplatform.sh --clean` deletes the existing corpus and that the orchestrator builds images but does *not* export artifacts back into `samples/binaries/platforms/`; and closes with a 6-step fixture-change policy ending "Never substitute invented bytes or mocked analysis output for a real fixture." **There is no general licensing/provenance section for third-party content** beyond the vendor/realworld warning.

`samples/source/` (24): asm 5, c 6, cpp 1, csharp 1, fortran 1, go 1, java 1, library 3, lua 1, python 1, rust 1, README.
`samples/docker/` (15): 3 build scripts, `collect-kernel-modules.sh`, `platforms.json`, and 10 Dockerfiles (`darwin/{amd64,arm64}`, `linux/{amd64,arm64,armhf,i386,riscv64}`, `windows/{amd64,i386,msvc}`).

### 8.2 `/home/mjbommar/projects/personal/glaurung/tests/fixtures/` — 37 files, 804 KB

| subdir | files | size | contents |
|---|---:|---:|---|
| `android/` | 27 | 212K | Real AArch64 artifacts **plus their sources and build scripts**: `packed_android.so` (APS2 `DT_ANDROID_RELA`), `packed_relr.so` (`DT_RELR`), `unpacked.so` + `relocs.c`; `pac_bti`, `pac_bti_stripped` (`-mbranch-protection=standard`) + `pac.c`; `sample.dex` (d8 from `dexsrc/{Sample,Widget}.java`), `sample.apk`, `sample_full.apk` (multidex); `AndroidManifest_termux_api.axml` (from `com.termux.api`, F-Droid, **GPLv3**); `foo_drv.ko` + `drv.c` (AArch64 `ET_REL` with a `file_operations`/`unlocked_ioctl` `_IOC` switch), `reloc_drv.ko` + `reloc_drv.c`; SELinux policies `sepolicy.{30,33,35}`, `sepolicy_nomls.33` + CIL sources; `build.sh`, `build_dex.sh`, `build_sepolicy.sh`, `README.md`. The README asserts all are genuine toolchain output, "no hand-mocked bytes." |
| `demangle/` | 1 | 536K | `corpus.jsonl` — the NDJSON symbol-demangling corpus. |
| `msvc-pdb/` | 4 | 28K | **No committed binaries**: `MANIFEST.json`, `fetch.sh`, `README.md`, `.gitignore`. Documents 8 (PE, PDB) pairs from one Win11 23H2 snapshot — `ntoskrnl.exe`, `ntdll.dll`, `tcpip.sys`, `dxgkrnl.sys`, `win32k.sys`, `lsass.exe`, `kernel32.dll`, `spoolsv.exe` — all x64, no ARM64, ~78 MB total, hence fetched rather than committed. |
| `analyst_rename/` | 2 | 12K | `analyst_locals.c`, `analyst_rename.c`. |
| root | 3 | — | `arm_terminal_loop.c`, `guarded_call_select.c`, `lazy_call_select.c`. |

### 8.3 `/home/mjbommar/projects/personal/glaurung/tests/` — 6.6 MB total

31 loose root files: Rust integration tests (`android_dex_triage.rs`, `cfg_integration.rs`, `disasm_integration.rs`, `flirt_signature_matching.rs`, `pe_tls_directory_msvc_pdb.rs`, `register_view_semantics.rs`, `lib.rs`, …), three Python files (`test_kb.py`, `test_llm_tools.py`, `test_tools_direct.py`), and three JSON baselines (`sample_duplication_baseline.json`, `test_census_baseline.json`, `test_facets.json`).

| subdir | files | size | what it holds |
|---|---:|---:|---|
| `common/` | 2 | 16K | Shared Rust test helpers. |
| `cortex_m/` | 4 | 20K | ARM Cortex-M / RTOS lane: `rtos.c` → `rtos.o`, `build.sh`, `MANIFEST.json`. |
| `decbench_adapter/` | 4 | 100K | Windows stdcall-symbol adapter: `stdcall_symbols.c` → `.dll`, `build.sh`, `MANIFEST.json`. |
| `decbench_corpus/` | 17 | 84K | 14 self-contained C programs from `gen_sources.py`, plus `baseline.json` — the 56-cell dev matrix (14 × {gcc,clang} × {O0,O2}) for GED / `type_match` / `byte_match`. |
| `decbench_scoreboard/` | 6 | 468K | Pinned 2026-08-08 DecBench submission ledger: `manifest.json` (250 ordered function identities), `glaurung-c1cfdc97.json` per-function evidence, derived `baseline-ledger.json`, `type-distance-one-9c25fcb.json` (29 functions one type edit from perfect: 13 verified, 16 open). |
| `decompiler_fixtures/` | 244 | 3.3M | **The semantic-fidelity gate corpus** — see §7.2 and below. |
| `decompiler_output_canaries/` | 3 | 32K | 7 named high-risk cells (4 official DecBench functions + 3 local matrix cells) = 11 pinned observations of output hash/size/signature/health counters. |
| `decompiler_profile/` | 2 | 28K | Clean-tree perf baseline of rev `4b6838f9`: cold/warm times, RSS, object-parse counts, stage times, binary+output hashes. |
| `fixtures/` | 37 | 804K | See §8.2. |
| `macho_lane/` | 5 | 56K | `macho_src.c` → `lib_x86_64.dylib`, `lib_aarch64.dylib`, `build.sh`, `MANIFEST.json`. |
| `open_defects/` | 2 | 164K | `inlined_printf_arg.c` + `known_failures.json`. |
| `pdb_types/` | 5 | 92K | MSVC PDB type-ingestion lane: `types.c` → `types.dll` + `types.pdb`. |
| `pe_identity/` | 10 | 192K | PE identity/symbol lane: `ident32/64.dll` + PDBs, `helper32/64.dll`. |
| `realistic_corpus/` | 4 | 32K | Function-discovery recall harness: `discovery.py`, `recall.py`, `discovery_baseline.json`, `src/overlap_probe.S`. |
| `recovered/` | 128 | 884K | Four end-to-end recovered-project trees (`hello-recovered`, `-v2`, `-v3`, `hello-fortran-recovered`), each with `src/`, `notes/`, `cache/`, `man/`, `crt/`. |
| `triage/` | 15 | 96K | Rust triage integration tests (`adversarial`, `budgets`, `determinism_json`, `entropy_real`, `io`, `ioc_integration`, `packers_real`, `real_files`, `sniffers`, `suspicious_integration`, `symbols_{elf,macho,pe}`, `truncation_json`). |

Additional detail on `tests/decompiler_fixtures/` beyond §7.2:
- `src/` is **flat numbered source files, not numbered directories**: 219 files, all matching `^[0-9]+_`, **218 unique IDs spanning 01…219**.
- `manifest.CURRICULUM_PROJECTS` has exactly **66 entries**, `15_binary_search_tree` … `80_trie`.
- Committed baselines by size: `arch_baseline.json` 429,368 B; `structural_baseline.json` 633,555 B; `defuse_baseline.json` 318,174 B; `baseline.json` 146,496 B; `stripped_divergences.json` 13,163 B.
- `structural.py` 519 lines, `defuse.py` 202 lines, `curriculum_oracle.c` (independent known-answer checks for `15_*`–`30_*`).
- `canary/` — 9 prebuilt `.so` lanes + `MANIFEST.json`: `03_loop_shapes-clang-O2`, `04_switch_shapes-gcc-O0`, `05_cleanup_and_state_machine-gcc-O0`, `07_packet_parser-gcc-O2`, `09_memory_effects-gcc-O2`, `13_loop_early_exit-gcc-O0`, `172_float_double_widths-gcc-O0`, `212_loop_with_returning_arm-gcc-O2`, `216_packed_union_wire_record-gcc-O0`.
- Matrix scope per its README: GCC/Clang O0/O2 for C and C++, rustc O0/O2 for Rust. `fixture_harness._fixture_sources` does **not** include the Go sources; the single `.S` serves a focused Rust CFG regression, not the Python matrix.

### 8.4 Other repo-root data trees

- **`data/`** — 9 files, 19 MB. `sigs/glaurung-base.x86_64.flirt.json` (8,819 B, the default `GLAURUNG_FLIRT_LIB`) and `types/`: `stdlib-winapi-protos.json` (**19,727,630 B** — essentially the whole 19 MB), `stdlib-libc-protos.json` (18,884 B), `stdlib-libc.json`, `stdlib-winapi.json`, `windows-api-sources.lock.json`, `overlays/windows-api-semantics.json`, `generated/MANIFEST.json`, `README.md`. This is what `GLAURUNG_TYPES_DIR` overrides.
- **`reference/`** — 114 files, 5.7 MB: `README.md` plus `specifications/` in 16 subdirs — `architecture` (14 files, 1.3M), `elf` (18), `pe-coff` (9, 1.2M), `security` (13), `tools` (11), `compression` (7), `archive` (4), `firmware` (7), `macho` (6), `wasm` (5), `kernel` (4), `samples` (4), `debugging` (3), `dynamic-linking` (3), `dotnet` (2), `java` (2). Mostly upstream headers and specs (41 `.h`, 11 `.md`, 10 `.txt`, 8 `.go`, 7 `.pdf`, 5 `.td`, 5 `.rst`, 4 `.c`). Its README records that **43 git submodules** (ghidra, angr, radare2, LIEF, ILSpy, …) were removed on 2026-08-31 because `uv`/`pip` cloned them transitively; they are now fetched on demand by `scripts/fetch-reference.sh`.
- **`java/`** — 9 files, 100 KB: one Maven module `java/glaurung-jvm-tools/` (`pom.xml`, 7 sources under `src/main/java/com/glaurung/jvmtool/` — `Args`, `AstSummary`, `BytecodeSummary`, `ClassInputs`, `Decompiler`, `Json`, `Main` — plus one test). An external JVM-side helper CLI emitting JSON bytecode/AST summaries and decompilation; built on demand by `python/glaurung/java/helper.py` unless `GLAURUNG_JVM_TOOLS_JAR` points at a prebuilt fat JAR.

---

## 9. Git history themes

**Scope.** `git log --since='5 months ago'` covers **2026-04-24 .. 2026-09-02**, **1,598 commits** (36 merges). The repository's first commit is **2025-08-29** ("Initial commit: Glaurung - Modern binary analysis framework"); **1,669 commits total**, so **96% of all history falls inside this five-month window**.

Monthly volume (all time) — a 2025 prototype, a six-month dormancy, then a sustained sprint:

| month | commits |
|---|---|
| 2025-08 | 29 |
| 2025-09 | 41 |
| 2025-10 | 1 (`IL/DC experiment notes`, then nothing until April) |
| 2026-04 | 116 |
| 2026-05 | 368 |
| 2026-06 | 44 |
| 2026-07 | 486 |
| 2026-08 | 518 |
| 2026-09 | 66 (2 days) |

June is a trough because the month's work was one long symbolic-execution branch.

### 9.1 Workstreams

Counts are approximate and overlap (a commit can be both "lifter" and "types").

**A. Source recovery / recompilation pipeline** — ~84 commits, 2026-04-24 .. 2026-08-31 (peak April). An orchestrator that takes a binary back to a compilable source tree, driven by a lettered bug ledger (Bug L … Bug HH).
- `2026-04-24 feat(recovery): v2 orchestrator with 8 fixes + cleaner hello-gcc-O2 output`
- `2026-04-26 fix(recovery): canonical libgfortran descriptor layout (Bug X)`
- `2026-04-26 fix(recovery): close the last xfail — every recovered tree builds (Bug EE)`
- `2026-04-26 test(recovery): project-wide build-gate across every recovered tree (Bug Z)`

**B. Analyst KB / CLI ergonomics** — ~39 commits, 2026-04-25 .. 2026-08-28. An April feature sprint against a numbered backlog (`#154`, `#165`, `#178`, `#180`, `#200`, `#226`, `#228`), then a late-August revival that wired the KB into the decompiler output path.
- `2026-04-25 feat(kb): undo/redo for analyst KB writes (Tier-S #228 v0)`
- `2026-04-25 feat(export): KB → JSON / Markdown / C header (Tier-B #165 v0)`
- `2026-08-28 kb: a rename in the project file never reached decompile`
- `2026-08-28 ir: an analyst's local names and types now reach the decompiled body`
- `2026-08-28 kb: the provenance ladder had two rungs, not seven`

**C. Windows port / PDB / driver security** — ~245 commits, 2026-05-16 .. 2026-09-01, but **221 of them in May 2026 alone** (15 June, 6 July, 1 August, 2 September). The densest burst in the log, and now the most dormant.
- `2026-05-16 analysis/cfg: recursive multi-pass discovery + Win64 .pdata seeds`
- `2026-05-17 windows-risk: track dynamic api dispatch flows`
- `2026-05-18 llm: precompute Windows CFG dominance summaries`
- `2026-05-25 ioctl_taint: propagate dispatcher nonnull set to orphan blocks`
- `2026-06-17 ioctlance iter12: model WDF WdfRequestRetrieveInputBuffer -> KMDF buffer taint`

**D. LLM agent + tool routing** — ~143 commits, 2026-04-24 .. 2026-08-28, with **129 in May** and only 9 after.
- `2026-04-24 feat(llm): 25-tool source-recovery ladder + orchestrator + first e2e run`
- `2026-05-18 llm: classify Windows call argument value roles`
- `2026-05-23 suggest_function_name: filter PE/CRT/WIL boilerplate from naming prompt`
- `2026-06-13 llm: match openai-responses: prefix for service-tier and tool routing`

**E. Java / JVM parsing and recovery** — ~86 commits, 2026-04-25 .. 2026-08-18, with **84 in May 2026**. A complete second front built in one month with exactly one commit since (a file split).
- `2026-05-15 Compile recovered Java projects with javac`
- `2026-05-15 Add Java xref query tools`
- `2026-05-16 Add archive decompilation and Java recovery foundations`
- `2026-05-16 Parse Java module extras and type annotations`
- `2026-08-18 analysis: split java_class.rs 2,644 -> 509, and a review that could never expire`

**F. Symbolic execution / SMT solvers / Axeyum** — ~92 commits, 2026-06-10 .. 2026-09-01 (22 June, 49 July, then near-zero).
- `2026-06-10 exec: native execution engine — concrete emulator + symbolic execution (Phases 0–6 cores)`
- `2026-06-10 symbolic: catch real driver bugs end-to-end (0->4 of 5 planted)`
- `2026-07-15 Report warm Axeyum snapshot reuse`
- `2026-07-17 symbolic: preserve DAG sharing in SMT-LIB traces`
- `2026-08-17 solver: fix all three backends, and gate the 11 feature configurations nobody built`

**G. Decompiler core — lowering, dataflow, rendering** — ~460 commits, dominated by 2026-07 (238) and 2026-08 (183). The largest cluster by far and the current center of gravity.
- `2026-07-23 ir: SSA-split reused temporaries + keep only the returned value bare (#1)`
- `2026-07-26 ir(call_args): stop inventing an argument the body never defines`
- `2026-08-14 ir: keep undecodable blocks instead of dropping them`
- `2026-08-15 ir: type the terminal edges and count the ones nothing explains`
- `2026-08-30 ir: the bit-demand fixed point swept forward over a backward analysis`

**H. Control-flow structuring** — ~103 commits, 2026-04-25 .. 2026-09-01 (72 July, 30 August).
- `2026-07-24 ir(structure): Step 2 — structure verifier for region/CFG coverage invariants`
- `2026-07-27 ir(loop): recover measured counted for loops`
- `2026-07-30 decompiler: fail closed on partial loop regions`
- `2026-07-31 decompiler: recover guarded rotated loops`
- `2026-09-01 tests: the jump-table defect is in structuring, and I had blamed the wrong pass`

**I. Type recovery, prototypes, ABI** — ~142 commits, 2026-04-25 .. 2026-09-01 (77 July, 65 August).
- `2026-04-25 feat(debug): DWARF type ingestion → type_db (#178)`
- `2026-07-29 feat(decompiler): recover prototype output by SSA value`
- `2026-08-06 fix(decompiler): make cross-arch C++ recovery ABI-honest`
- `2026-08-19 ir: aggregate returns and by-value parameters — 52 cells, and a passing test that passes by accident`
- `2026-09-01 pdb: a type lane, and the precise reason PDB types do not reach prototypes`

**J. Lifters and architecture coverage** — ~168 commits, 2026-04-25 .. 2026-09-01 (47 July, **84 August** — the peak).
- `2026-07-23 arm32: broaden Thumb-2 lifter coverage (scalar, mem-pair, IT blocks)`
- `2026-08-07 fix(decompiler): lift exact AArch64 CLZ semantics`
- `2026-08-14 ir: lift AArch64 scalar floating point`
- `2026-08-27 disasm: capstone puts the ARM shift on the operand, and 4,610 CFG edges went with it`
- `2026-09-01 arm32: Cortex-M system registers were undecodable, losing the whole function`

**K. Fixture corpus, gates, and the test estate** — ~275 commits, 2026-04-24 .. 2026-09-02 (84 July, **107 August**, 28 in two days of September).
- `2026-07-24 test: make the fixture harness a fail-closed semantic regression gate (review #10)`
- `2026-08-20 tests: binary-level adversarial lanes, and the corpus was handing us the answer`
- `2026-08-27 fixtures: the largest defect class could not fail a single cell in 205 fixtures`
- `2026-09-01 tests: 271 tests are compiled and never executed by any gate`
- `2026-09-02 tests: facet every test file by what it NEEDS, applied as markers at collection`

**L. DecBench evaluation** — ~63 commits, 2026-07-23 .. 2026-09-01 (25 July, 37 August).
- `2026-07-25 ir: narrow logical-shift casts through width-preserving arithmetic (decbench +2)`
- `2026-08-11 Correct DecBench GED v3 score ledger`
- `2026-08-27 decbench: score the whole sample-set without Joern, and the mean GED distance fell 30%`
- `2026-08-30 decbench: the completeness gate certified a partial corpus as complete`
- `2026-09-01 decbench: i386 stdcall bodies were in the binary all along (F1a, 33 rows)`

**M. Performance and allocation** — ~109 commits, concentrated 2026-08-20 .. 2026-08-31.
- `2026-08-20 analysis: the ELF prologue scan was applying an MSVC rule, and it cost 63% of the sweep`
- `2026-08-30 disasm: 12-16 allocations per decoded instruction, and perf could not see them`
- `2026-08-30 ir: invalidate was 85% of copy propagation, and its question is unanswerable early`
- `2026-08-30 benches: criterion over ir/ and analysis/, which had none at all`
- `2026-08-31 perf: use mimalloc for Rust allocations -- glibc malloc was 26% of a decompile`

**N. Codebase hygiene — file splits, fitness ratchet, dead code** — ~89 commits, 2026-07 .. 2026-09 (29 in August). Driven by `tools/fitness_baseline.json`; every split names its before/after LOC.
- `2026-08-17 symbolic: split axeyum_backend 3,357 -> 925, and it has not compiled in 17 days`
- `2026-08-18 python_bindings: split ir.rs 2,738 -> 1,422, and seven of eight PyO3 items would have been mis-cut by a keyword scan`
- `2026-08-19 fitness: a "no further split" licence must expire, and dec_render's had`
- `2026-08-31 refactor: split the four files a day of optimisation grew past their reviews`
- `2026-08-31 build: drop 44 git submodules -- they made uvx --from git+... unusable`

**O. Docs / diaries / roadmaps** — ~235 commits, 71 in July and **124 in August**. A distinctive practice: numbered diary entries recording measurements and frequently retracting the author's own earlier claims.
- `2026-08-16 docs: Entry 56 — my own hypothesis, weakened by a two-minute measurement`
- `2026-08-18 docs: diary entries 78-79 — two of my confident diagnoses, measured`
- `2026-08-27 docs: two of our three named decompiler defects were described backwards`
- `2026-08-31 CLAUDE.md: correct four claims this session disproved by checking them`
- `2026-08-31 docs: three traps that cost a day, recorded where the next person will look`

**P. CI** — ~13 commits, essentially all 2026-08-31 .. 2026-09-02. The newest workstream in the repository, days old.
- `2026-09-01 ci: install the cross toolchains those tests compile with`
- `2026-09-01 ci: run the symbolic engine's tests, which nothing had ever executed`
- `2026-09-01 ci: 60 minutes was not enough for the Python job`
- `2026-09-02 ci: run wheels where they are consumed, and run the corpus where fixtures exist`

### 9.2 What the last 30 days looked like

**577 commits between 2026-08-03 and 2026-09-02** — 36% of the five-month window in one month. 223 touch `src/ir/`, 257 touch `python/`. Four overlapping phases:

*Early August (3rd–20th)* — **cross-architecture decompiler correctness**: ARM32/AArch64 lifter semantics, SysV/i386 ABI honesty, aggregate returns, jump-table and switch structuring, each landing with a fixture-baseline ratchet.
*Mid-August (16th–19th)* — a **file-split and hygiene campaign** driven by the fitness ratchet, which incidentally discovered that all three SMT solver backends had not compiled in 17 days and that `--features python-ext` never builds `src/symbolic/`.
*Late August (20th–31st)* — a **profiling campaign** (real `perf`, allocation counting under a custom `GlobalAlloc`, Criterion benches introduced where there were none, mimalloc adopted after glibc malloc measured 26% of a decompile), alongside a **DecBench scoring audit** that found the published row was a coverage artifact.
*Final week (Aug 27 – Sep 2)* — a pivot to the **test estate and CI**: analyst-KB writes finally reaching the decompiled body, then a forensic audit finding 271 tests compiled but never executed, 33 tests asserting nothing, twelve test files that only found their fixtures from the repo root, 1,162 measured failures encoded as strict xfails, and the first real CI wiring in the project's history.

The tone throughout is self-correcting: a large fraction of subjects are of the form "X was wrong, and here is the measurement."

### 9.3 Most-changed source files (5-month window)

| commits | path | what it is |
|---|---|---|
| 197 | `src/ir/ast.rs` | C-like AST lowering for lifted functions (9,710 LOC — the single hottest file) |
| 155 | `src/python_bindings/ir.rs` | PyO3 bindings for the LLIR pipeline; the real pipeline entry point |
| 129 | `python/glaurung/llm/agents/memory_agent.py` | LLM agent + `register_analysis_tools` tool-registration surface (1,849 LOC) |
| 93 | `src/analysis/cfg.rs` | Bounded function discovery and CFG construction |
| 88 | `src/ir/lift_x86.rs` | x86/x86-64 → LLIR lifter |
| 71 | `src/ir/mod.rs` | LLIR core types and pass wiring |
| 70 | `src/ir/call_args.rs` | Reconstructs call arguments by folding preceding argument-register assignments |
| 66 | `src/ir/stack_locals.rs` | Promotes stack-relative memory accesses to named locals |
| 65 | `src/ir/types_recover.rs` | First-cut type recovery for VRegs |
| 56 | `python/tests/test_fitness_report.py` | The file-size fitness / large-module ratchet |
| 54 | `src/ir/structure.rs` | Structural analysis — recovers high-level control flow from the CFG |
| 50 | `src/symbolic/solver/axeyum_backend.rs` | Pure-Rust in-process SMT backend |
| 46 | `src/ir/value_number.rs` | SSA value numbering |
| 46 | `python/tests/test_decompiler_fixture_harness.py` | Tests the fixture harness itself is fail-closed |
| 43 | `src/symbolic/explore.rs` | Symbolic path exploration |
| 43 | `src/ir/copy_prop.rs` | Copy propagation + dead-copy elimination on the structured AST |
| 42 | `tools/diff_decompile.py` | Fail-closed execution-differential decompiler correctness gate |
| 42 | `tests/decompiler_fixtures/manifest.py` | Declarative oracle for the fixture corpus |
| 41 | `src/python_bindings/analysis.rs` | PyO3 bindings for the analysis surface |
| 41 | `src/ir/const_fold.rs` | Algebraic identity folding over the AST |
| 36 | `python/tests/test_cli_decompile.py` | Integration tests for `glaurung decompile` |
| 35 | `src/ir/name_resolve.rs` | Replaces bare VAs with symbol / PLT / IAT / Mach-O-stub names |
| 33 | `src/ir/dead_stores.rs` | Intra-body dead-store elimination |
| 33 | `python/glaurung/llm/kb/xref_db.py` | Persistent cross-reference database |
| 32 | `python/tests/test_decompiler_arch_roundtrip.py` | The only gate that *executes* cross-arch recovered code |
| 30 | `src/ir/naming.rs` | Role-based register renaming |
| 29 | `src/ir/strings_fold.rs` | Folds C-string literals into the AST |
| 29 | `src/ir/lift_arm32.rs` | ARM32/Thumb-2 → LLIR lifter |
| 29 | `examples/ioctlance.rs` | Dispatch-aware IOCTLance-style scanner for Windows drivers |
| 27 | `src/ir/loop_form.rs` | Recovers source-level loop forms |

(Paths are relative to `/home/mjbommar/projects/personal/glaurung/`.)

**Fourteen of the top thirty are `src/ir/*` decompiler passes.** That is the shape of the project right now.

**Baseline / generated-file churn** (excluded from the table above, but informative — their churn rate *is* the decompiler's change rate):

| commits | path |
|---|---|
| 92 | `tests/decompiler_fixtures/baseline.json` |
| 80 | `tests/decompiler_fixtures/arch_baseline.json` |
| 53 | `tools/fitness_baseline.json` |
| 43 | `tests/decompiler_fixtures/structural_baseline.json` |
| 22 | `tests/decompiler_fixtures/defuse_baseline.json` |

Note the ordering: `arch_baseline.json` is refreshed at 87% the rate of `baseline.json`, but `defuse_baseline.json` at only 24% — consistent with CLAUDE.md's warning that the def-use census is the baseline the iteration loop forgets.

**Docs churn** is concentrated in exactly the areas that are *no longer* being coded: `docs/windows-port/atomic-tools.md` (137), `docs/parsers/java/README.md` (71) and `JVM_AGENTIC_ANALYSIS_PLAN.md` (71), `docs/axeyum-integration/capture/README.md` (77). The high-churn *active* docs are `docs/design/decompiler-roadmap.md` (63) and the DecBench gap/remediation diaries (61 and 46).

### 9.4 Frontier: history vs CLAUDE.md

CLAUDE.md states the active frontier as: *decompiler quality (control-flow structuring, type-aware re-render), the Windows port (PDB ingestion/naming, `ioctl_taint`, `windows-risk`), analyst ergonomics, and the LLM vuln-discovery substrate (L1–L5 routing + F1–F7 cost guards).*

- **Decompiler quality — accurate, and understated.** Not one of four frontiers; essentially *the* frontier. ~460 core + ~103 structuring + ~142 type/ABI + ~168 lifter commits, 223 of the last 30 days' commits touching `src/ir/`, 14 of the 30 most-changed source files. Both named sub-areas are live through 2026-09-01.
- **Windows port — largely dormant.** 221 of 245 commits are in **May 2026**; June 15, July 6, August 1, September 2. `cli/commands/windows.py` and `windows_risk.py` were last touched functionally on **2026-07-28**; the only later commit was a repo-wide `ruff format`. `ioctl_taint`/IOCTLance work stops at **2026-06-17**. The one live thread is PE/PDB *symbolization as a decompiler input* (`2026-09-01 symbols: TLS callbacks were read from SizeOfZeroFill, so every PE had none`; `2026-09-01 pe: the resolver was blind to every shipped Windows binary`) — decompiler-correctness work that happens to run on PE, not `windows-risk` feature work.
- **Analyst ergonomics — briefly and recently revived, then paused.** Nothing May through Aug 26, then a concentrated 2026-08-28 burst. Real, recent, and small — roughly one day of work in five months, framed as plumbing analyst data into the decompiler rather than as its own track.
- **LLM vuln-discovery substrate — dormant.** 129 of ~143 LLM commits are in **May 2026**. The last routing-specific commit is `2026-06-13`. No commit in the window mentions L1–L5 or F1–F7 by those names. Built, then parked.

**What CLAUDE.md's frontier list omits and the log says is live:**

1. **DecBench scoring and corpus integrity** — 63 commits, all since 2026-07-23, 37 in August, still active 2026-09-01. CLAUDE.md discusses DecBench only as a boundary/cost caution.
2. **Performance and allocation** — a discrete late-August campaign that CLAUDE.md documents in its lessons but does not list as a frontier.
3. **Test estate, gate coverage, and CI** — the single most active thread in the last five days, and the first working CI in project history.
4. **Codebase hygiene / file splits** — ~89 commits with a dedicated ratchet and its own class of regressions.
5. **Symbolic execution / Axeyum SMT** — ~92 commits June–July, cold since 2026-08-19. Not mentioned in the frontier list at all despite being 26 files and 21K LOC.
6. **Java/JVM analysis** — 86 commits, an entire parallel capability built in May, unmentioned in CLAUDE.md and untouched since.

**One-line summary:** the log's frontier is **decompiler correctness (structuring, types, lifters) verified by an increasingly rigorous test/gate/CI estate, with DecBench scoring and performance as adjacent tracks**. Windows, LLM routing, Java and symbolic execution are completed-and-parked capabilities, not active frontiers.

---

## 10. In the docs but not in the code

Consolidated list of names a doc writer might inherit from `CLAUDE.md`, `AGENTS.md`, `README.md` or `docs/` that do **not** exist as written. Each row names the grep that establishes it. All greps run from `/home/mjbommar/projects/personal/glaurung`.

### 10.1 Missing outright

| name | claimed in | grep | reality |
|---|---|---|---|
| `python/glaurung/kb/` | `CLAUDE.md:23` ("the `kb/` knowledge base") | `ls -d python/glaurung/kb` → *No such file or directory*; `find . -type d -name kb -not -path './.venv/*' -not -path './target/*'` → `./python/glaurung/llm/kb` | The KB is `python/glaurung/llm/kb/` — a subpackage of `llm/`, not a peer. |
| `docs/data-model/` | `CLAUDE.md:377`; referenced **six times** inside `.claude/agents/rust-data-model-creator.md` (lines 3, 11, 17, 47, 110, 138) | `ls -d docs/data-model` → *No such file or directory* | The directory does not exist. The `rust-data-model-creator` subagent's entire method ("Read all documentation in docs/data-model/", "Follows all patterns from docs/data-model/") points at nothing. This is a **broken agent**, not just a stale doc line. |
| `GLAURUNG_AGENT_ROUTE` | `CLAUDE.md:368` | `grep -rn "GLAURUNG_AGENT_ROUTE" --include='*.py' --include='*.rs' --include='*.md' .` → 1 hit, `CLAUDE.md:368` | No reader anywhere. Routing is reachable only via `--route` or `tool_filter=`. |
| `--tools t1 t2` (an ask/agent flag) | `python/glaurung/llm/tool_routing.py:11` (the code's own docstring) | `grep -rn '"--tools"' python/glaurung/cli/` → 0 | No such flag. |
| `--max-parallel` | implied by `CLAUDE.md:365` ("lower `max_parallel` in `sweep_binary`") | `grep -rn "max_parallel" python/glaurung/` → 4 hits, all in `llm/cwe_sweep.py` | The parameter exists (default `1`) but is not reachable from any CLI flag. |
| An "L1" identifier | `CLAUDE.md:358` ("L1 findings runner") | `grep -rnoP '\bL1\b' python/glaurung/llm/ python/glaurung/cli/` → 1 hit, a comment at `cli/commands/ask.py:323` | L2–L5 are real docstring tags; L1 is not. The thing meant is `llm/findings_runner.py`, whose docstring never says L1. |
| `.claude/modules/` + `cm.py` | `CLAUDE.md:3-5` (says it "used to be compiled … that system has been removed") | `ls -d .claude/modules` → missing; `find . -name cm.py` → nothing | Correctly described as removed. Listed here so nobody goes looking. |
| Anthropic 4M-tokens/min handling | `CLAUDE.md:365` | `grep -rni "tokens/min\|rate.limit\|4_000_000" python/glaurung/llm/` → 1 incidental comment | No rate-limit constant, retry-after handling, or 4M literal in code. |
| `GLAURUNG_DECBENCH_KIT`, `GLAURUNG_RUN_HOLDOUT`, `GLAURUNG_RUN_LIVE_AGENT_TESTS`, `GLAURUNG_LOGFIRE`, `GLAURUNG_TRACE_PARSES`, `GLAURUNG_DEBUG_HOIST` | various `docs/` files (see §6.3) | see §6.3 | Six documented env vars with no reader. The live tests actually gate on `GLAURUNG_LIVE_LLM`. |

### 10.2 Present but in a different place or shape than documented

| name | documented as | actual |
|---|---|---|
| `ModelHyperparameters` | "Wired in `LLMConfig`" (`CLAUDE.md:349`) | Lives in `python/glaurung/llm/agents/base.py:28`, not `config.py`. |
| `ioctl_taint` | a Windows-port frontier item | **Exists** — `src/analysis/ioctl_taint.rs`, 1,511 LOC. Last functional commit 2026-06-17. |
| `windows-risk` | a Windows-port frontier item | **Exists** — CLI subcommand `windows-risk` → `python/glaurung/cli/commands/windows_risk.py`, 2,652 LOC. Makes no LLM call. Last functional commit 2026-07-28. |
| "the `windows analyst` LLM code path" (`CLAUDE.md:334`) | listed among "every LLM code path" | `python/glaurung/cli/commands/windows.py` (4,027 LOC) imports no `pydantic_ai`, has no `--model`, and its four agent modules' docstrings all read "Deterministic Windows … workflow". It is not an LLM code path. |
| `docs/development/project-structure.md`, `docs/design/decompiler-roadmap.md`, `docs/development/decompiler-testing.md`, `docs/development/decompiler-parity-backlog.md`, `docs/architecture/IDA_GHIDRA_PARITY.md`, `samples/README.md`, `docs/tutorial/_fixtures/01-install/help-head.out`, `.claude/agents/rust-data-model-creator.md`, `tools/{dectest,build_guard,compare_decompilers,gen_native_stub,decbench_matrix}.py`, `scripts/{decbench-local-gate,feature-build-gate,lint-rust}.sh` | all named in CLAUDE.md | **All present.** Verified by `ls`. |

### 10.3 Numbers in CLAUDE.md that the tree has outgrown

| claim | CLAUDE.md | measured 2026-09-02 |
|---|---|---|
| "~345 test files" (Python suite) | line 62 | **462** files in `python/tests/` (461 `test_*.py`) |
| "~125 test modules" (Rust) | line 65 | **276** files under `src/` with `#[cfg(test)]`; 3,022 `#[test]` fns |
| "~120 tests" behind `python-ext` | line 118 | 46 files carry `python-ext` gates; the count is not separable this way any more |
| "26 files, 21,459 product LOC" in `src/symbolic/` | line 137 | **exactly right** (26 files, 21,459 LOC) — the one number that is current |
| "the four Python entry points" | `pipeline.rs` docs | correct: `decompile_at`, `decompile_range_at`, `decompile_all`, `decompile_many` |
| "~163 tools" / "164 `tool_to_pyd_ai` calls" | `tool_routing.py:3`, `tools/base.py:57`, `memory_agent.py:667` | **219** registered (55 wrapper + 164 direct) |
| "seven-level `set_by` ladder (`manual/dwarf/stdlib/flirt/propagated/auto/borrowed`)" | line 27, and `provenance.py`'s own docstring | **twelve** values; adds `pdb`, `gopclntab`, `cil`, `ported`, `analyzer`; `dwarf`/`pdb`/`gopclntab` are deliberately *equal* rank |
| "`--route` … ≤30 tools/question" | line 363 | The ≤30 bound is asserted only on the *declared* tuple length; the largest intent declares 15 and only 7 survive filtering |
| "x86/x64, ARM/ARM64, RISC-V" disassembly *and* by implication decompilation | line 15-16 | Disassembly: yes (capstone covers RISCV/RISCV64, MIPS, PPC). **Decompilation: no RISC-V lifter** — `lift_function::supports_arch` is `X86 | X86_64 | AArch64 | ARM` only |

### 10.4 Code that exists but is unreachable in every build

| path | why |
|---|---|
| `src/io/` (`mod.rs`, `error.rs`, 335 LOC) | Not declared as a module in `src/lib.rs`. Compiles in no configuration. |
| `src/hashing/` (`mod.rs`, 62 LOC) | Same. |
| `src/data/tlds.txt` | No `include_str!` or other reference anywhere in `src/`. |
| `src/logging.rs`'s `RUST_LOG` filter | Reachable only through `glaurung.init_logging()`, which is exported but called by nothing outside a docstring. |
| `PreparedLlir::mir()` | `#[allow(dead_code)]`; verified typed MIR (`src/ir/mir/`, 4,550 LOC) has no production consumer. |
| `tool_routing._GRAPH_TOOLS`, `_VULN_FACT_TOOLS` | Defined but referenced by no `Intent`. |
| `LLMConfig.risk_scorer_model`, `.fallback_model`, `.fallback_on_error`, `.cache_responses` | Defined and never read anywhere in `python/`. |
| Cargo features `triage-core`, `triage-heuristics`, `triage-containers` | Declared in `Cargo.toml`; **zero** `cfg(feature = …)` sites in `src/`. `triage-core` is the default feature and gates nothing. |
