# Rust crate map

> **Kind:** architecture · **Status:** maintained

What is in `src/`, how big it is, and — the part that has caught people —
**which builds compile it**. Three of the thirteen Cargo features gate nothing
at all, one large subsystem is in neither the default build nor the shipped
wheel, and two directories are tracked in git and compiled by no configuration.

Every number below was measured at commit `13faa6f7` with the command shown
beside it. Re-run the command rather than trusting the number; the tree has
grown 46% under a note that stood still before.

```bash
find src -name '*.rs' | xargs wc -l | tail -1        # 489 files, 290,841 lines
find src/<dir> -name '*.rs' | xargs wc -l | tail -1  # one directory
```

## The whole tree at a glance

`[package] name = "glaurung"`, `edition = 2021`,
`crate-type = ["cdylib", "rlib"]`. `mimalloc` is wired as the
`#[global_allocator]` in `src/lib.rs`; the allocator was 26% of a release
decompile profile, so this is a load-bearing line rather than a preference.

| directory | files | lines | what it owns | built by |
|---|---:|---:|---|---|
| `ir/` | 202 | 164,779 | LLIR, AST, every decompiler pass, all three lifters, all renderers | default |
| `analysis/` | 57 | 28,334 | CFG and function discovery, xrefs, jump tables, exception tables, IOCTL surfaces, format-specific resolvers | default |
| `symbolic/` | 26 | 21,459 | symbolic/concolic execution over the emulator's `Domain`; hash-consed bitvector `Expr` IR and the solver layer | **`symbolic` only** |
| `core/` | 34 | 16,924 | the primitive data model — `Address`, `Binary`, `Section`, `Symbol`, `Function`, `BasicBlock`, the graphs, `DataType`, `Artifact` | default |
| `python_bindings/` | 20 | 10,511 | the PyO3 surface, one module per subsystem | **`python-ext`** |
| `formats/` | 38 | 10,477 | PE, ELF, DEX, AXML, APK, SELinux policy parsers | default (two arms gated) |
| `program/` | 23 | 8,951 | program-scoped ownership: `ProgramImage`, `ProgramSession`, symbols, types, references, call graph, spans | default |
| `triage/` | 21 | 8,008 | bounded deterministic first-touch analysis: sniffing, header validation, entropy, packers, containers, confidence | default |
| `symbols/` | 13 | 4,645 | symbol extraction per format, including `pdb.rs` (1,629 lines) | default |
| `exec/` | 10 | 3,591 | the concrete emulator over LLIR | **`exec`** (⊂ `python-ext`) |
| `strings/` | 11 | 3,260 | bounded string scanning, IOC classification, language detection | default |
| `debug/` | 3 | 2,423 | DWARF ingestion only — PDB is in `symbols/`, not here | default |
| `disasm/` | 5 | 1,751 | decoder adapters (iced-x86, capstone) and the backend registry | default |
| `unpack/` | 3 | 1,269 | static recovery of a packed image (`upx.rs`, `nrv.rs`) | default |
| `target/` | 5 | 956 | one validated `TargetSpec`: arch, ABI, width, register roles, code mode | default |
| `entropy/` | 4 | 840 | Shannon entropy and sliding-window analysis | default |
| `similarity/` | 1 | 336 | CTPH fuzzy hashing, BLAKE3-XOF based (deliberately not ssdeep, to avoid GPL) | default |
| `decompile/` | 2 | 235 | `parse_object` and the run/function profilers — small, and every entry point opens its image through it | default |
| `demangle/` | 1 | 123 | Itanium and Rust demangling; MSVC is detected and passed through | default |
| loose files | 6 | 1,250 | `lib.rs` 265, `timeout.rs` 238, `winmd.rs` 203, `logging.rs` 188, `testing.rs` 190 (`cfg(test)`), `error.rs` 166 | default |

`flirt/` (1 file, 322 lines) rounds out the list: FLIRT-style prologue matching
against a JSON library built by `glaurung.tools.build_flirt_library`.

## Features, and what each one actually gates

```bash
sed -n '/^\[features\]/,/^\[/p' Cargo.toml
rg -o 'feature = "<name>"' src/ | wc -l          # occurrences
rg -l 'feature = "<name>"' src/ | wc -l          # files
```

| feature | pulls in | `cfg` sites in `src/` | what it gates |
|---|---|---:|---|
| `default` | `triage-core` | — | — |
| `triage-core` | — | **0** | Nothing. It is the default feature and it gates no code. |
| `triage-heuristics` | — | **0** | Nothing. |
| `triage-containers` | — | **0** | Nothing. |
| `triage-parsers-extra` | `goblin`, `pelite` | 4 in 1 file | The goblin/pelite secondary parsers in `src/triage/parsers.rs`. |
| `python-ext` | `pyo3`, `pyo3/extension-module`, `exec` | 279 in 46 files | All of `src/python_bindings/`, `src/disasm/py_api.rs`, and the `#[pyclass]`/`#[pymethods]` blocks scattered through `core/`, `triage/`, `strings/`. |
| `exec` | — | 3 in 2 files | `src/exec/` and `src/python_bindings/exec.rs`. **Included in `python-ext`**, so the shipped wheel has the concrete emulator. |
| `symbolic` | `exec` | 2 in 2 files | `src/symbolic/`, 21,459 lines behind one `cfg` in `src/lib.rs`. In neither `default` nor `python-ext`. |
| `dev-oracle` | `exec`, `dep:unicorn-engine` | 1 | `src/exec/oracle.rs`, a differential test against system libunicorn. Never shipped. |
| `solver-z3` | `symbolic`, `dep:z3` | 49 in 5 files | The z3 backend under `src/symbolic/solver/`. |
| `solver-axeyum` | `symbolic`, `dep:axeyum-solver`, `dep:axeyum-ir` | 57 in 5 files | The pure-Rust QF_BV backend. |
| `solver-bitwuzla` | `symbolic` | 33 in 3 files | A benchmark-only C-API cell, deliberately outside production backend selection. |
| `solver-axeyum-text` | `solver-axeyum`, `axeyum-solver/full` | 8 in 1 file | The legacy SMT-LIB text bridge. |

Three of the four `triage-*` features are inert markers. They are declared,
they appear in `fuzz/Cargo.toml`'s feature list, and no `#[cfg]` in `src/` ever
reads them.

## Reachability: what each build compiles

This is the table to check before believing a green build.

| command | compiles | does **not** compile |
|---|---|---|
| `cargo build` / `cargo test` | everything except the column at right | `python_bindings/`, `disasm/py_api.rs`, `exec/`, `symbolic/`, the goblin/pelite arms of `triage/parsers.rs` |
| `cargo test --features python-ext` | + `python_bindings/` (10,511 lines) and `exec/` (3,591) | **still not `symbolic/` (21,459 lines) or any solver backend** |
| `cargo check --features python-ext --lib` | product code only | `#[cfg(test)]` modules — so a test-only call site on a stale signature passes `check` and fails `test` |
| `maturin` / the shipped wheel | `pyo3/extension-module` + `python-ext`, hence `exec` | `symbolic/` and every solver |
| `cargo test --features symbolic` | + `symbolic/` | the solver backends, unless one is also named |
| `scripts/feature-build-gate.sh` | 12 `cargo check --all-targets` lanes covering every combination above **and `fuzz/`** | — |

`[tool.maturin]` in `pyproject.toml` sets
`features = ["pyo3/extension-module", "python-ext"]`, which is where the
"wheel has `exec` but no `symbolic`" fact comes from.

The practical rule: `cargo check` is the inner loop, `cargo test --features
python-ext` is what says a refactor is done, and
`scripts/feature-build-gate.sh` is what says a feature-gated tree still
builds. See [`../development/testing-gates.md`](../development/testing-gates.md)
for where each of those runs.

## `src/ir/` — the decompiler, one level down

`ir/` is 57% of the crate. The file-plus-directory pairs are the Rust 2018
layout: `foo.rs` is the module and `foo/` holds its submodules, so both rows
below are real and separate.

| subdirectory | files | lines | + the module file |
|---|---:|---:|---|
| `ast/` | 18 | 12,519 | AST lowering and **every renderer**: `c_render.rs`, `ctx_render.rs`, `decbench_render.rs`, `dec_render/`, plus `lower_region`, `lower_conds`, `declaration_plan`, `return_ctype`, `param_spills`, `float_gate`, `width_semantics`, `abi_widths`, `dwarf_render_types`, `named_calls`, `prepare`, `return_folds` — with `ast.rs` at 9,710 |
| `lift_x86/` | 11 | 5,455 | `lift_x86.rs` 9,556 |
| `mir/` | 9 | 4,550 | verified typed mid-level IR: `builder`, `model`, `memory`, `query`, `verify`, `verify_objects`. Built on demand via `PreparedLlir::mir`; **no production consumer** — the code carries `#[allow(dead_code)]` and says so |
| `stack_locals/` | 10 | 4,522 | stack-slot promotion; `stack_locals.rs` 4,928 |
| `copy_prop/` | 9 | 3,298 | `copy_prop.rs` 1,536 |
| `call_args/` | 8 | 3,024 | argument reconstruction; `call_args.rs` 5,699 |
| `memory_objects/` | 6 | 2,930 | inferred memory objects and affine access paths |
| `structure/` | 8 | 2,604 | `cfg`, `region`, `if_shape`, `loop_shape`, `switch_shape`, `path_predicates`, `fallback`, `verify`; `structure.rs` 3,032 |
| `types_recover/` | 5 | 2,506 | `types_recover.rs` 5,539 |
| `value_number/` | 7 | 2,065 | `value_number.rs` 2,692 |
| `lift_arm32/` | 7 | 1,539 | `lift_arm32.rs` 4,030 |
| `lift_arm64/` | 3 | 1,476 | `lift_arm64.rs` 3,598 |
| `abi/` | 2 | 539 | `abi.rs` 1,823 |
| `structured_reaching/`, `lazy_call_select/`, `ast_tests/`, `readonly_fold/` | 1–4 | 111–511 | |

Three lifters, not five: `lift_function::supports_arch` accepts
`X86 | X86_64 | AArch64 | ARM`. The disassembler covers more architectures than
the decompiler does — capstone decodes MIPS, PowerPC and RISC-V, and none of
them can be lifted.

For the ordered pass list read
[`../reference/decompiler-passes.md`](../reference/decompiler-passes.md), which
is generated from the two functions that hold it; for what the stages mean read
[`decompiler-pipeline.md`](decompiler-pipeline.md).

## `src/analysis/` — one level down

| subdirectory | files | lines | |
|---|---:|---:|---|
| `cfg/` | 19 | 8,327 | the discovery pipeline, documented as a table in `src/analysis/cfg.rs`: `packed` → `image_view` → `budgets` → `scan`/`entry_shape`/`pe_tables`/`plt`/`seeds` → `worklist` → `body_index` → `walk`/`ctrl_flow`/`extents`/`function_build`/`repair`/`must_dataflow`/`dispatch_flow`/`dispatch_resolution`/`stats`; `cfg.rs` 1,992 |
| `java_class/` | 7 | 2,263 | JVM classfile parsing; `java_class.rs` 666 |
| `dispatch/` | 3 | 665 | indirect-branch target-set resolution; `dispatch.rs` 2,161 |
| `linux_ioctl/` | 1 | 105 | `linux_ioctl.rs` 340 |

Loose modules worth knowing by name: `ioctl_taint.rs` (1,511 — WDM driver
abstract interpretation, see [`ioctl-taint.md`](ioctl-taint.md)),
`exception.rs` (1,315), `xrefs.rs` (1,304), `jump_table.rs` (1,026),
`linux_symbolic_frontend.rs` (871), `ioctl_surface.rs` (769), `elf_plt.rs`
(701), `pe_iat.rs` (571), `cil_metadata.rs` (447, .NET), `vtable.rs` (435),
`macho_stubs.rs` (401), `java_jar.rs` (353), `lua_bytecode.rs` (279),
`gopclntab.rs` (248, Go), `elf_got.rs` (225), and `completeness.rs` (141,
which turns "a budget fired" into a note the reader can see).

## `src/python_bindings/` — the PyO3 surface

Built as `glaurung._native`; the stubs beside it are generated
(see [`python-package-map.md`](python-package-map.md)).

| file | lines | registers |
|---|---:|---|
| `ir.rs` + `ir/` | 2,496 + 4,303 | the decompiler entry points, and the AST pass order |
| `analysis.rs` | 1,908 | CFG and function discovery, xrefs, call graph |
| `strings.rs` | 388 | |
| `debug.rs` | 342 | DWARF |
| `symbols.rs` | 301 | |
| `similarity.rs` | 166 | |
| `triage.rs` | 161 | |
| `exec.rs` | 124 | gated on `exec` |
| `unpack.rs` | 110 | |
| `core_types.rs` | 110 | |
| `mod.rs` | 45 | `register_python_bindings`, calling the rest in a fixed order |
| `disasm.rs` | 34 | |
| `winmd.rs` | 23 | |

`src/lib.rs` also defines three `#[pyfunction]`s directly:
`symbol_address_map`, `symbol_table_entries`, `pe_export_entries`.

`python_bindings/ir/pipeline.rs` (532 lines) holds the AST pass ordering. That
is a known boundary violation, not an intention —
see [`module-boundaries.md`](module-boundaries.md).

## `src/formats/`

| subdirectory | files | lines | contents |
|---|---:|---:|---|
| `pe/` | 11 | 4,365 | `headers`, `sections`, `types`, `utils`, and `directories/` (`export`, `import`, `resource`, `debug`, `tls`) |
| `elf/` | 13 | 4,172 | `headers`, `sections`, `segments`, `dynamic`, `relocations`, `packed_relocations`, `notes`, `symbols`, `eh_frame_segment`, `types`, `utils` |
| `axml/` | 5 | 785 | Android binary XML |
| `dex/` | 4 | 675 | Android DEX |
| `apk/` | 2 | 283 | APK/AAB/JAR member extraction over the ZIP central directory |
| `sepolicy/` | 2 | 189 | SELinux policy |

**There is no `src/formats/macho/`.** Mach-O support lives in
`src/symbols/macho.rs`, `src/analysis/macho_stubs.rs`, and through the `object`
crate in `src/decompile/profile.rs`.

## Benchmarks, fuzzers, examples

`benches/` — 10 Criterion benches, `harness = false`: `ir_lift`,
`ir_dataflow`, `ir_structure`, `analysis_cfg`, `decompile_pipeline`,
`lang_detect`, `triage`, `strings`, `entropy`, and `emulator`
(`required-features = ["exec"]`). They are diagnostic: Criterion here has no
stored baselines.

`fuzz/` is a **separate crate**. Its manifest depends on `glaurung` with
`default-features = false, features = ["triage-core", "triage-heuristics",
"triage-containers"]` — a narrower configuration than anything else in the
repository, and one that no root-manifest `cargo check` can see. It is the last of the
twelve `scripts/feature-build-gate.sh` lanes for exactly that reason. Eight targets:
`disasm_decode`, `demangle_all`, `formats_parse`, `sniffers_sniff`,
`entropy_analyze`, `containers_detect`, `headers_validate`, `parsers_parse`;
`fuzz/seed_corpus.py` seeds them from the repository's own binaries.

`examples/` — 15 Rust examples. Nine carry a `required-features` line in
`Cargo.toml` (`ioctl_scan`, `ioctlance`, `linux_symbolic_cve`,
`ordered_native_replay`, and five `axeyum_*` drivers); the other six
(`ast_demo`, `check_canary`, `check_prologue`, `test_classifier`,
`ioctl_surface_scan`, `linux_symbolic_frontend`) build in the default
configuration. Five Python examples sit alongside them.

## Tracked but never compiled

```bash
rg -n 'mod io|mod hashing' src/lib.rs     # no match
rg -l 'tlds.txt' src/                     # no match
```

| path | lines | why |
|---|---:|---|
| `src/io/` (`mod.rs`, `error.rs`) | 335 | Not declared as a module in `src/lib.rs`. Compiles in no configuration. |
| `src/hashing/` (`mod.rs`) | 62 | Same. |
| `src/data/tlds.txt` | — | No `include_str!` or any other reference in `src/`. |

Two more things exist and are unreachable in practice rather than by the build:
`PreparedLlir::mir()` carries `#[allow(dead_code)]` over 4,550 lines of
verified typed MIR with no production consumer, and `src/logging.rs`'s
`RUST_LOG` filter is reachable only through `glaurung.init_logging()`, which
nothing outside a docstring calls.

## Dependencies worth knowing

`pyo3 0.26`, `object 0.37`, `gimli 0.33`, `pdb 0.8`, `iced-x86 1.20`,
`capstone 0.12`, `goblin 0.10` / `pelite 0.10` (optional), `rayon`, `memmap2`,
`blake3`, `cpp_demangle` / `rustc-demangle` / `msvc-demangler`,
`windows-metadata 0.60`, `whatlang`, `flate2`, `mimalloc`. The z3, axeyum and
unicorn dependencies are all `optional = true` and reachable only through the
features above.

The feature list itself is generated into
[`../reference/cargo-features.md`](../reference/cargo-features.md), and the
environment variables each build reads into
[`../reference/environment-variables.md`](../reference/environment-variables.md).
