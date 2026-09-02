# The decompiler pipeline

> **Kind:** architecture · **Status:** maintained

How a byte range becomes C. This document describes the pipeline **as built**,
names the file that owns each stage, states the design rules the code embodies,
and — in [§7](#7-built-vs-not-built) — says plainly which parts of the intended
architecture do not exist yet.

The ordered pass list is not here. It is generated from the source into
[`../reference/decompiler-passes.md`](../reference/decompiler-passes.md) by
`tools/gen_pass_reference.py`, so it cannot drift. This file explains why the
order is what it is.

Every path and symbol below was checked against the tree; the commands are in
[Appendix A](#appendix-a--verification-commands).

---

## 1. One entry point, four Python functions

The whole decompiler is reached through `src/python_bindings/ir.rs` and its
submodule tree `src/python_bindings/ir/`. There is no Rust-level `Decompiler`
trait and no engine plug-in seam: `src/decompile/` holds only run profiling.

| `#[pyfunction]` | `src/python_bindings/ir.rs` | what it decompiles |
|---|---|---|
| `decompile_at` | line 108 | one function, by entry VA |
| `decompile_range_at` | line 510 | an explicit `[start, end)` range |
| `decompile_all` | line 942 | up to a budget of discovered functions |
| `decompile_many` | line 1222 | an explicit VA list, one analysis pass |
| `take_render_verification` | line 1639 | drains render-verification diagnostics |

`src/python_bindings/ir/lift.rs` additionally exposes `lift_bytes` and
`lift_window_at`, which return raw LLIR as dicts and run no pipeline at all.

**The four are deliberately identical.** They share one copy of the LLIR
preparation (`prepare_llir_for_lowering`) and one copy of the AST pass list
(`run_ast_passes`), both in `src/python_bindings/ir/pipeline.rs`, whose module
doc states the reason: *"One copy of the pass list, one copy of the LLIR
preparation, so the four Python entry points cannot drift into different value
models."* That is not a hypothetical. The same file records that a loop-hoist
retry once landed in one of four copy-pasted pass lists and silently did nothing
in the other three — which is exactly how a real fix gets measured as
ineffective. The same rule covers the pass-by-pass debug dump: it is read inside
`run_ast_passes`, so every entry point gets identical diagnostics rather than
only the one that happened to carry the macro.

The consequence for contributors is the one `CLAUDE.md` states: `cargo test`
without `--features python-ext` does not compile this tree, and most passes are
only reachable through it.

### The CLI surface

`glaurung decompile` (`python/glaurung/cli/commands/decompile.py`) selects among
the four: `--func` / default entry → `decompile_at`, `--range-start/--range-end`
→ `decompile_range_at`, `--all` → `decompile_all`, `--vas` → `decompile_many`.
The output contract is in
[`../reference/decompiler-output-format.md`](../reference/decompiler-output-format.md).

---

## 2. Stage 0 — image, discovery, naming

Everything before the IR stages, inline in `decompile_at_session`
(`src/python_bindings/ir.rs`). In source order:

1. `RunProfiler::from_env("decompile_at")` — opt-in phase profiling
   (`src/decompile/profile.rs`).
2. `ProgramSession::from_path` → `ProgramImage` (`src/program/`). **One owner
   parses the image.** Passes ask the session; they never reopen the object.
3. `image.normalize_function_entry(func_va)` strips the ARM32 Thumb bit
   (`src/analysis/arm32_mode.rs`). A symbol's value carries that bit; decoding
   one byte in recovers a body with no parameters at all.
4. `image.exception_call_sites()` — Itanium LSDA call sites
   (`src/analysis/exception.rs`).
5. DWARF output contracts and the type environment
   (`src/python_bindings/ir/dwarf_contracts.rs`, `src/ir/dwarf_type_env.rs`) —
   **only when `style == "decbench" && types`**.
6. `Budgets { max_functions, max_blocks, max_instructions, timeout_ms }`.
7. `py.detach(|| session.discover_functions(&budgets, &[func_va]))` — whole-binary
   CFG discovery (`src/analysis/cfg/`), with the GIL released so Ctrl-C works.
8. `target_calling_convention(&image)` → `CallConv` — and the capability gate
   (§3).
9. `name_resolve::collect_address_map_with_pdb_cache_and_data_symbols` — **one**
   image parse yielding both call-target names (symbols, PDB cache, PE
   exports/IAT) and named static storage, then `add_discovered_function_names` /
   `add_referenced_function_names`. Two parses tripped the object-parse ceiling.
10. `lift_function_from_image` → the raw `LlirFunction`.
11. `soft_helpers::inline_soft_helper_calls` — libgcc division helpers expanded
    to the arithmetic they perform. **Must be on raw LLIR**, before ABI
    annotation and before SSA, because the expansion is written in terms of the
    architectural argument registers.
12. `abi::annotate_calls` then `call_contracts::apply_known_llir_call_contracts` —
    call effects recorded on the call itself, **before SSA**, so a call
    participates in def/use like any other instruction instead of every later
    pass special-casing it.
13. `function_tables::collect_function_pointer_tables` — relocation-proven
    function-pointer tables.
14. `session.call_graph_for(...)` + `recover_direct_callee_layouts`
    (`src/python_bindings/ir/callee_contracts.rs`) — bounded, demand-driven
    interprocedural callee layout and prototype recovery. The call graph is
    built from the functions already fetched at step 7, so one logical query
    registers one discovery-cache hit rather than two.
15. **The analyst overlay is applied here and not earlier.** Everything between
    step 9 and step 14 resolves callees *by name* against what the binary calls
    them. Renaming `validate` to `parse_packet_hdr` before those run means they
    look up a name no symbol source knows, find nothing, and downgrade a
    recovered `int validate(char *, int)` to `long f(void)` at every call site.
    A rename is a presentation decision, so it lands after the analysis that
    depends on binary truth (`name_resolve::apply_analyst_names`,
    `SymbolEnv::rename_display`).

---

## 3. Architectures and calling conventions

`src/ir/lift_function.rs:199` is the authority:

```rust
pub fn supports_arch(arch: Arch) -> bool {
    matches!(arch, Arch::X86 | Arch::X86_64 | Arch::AArch64 | Arch::ARM)
}
```

Three lifters back that set:

| lifter | files | covers |
|---|---|---|
| `src/ir/lift_x86.rs` + `src/ir/lift_x86/` (11 modules) | plus `src/ir/x87.rs` for x87 floating point | x86 and x86-64 |
| `src/ir/lift_arm64.rs` + `src/ir/lift_arm64/` | | AArch64 |
| `src/ir/lift_arm32.rs` + `src/ir/lift_arm32/` | | ARMv7 / Thumb-2 |

**There is no RISC-V, MIPS or PowerPC lifter.** Those architectures exist in
`Arch` (`src/core/binary.rs:64`) and are reachable through
`src/disasm/capstone.rs` for *disassembly*, but `supports_arch` rejects them and
`target_calling_convention` raises
`ValueError("LLIR decompiler does not support target …")`. A capability gap
presents as a typed refusal, never as an empty body.

`validate_code_mode` runs before any byte is decoded and rejects incoherent
`(arch, thumb)` pairs. `LiftError` distinguishes `UnsupportedArchitecture` /
`IncoherentCodeMode` / `NoLiftableBlocks`, and `affected_ranges()` names the VA
ranges that were lost, so a caller can tell a capability gap from data loss.

Six calling conventions, all reachable, assigned in `src/target/spec.rs:107-112`:

| target | `CallConv` |
|---|---|
| x86-32 | `Cdecl32` |
| x86-64, Windows ABI | `Win64` |
| x86-64, otherwise | `SysVAmd64` |
| AArch64 | `Aarch64` |
| ARM32, hard float | `ArmHardFloat` |
| ARM32 | `Arm` |

ARM32 is a conformance architecture, not an afterthought: the ARM32 frame
recogniser, the VFP argument rule, and the Thumb-bit normalisation are all in
the shared path rather than bolted on.

---

## 4. Stage 1 — LLIR preparation

`prepare_llir_for_lowering`, `src/python_bindings/ir/pipeline.rs`. The generated
reference tabulates the calls; the shape is:

```
exception edges -> SSA -> bit-demand oracle -> erase proof-dead lanes
                              |
                        (if anything was erased: rebuild and recompute SSA)
                              |
   provisional parameter slots -> prototype recovery -> registration-API merge
                              |
             materialize_return_values -> (if it changed anything: SSA again)
                              |
        resolve_indirect_jumps -> structure::recover_verified_with_health…
                              |
     value numbering with DWARF register lifetimes -> lock parameter slots
```

Three things in that sequence are load-bearing and easy to get wrong:

- **SSA is recomputed on purpose, twice at most.** Prototype recovery needs
  initial SSA and parameter evidence; a proven direct output then upgrades
  operand-free machine returns to explicit LLIR uses, so SSA and the definedness
  oracle must run again before value numbering and structuring. Keeping that
  feedback edge in the shared helper is what stops `--all`, `--vas` and
  address/range decompilation from observing different return identities.
- **Debug declarations outrank a registration-API fact.** A
  `FunctionPrototypeFact` from `ProgramEnvironment` is merged only where local or
  debug recovery did not already lock arity or output, so conflicting evidence
  fails closed rather than being averaged.
- **Structuring happens here, on LLIR, not on the AST.** `recover_verified_with_health_and_destinations`
  returns `(Region, CfgHealth)`; the AST is lowered *from* the region tree.

The result is `PreparedLlir { region, cfg_health, numbered, definition_widths,
parameter_slots, prototype }`.

---

## 5. Stage 2 — the ordered AST passes

`lower(&lf, &region, outer_name)` (`src/ir/ast.rs`) produces the AST from the
region tree. Then `exception_recover::mark_landing_pads`, the string pool
(`strings_fold::collect_string_pool_from_image`), the read-only data facts
(`readonly_data_for` → `src/ir/readonly_fold.rs`) and the ELF GOT target map
(`src/analysis/elf_got.rs`) are collected, and `run_ast_passes` runs the list.

Every step is wrapped in a `pass!` macro that (a) times it through
`FunctionProfiler`, (b) calls `ir::health::trace_pass`, and (c) prints the
rendered body when `GLAURUNG_DUMP_PASSES` is set. **A transform that is not named
is a transform the health report cannot attribute** — `tools/pass_health_report.py`
blames the first pass at which a counter moves, so an unnamed transform's damage
is charged to whichever named boundary observes it.

The full table is generated; what a reader needs is the *ordering constraints*,
which are the actual design content:

| constraint | why |
|---|---|
| wide-copy recovery runs **first** | packed XMM moves lift as four scalar lanes so the arithmetic stays analyzable; copy propagation erases the 16-byte transport identity if it gets there first |
| per-definition flag pruning before per-name | flags are un-versioned, so one read keeps every write of that name alive; the per-name pass cannot see a write an unread overwrite supersedes |
| GOT folding **before** name resolution | otherwise a symbol attaches to the linkage word rather than to the address the slot will hold |
| argument reconstruction **after** tail-call recovery | a resolved terminal jump must become a call before the backward argument scan can see its register setup |
| an authoritative library prototype outranks ABI liveness | ABI liveness supplies candidates; a known prototype is a fact. This is Ghidra's locked `FuncProto` model, and the alternative is asking the C renderer to paper over a semantically impossible AST |
| stack-slot promotion **before** naming | `stack_N` / `local_N` must be allocated before `arg0` / `ret` / `varN` exist, or the two namespaces collide |
| direct-output materialisation while the raw ABI register still exists | ARM32/AArch64 reuse `arg0`'s register for the result; the later spill-role split must rename the definition and the return use together |
| dead-store elimination **after** naming | it needs to see `ret` / `arg0` rather than the physical register, which is what kills the pre-call `%ret = 0` idiom |
| the machine-frame recogniser runs twice | stack-idiom rematerialisation can expose a second canonical epilogue spelling. Each recogniser is idempotent and fail-closed when the frame is not exactly balanced |

Architecture dispatch inside the list is by `CallConv`, not by a parallel
pipeline: `recognise_machine_frame` selects `x86_prologue` for
`SysVAmd64`/`Win64` and `arm32_prologue` for `Arm`/`ArmHardFloat`, then runs
`dead_stores::prune_callee_saved_spills` for *every* convention including
AArch64, which has no dedicated recogniser in that match. AArch64's prologue
recogniser is instead folded into the dead-store pass.

---

## 6. Stage 3 — post-pipeline, type projection, render

After `run_ast_passes`, still in `src/python_bindings/ir.rs`:

- the analyst's own frame-slot names and types (`stack_locals::apply_analyst_locals`),
  joined by frame offset and applied through the **same** mechanism DWARF names
  use, so an analyst rename gets the same rejection a bad DWARF name gets;
- DWARF register locals merged into the stack facts;
- exception recovery for `--style decbench`
  (`exception_recover::{recover_typed_handlers, mark_int_throws_with_address_map, recover_throws}`);
- `recognise_machine_frame` again;
- PDB field annotation and the PDB public-symbol map when a cache is configured;
- `analysis::completeness::cfg_incompleteness_note` — a rendered note when a
  discovery budget fired, so truncation is **visible in the output** rather than
  silent.

### Type-map projection

Type recovery produces facts keyed by machine **storage** (`rdi`, a frame
offset). The renderer needs them keyed by AST **role** (`arg0`, `ret`,
`local_8`). `src/python_bindings/ir/type_maps.rs` does that projection:
`decbench_type_maps` for `style="decbench"`, `remap_type_map` for plain
`types=True`. Refinements applied on the way: promoted slot sizes, exact
definition widths, DWARF source types, per-value SSA evidence, and a float-copy
fixed point.

Type recovery deliberately runs on the **raw** LLIR, not the numbered one:
value numbering canonicalises `edi` → `rdi`, and the sub-register width is *the*
`-O0` type signal. Two LLIRs are kept alive for exactly this reason — which is
also the clearest symptom of the value-model defect in [§7.2](#72-the-root-cause-that-is-still-open).

### Render styles

| `--style` | native token | renderer | file |
|---|---|---|---|
| `plain` (default) | `""` | `ast::render` / `ast::render_with_types` | `src/ir/ast/ctx_render.rs:639,733` |
| `c` | `"c"` | `ast::render_c` | `src/ir/ast/c_render.rs:51` |
| `decbench` | `"decbench"` | `render_decbench` and five progressively richer variants | `src/ir/ast/decbench_render.rs:45-130` |

`style == "decbench"` is **a behaviour fork, not a formatting switch**. It alone
turns on DWARF output contracts, the DWARF type environment, the program
environment, semantic prototype recovery, and the ~25-step refine chain in
`src/python_bindings/ir/decbench_render.rs`.

That chain ends at a named boundary, `ready_to_render`, followed by
`verify_defs::verify_before_render` on the AST that is **about to be printed** —
which is what makes the verdict trustworthy. The verdict leaves the boundary
through three channels ranked by what they cost the consumer:

- always: `health::record_render_verification`, which `take_render_verification`
  reports and the CLI turns into one stderr line. The emitted C is unchanged, so
  this channel can be unconditional.
- `GLAURUNG_PASS_HEALTH`: the same count as `undefined_uses` on the
  `ready_to_render` event.
- `GLAURUNG_VERIFY_DEFS`: each violation spliced in as a `// glaurung-verify:`
  comment. Opt-in, because the decbench render is an artifact other tools parse
  and score, and a comment announcing our own bug inside it is instrumentation
  leaking into a submission.

Reporting rather than erroring is deliberate: a violation means *that function's*
decompilation is untrustworthy, not that an analyst's whole run should fail, and
suppressing the body would destroy the only evidence of what went wrong.

---

## 7. Built vs. not built

The design documents that shaped this pipeline are archived under
`docs/history/design/plans-superseded/`. Several of their targets are still
open, and a reader who takes the target architecture for the built one will look
for code that is not there. This section is the ledger. Every claim was checked
with `rg` — see [Appendix A](#appendix-a--verification-commands).

### 7.1 What does not exist

| target | status |
|---|---|
| `src/ir/hir/`, `src/lift/`, `src/ir/lifted/`, `src/render/` | **absent.** The layer split those directories represent has not happened; `src/ir/` still mixes lifting, dataflow, recovery, structuring, AST and rendering |
| `FunctionFacts`, `CallFactStore` | **absent** — zero occurrences in `src/`. The design for them is live at [`../design/function-facts-and-call-facts.md`](../design/function-facts-and-call-facts.md), including the measurements proving the existing `CallGraph` cannot found them |
| `ProgramEnvironment::types()` | **write-only.** The accessor exists (`src/program/environment.rs:59`) and its only callers are in `src/program/session_tests.rs`. Nothing in production reads the type store back |
| `remap_type_map` | **still live**, with three production call sites in `src/python_bindings/ir.rs`. Deleting it was a stated goal of the typed-SSA plan; the plain-`types=True` path still needs it |
| the ten `DEC_*` render-time thread-locals | **still there**, `src/ir/ast.rs:1365-1419`. Rendering reads global cells. Two of them (`symbol_env`, `install_dec_global_names`) now at least have install/release in the same function rather than being cleared by the renderer, but the cells remain |

`src/ir/mir/` is the interesting case. It **exists** — nine modules, a typed
model, a verifier, and object queries — and `PreparedLlir::mir()` builds verified
typed MIR on demand for every decompilation. But it is `#[allow(dead_code)]`
with **no production consumer**: its only caller is a `#[cfg(test)]` test in
`src/python_bindings/ir.rs`, and the one other reachable call to
`ir::mir::lower_verified_with_image` outside `src/ir/mir/` and its tests is the
`GLAURUNG_DUMP_PASSES` debug block at `src/python_bindings/ir/pipeline.rs:507`.
It is computed lazily rather than stored because
building it eagerly measured **+13% on a whole-binary decompile** (0.53 s → 0.60 s
on `09_memory_effects-clang-O2`, recorded in the doc comment at
`src/python_bindings/ir/pipeline.rs`) for an artifact no caller reads. So the
blocker is no longer "MIR is only built under an environment variable"; it is
that nothing has been migrated onto it.

### 7.2 The root cause that is still open

The clearest statement of why the pipeline looks the way it does is in the
archived `value-model-root-cause-and-plan.md`: **`VReg` is an overloaded key.**
One enum — `Phys(String) | Temp(u32) | Flag(Flag)` — is simultaneously used as
value *identity* (a mangled string), *storage* (the register spelling), *width*
(implied by the spelling: `eax` = 4, `rax` = 8), *role* (`ret`, `argN`,
`local_N`) and *kind*. Three consequences follow, and all three are visible in
the pipeline above:

1. a pass needing one of those five must parse a name;
2. a pass changing one silently changes the others — canonicalising `edi` → `rdi`
   to keep def/use aligned destroys the width, which is why §6 keeps two LLIRs
   alive and reconciles them by name remapping;
3. a fact with no spelling cannot be represented — a return type, a frame base,
   an address-taken object, "this flag is undefined".

Item 3 is the one that has been partly paid down: `Op::Undef` and
`VReg::FlagValue` now give undefinedness and flag definitions their own identity
(see [`x86-flags.md`](x86-flags.md)), and `RecoveredPrototype` carries the
signature as an immutable companion object rather than as a set of names.

### 7.3 The cautionary datum

The same document records the event that forced it. In one session the execution
differential went 36% → 84% → **92%** at gcc `-O0` while **~25 of 56 DecBench
metric cells regressed and none improved** (`matrix:gcc:O0` GED 3.0 → 15.0;
`statemachine:gcc:O2` 14.0 → 29.0). It was not bad luck. In a representation
where the only way to fix a semantic defect is to add statements, behaviour and
graph-edit distance are *forced* to move in opposite directions. It was invisible
because the only lane that scores GED skipped silently.

Two rules come from that, and both are enforced now: a metric lane that cannot
run is a failure rather than a skip (`scripts/decbench-local-gate.sh`, and
`python/tests/test_local_gate_fails_closed.py` proves it), and a behavioural gate
is never reported as a full gate. See
[`../development/decompiler-testing.md`](../development/decompiler-testing.md).

---

## 8. The design rules the code embodies

These are the rules the pipeline is actually built to, distilled from the
superseded architecture plans and from the roadmap's non-negotiable list. They
are stated here because a reader can otherwise only infer them from comments
scattered across 57 modules.

1. **Machine truth, source interpretation and rendered spelling are distinct.**
   A 32-bit constant stays exact 32-bit machine data even when evidence
   interprets it as a pointer. The type model has three layers — machine sort
   (exact width; mandatory truth), operation interpretation (signed vs unsigned
   *at a use*), and recovered source type (a hypothesis with provenance) — and
   collapsing them turns a bad inference into wrong semantics.
2. **Rendered C is a view, never an input to semantic recovery.** Renderers are
   pure formatting projections. The pre-render verifier exists precisely because
   this rule was once broken: `render_decbench_typed` used to give bare returns
   their ABI register, coalesce parameter spills and copy-propagate *while
   printing*, so a def-before-use checker written against the pre-render AST
   produced false positives on correct functions and was reverted. There was no
   post-fold AST to check. Prepare-then-render made the check possible.
3. **The structurer must be total, not merely a better matcher.** The contract
   is coverage, not prettiness: every reachable block appears, every edge is
   either structured or emitted as an explicit `goto`, a shared join is emitted
   once, every emitted target has a label, and an unrecognised shape produces
   correct goto-based output rather than plausible-but-wrong structure. A dumb
   structurer that always emits gotos is correct; a clever one that drops a block
   is not. `src/ir/structure.rs` keeps anything unmatched as
   `Region::Unstructured` carrying raw block indices, and
   `src/ir/structure_accounting.rs` asks whether the region tree accounts for the
   whole graph.
4. **The verifier comes first.** Before replacing a stage, add the check that
   would have caught its bugs. That is why `src/ir/verify.rs` (LLIR
   well-formedness), `src/ir/verify_defs.rs` (definition-before-use over the
   AST), `src/ir/definedness.rs`, `src/ir/effect_census.rs` and
   `src/ir/structure_accounting.rs` exist and run in the *current* pipeline
   rather than waiting for the rewrite they were designed for.
5. **A failed proof degrades explicitly.** It keeps a lower-level expression, an
   explicit unknown, or an honest `goto`. It does not guess, and it does not
   abort unrelated functions. `cfg_incompleteness_note` and `LiftError::affected_ranges`
   are this rule at the two ends of the pipeline.
6. **Unknown never means "no effect".** An unmodelled instruction or call
   clobbers conservatively.
7. **Incompleteness is monotone.** A downstream stage may add reasons for
   partiality; it may not erase them.
8. **Evidence is retained with provenance; selection is policy and conflict is
   data.** Manual, debug, relocation, symbol, ABI and heuristic facts disagree,
   and the ladder that resolves them is one table
   ([`../reference/provenance.md`](../reference/provenance.md)), not a rule
   re-derived per pass.
9. **One session parses and indexes one image.** Passes consume session APIs.
10. **Graph-changing passes fail closed** — preconditions proved, postconditions
    verified, and the transform declined rather than half-applied when the shape
    is not exactly what it matched.
11. **Metric gains do not override execution, verifier, completeness and canary
    evidence.** §7.3 is why.
12. **A file split counts only if it creates a narrower API and one reason to
    change.** Fragmentation is not architecture.

The target pipeline those rules are aiming at, recorded in
`docs/history/refactoring-portfolio-2026-08/02-ir-decompiler-boundaries.md`:

```text
machine instructions
  -> architecture lifter        -> LLIR
  -> CFG-aware SSA + memory/object identities
  -> verified typed MIR
  -> semantic recovery services
  -> graph-complete HIR
  -> pure AST renderer
```

Comparing that with §§2–6: the first three arrows exist (MIR verified but
unconsumed), the fourth is spread across `src/ir/` rather than being a service
layer, and the fifth does not exist — the AST *is* the HIR, and the renderer is
pure only for `decbench`, where the prepare/verify/render split was made
explicit.

---

## 9. Provenance, and why there is no line map

DecBench's maintainers wrote an audit of our IR — "Glaurung and Manifold:
final-AST lineage blockers" — stating that our AST discards machine-instruction
lineage and prescribing a four-step fix plus a JSON schema extension. The claim
is correct: `lower_block` (`src/ir/ast/lower_conds.rs:280`) passes only
`&ins.op` to `lower_op_stmt` and drops `ins.va`, and `ast::Function`
(`src/ir/ast.rs:622`) keeps only `name`, `entry_va` and `body`. Two things about it matter for anyone
planning work from it. First, that audit exists **only on an unmerged draft
branch** of DecBench (PR #48); the version on `main` contains none of it, and
there is no open issue asking us for anything. Second, and structurally: the
external eval-kit submission format **cannot carry provenance at all** —
`evalkit/templates.py` has no slot for `line_mappings`, `variables`, types or
offsets, and `evalkit/ingest.py` never sets them. An external submission is
therefore incapable of scoring native provenance evidence no matter what we
emit. The full analysis is in
`docs/history/design/campaigns/decbench-native-provenance-2026-08-27.md`, which
also records the DecBench upstream boundary that applies to acting on any of it
(see `CLAUDE.md`).

What we build instead is deliberate. **Per-variable machine addresses, no line
map.** A line map needs AST-node-to-instruction lineage, which lowering
discards. A *variable*-to-address map needs no node identity at all: a promoted
stack local is minted from a frame coordinate that `stack_locals` publishes, and
the LLIR still holds, on every instruction, both that coordinate and the machine
VA it came from. The join is on the storage the analyst is actually naming
(`src/ir/variable_addresses.rs`), and it is fail-closed in five stated ways
because a plausible *wrong* address is worse than none — it is a real
instruction start inside the function, so it passes a consumer's validator and
mis-attributes evidence silently. Conflating the two problems is why the
capability went unbuilt for as long as it did.

---

## Appendix A — verification commands

Run from the repository root. Results below were taken at `13faa6f7`.

```bash
# §1 entry points
rg -n '#\[pyo3\(name = "decompile' src/python_bindings/ir.rs

# §3 architectures and conventions
rg -n -A2 'pub fn supports_arch' src/ir/lift_function.rs
rg -n 'CallConv::' src/target/spec.rs

# §5 how many src/ir modules the bindings actually drive  -> 57
rg -o 'crate::ir::([a-z_0-9]+)' -r '$1' \
   src/python_bindings/ir.rs src/python_bindings/ir/ --no-filename | sort -u | wc -l

# §7.1 what is absent
ls -d src/ir/hir src/lift src/ir/lifted src/render     # all four: No such file
rg -c 'FunctionFacts|CallFactStore' src/               # no matches
rg -n 'remap_type_map' src/python_bindings/ir.rs       # 3 production call sites
rg -n '^\s*static DEC_[A-Z_]+' src/ir/ast.rs           # 10 thread-locals
rg -n '\.types\(\)' src/ python/ tools/                # only session_tests.rs
rg -n '\.mir\(' src/                                   # one caller, a test
rg -n 'lower_verified_with_image' src/ | grep -v '^src/ir/mir/'

# §9 the dropped instruction address
rg -n -A4 'fn lower_block' src/ir/ast/lower_conds.rs
rg -n -A5 'pub struct Function ' src/ir/ast.rs
```

---

## See also

- [`../reference/decompiler-passes.md`](../reference/decompiler-passes.md) — the
  generated pass list.
- [`../reference/decompiler-output-format.md`](../reference/decompiler-output-format.md) —
  the JSON contract and the CLI flags.
- [`register-model.md`](register-model.md) — who owns register views, and the
  prepare-then-render boundary.
- [`x86-flags.md`](x86-flags.md) — the flag producer/consumer protocol.
- [`../development/decompiler-testing.md`](../development/decompiler-testing.md) —
  how a change to any of this is proved.
- [`../design/function-facts-and-call-facts.md`](../design/function-facts-and-call-facts.md) —
  the largest unbuilt piece, with the measurements that constrain it.
