# Handoff: decompiler work recovered and integrated, 2026-07-27

> **Kind:** record · **Date:** 2026-07-28

> **Status: historical closed handoff.** This document preserves the evidence
> and repository state from July 2026; it is not a current work queue or test
> report.

**Worktree:** `/home/mjbommar/projects/personal/glaurung`
**Original state:** `master` @ `b66a4cb`, seven commits behind upstream, all work uncommitted
**Closed:** 2026-07-28 on `master`; final upstream revision recorded after push
**Integrated commits:** `39d1b44` (bounded indirect dispatch), `416b02d`
(flags, indirect-memory semantics, region ownership, completeness telemetry),
`2f32318` (lane-specific fail-closed fixture selection and refreshed baseline)

## Closure evidence

- The redundant local `Expr::Ternary` representation was removed; the tree uses
  upstream's width-carrying `Expr::Select` only.
- All four Python decompile entry points share `run_ast_passes`; the committed
  `--all`/`--vas` equivalence test passes.
- Dispatch resolution has 19 focused tests; structuring has 25 focused tests;
  subtraction flags, memory-indirect jumps, and public completeness aggregation
  have dedicated regression coverage.
- The pinned full execution-differential matrix completed all 56 lanes and 623
  lane-specific functions with zero regressions and three baseline improvements:
  `classify`, `dispatch_switch`, and `sub_then_sign`.
- On the final recovered tree, `cargo test --workspace` passes: 1,083 unit tests
  passed, two were ignored, and every integration-test executable passed.
- The fail-closed Axeyum/Z3 primitive comparison completed all 230 cells across
  8/16/32/64/128-bit widths with zero wrong and zero unknown results.
- The full Python replay completed with 2,526 passed and 43 skipped, but 27 stale
  API/model-policy expectations still fail. Repository-wide Ruff and `ty` also
  retain pre-existing debt (3,520 and 1,968 diagnostics respectively). Those are
  project-wide baseline failures, not claimed green by this recovery.

Everything below is retained as the original handoff and diagnosis. Statements
about branches, commit positions, and measurements describe the 2026-07-27 state,
not current repository truth.

---

## 0. Read this first — the collision

While this work was in progress, seven commits landed upstream implementing the loop
forms and select rendering that this session's analysis had identified as the top
defect:

```
fa2e6f6  ir(select): render lifted selects structurally
1ddab10  ir(loop): recover measured counted for loops
846c75d  ir(loop): bound head-test recovery to countdowns
04b7cf1  fix(ir): preserve do-while latch definitions
2354819  ir(loop): recover head-tested while form
d40a71a  ir(structure): recover single-latch do-while loops
3227d43  test(decbench): refresh baseline at b66a4cb
```

New upstream file: `src/ir/loop_form.rs` (670 lines). 3,667 insertions over 29 files.

### Two consequences

**(a) Drop the ternary/select work in this tree — it is duplicated by `fa2e6f6`.**

| path | what to remove |
|---|---|
| `/home/mjbommar/projects/personal/glaurung/src/ir/ast.rs` | `Expr::Ternary` variant, its lowering in `lower_op`, its three printer arms, and ~30 auto-generated match arms across `src/ir/*.rs` |
| `/home/mjbommar/projects/personal/glaurung/src/ir/dce.rs` | `fold_flags_into_ternaries` and `fold_ternaries_body` |
| `/home/mjbommar/projects/personal/glaurung/src/python_bindings/ir.rs` | the `fold_flags_into_ternaries` call in `run_ast_passes` |

Upstream's version is integrated with `loop_form.rs`; this one is not.

**(b) Everything else needs rebasing onto `fa2e6f6`, then re-measuring from scratch.**
Every number in this document and in the session's diary was measured against
`b66a4cb`. Upstream both refreshed the DecBench baseline *and* landed the loop forms,
so the diary's headline finding — "we emit `while(1){if(!c) break;}` for 126 of 126
loops" — is very likely **stale**. Re-run before trusting any of it.

### Likely conflicts

Upstream rewrote all of these; expect merge work:

```
src/ir/copy_prop.rs        src/ir/dce.rs             src/ir/dead_stores.rs
src/ir/expr_reconstruct.rs src/ir/name_resolve.rs    src/ir/naming.rs
src/ir/pdb_fields.rs       src/ir/stack_locals.rs    src/ir/strings_fold.rs
src/ir/structure.rs        src/ir/structure_accounting.rs
src/ir/switch_ladder.rs    src/ir/value_split.rs     src/ir/verify_defs.rs
src/ir/widen.rs            src/python_bindings/ir.rs
tests/decbench_corpus/baseline.json
tests/decompiler_fixtures/baseline.json
```

Untouched upstream, so these should rebase cleanly: `src/analysis/*`,
`src/ir/types.rs`, `src/ir/lift_x86.rs`, `src/ir/use_def.rs`, `src/ir/value_number.rs`,
`src/exec/interp.rs`, everything under `tools/`, and the new tests and docs.

---

## 1. Jump-table dispatch resolution — new file, not upstream

`/home/mjbommar/projects/personal/glaurung/src/analysis/dispatch.rs` — 1013 lines, 19 tests.

| line | what it is |
|---|---|
| `:86` | `Unresolved { UnknownBase, NoTableAt(u64), NoBound(u64) }` — makes CFG incompleteness a representable fact instead of a silently empty successor list |
| `:109` | `Bounds { regs, slots }` — what a guard established, carried across its in-range edge |
| `:158` | `DispatchTracker` — streaming abstract interpretation over the block being decoded; nothing buffered, nothing decoded twice |
| `:227` | `inherit_bound` |
| `:271` | `dest_reg` — uses the decoder's `Access` class |
| `:294` | `bound_value` — bounds a register *and any stack slot aliasing it* |
| `:308` | `export_bounds` |
| `:316` | `observe` — the transfer rules |
| `:497` | `resolve` — **fails closed** |

### Three defects this file exists to fix, each measured

1. **Tables were never bound to the jump that reads them.**
   `discover_jump_tables` fed *function-entry seeds only*, so the dispatching
   function's own CFG gained **zero** successors. `dense_jumptable` at clang -O0 was
   3 blocks (entry, dispatch, default) and returned `-1` unconditionally; the eight
   case arms — thirty instructions — never entered the graph. `structure_accounting`
   reported it **clean**, because it checks the region tree against the CFG, not
   against the program.

2. **`dest_reg` (`:271`) must use the decoder's `Access`.** `jmp rax` has `rax` as
   operand 0 but only *reads* it. Treating operand 0 as a definition made `observe`
   clear the very register the jump was about to be resolved through, so every
   dispatch came back `UnknownBase`. All ten unit tests passed at the time — their
   synthetic operands were all `ReadWrite`. Only the round trip showed it.

3. **`resolve` (`:497`) must fail closed.** It previously fell back to the rodata
   scan's run length when no guard bounded the index. That scan returns **65 entries
   for an 8-entry table** (the next table's offsets, read against the previous
   table's base, still land in `.text`), so every unguarded dispatch gained ~57
   successors belonging to other functions.

### The bound is a propagating dataflow fact, not a register name

A census of 24 real dispatch sites across 20 fixture binaries found only **3**
resolving under name-matching. In 14 of the 21 misses the guard checks one register
and the table is indexed by another — clang -O0 spills the index to its frame slot
*before* the guard runs and reloads it into a different register (11 sites); clang -O2
copies it via `mov %edi,%ecx` (3 sites). `bound_value` (`:294`) therefore bounds the
register *and* any slot aliasing it, and `export_bounds`/`inherit_bound` carry both
across the guard's in-range edge.

`and $2^k-1` is also treated as its own range proof — both compilers emit
power-of-two switches at -O2 with no comparison at all.

Safety test at `:484` (`an_unbounded_dispatch_does_not_resolve`) and `:~560`
(`a_stack_adjust_does_not_bound_an_unrelated_dispatch`) — the second exists because
`sub $0x8,%rsp` appears in nearly every prologue.

---

## 2. CFG wiring

`/home/mjbommar/projects/personal/glaurung/src/analysis/cfg.rs`

| line | what |
|---|---|
| `:135` | `unresolved_indirect: Vec<(u64, Unresolved)>` — the completeness signal |
| `:137` | `resolved_dispatches: Vec<(u64, usize)>` |
| `:647` | `index_bounds: HashMap<u64, Bounds>` |
| `:680` | inherit the guard's bounds at block start |
| `:721` | `dispatch.observe(&ins)` — streaming, per decoded instruction |
| `:788` | `dispatch.resolve(&ins, tables)` at the indirect jump |
| `:831` | export bounds across the guard's in-range edge |
| `:2781` | build `jump_table_index` |
| `:3153` | pass it into `discover_function` |

---

## 3. The `sub`-flags fix

`/home/mjbommar/projects/personal/glaurung/src/ir/lift_x86.rs`
`:383` `sub_flag_ops` · `:941` applied in the ALU path · `:2658` test

`emit_bin` emitted only the arithmetic, so **`sub`, `add`, `and`, `or`, `xor`, `shl`,
`shr`, `sar` and `imul` defined no flags at all** — every `jcc` after an arithmetic
instruction read a stale flag from whatever compared last.

`05_cleanup_and_state_machine:clang:O0:fsm` showed it: the switch guard came out as
`if (~ule)` where `ule` still held the *enclosing loop's* condition, and `~` of a 0/1
flag is `-1` or `-2` — both true — so the recovered `switch` was unreachable. After the
fix the guard reads `if (3 < state)`, which is the source's semantics.

This is the **fourth** instance of one gap. `neg` defined no flags; `test` defined
three of the four that matter; `cmovcc` mis-modelled its condition. The family deserves
an audit rather than a fifth individual fix — see `docs/design/x86-flags.md`.

`cmp` already emitted exactly the right block, and `cmp` *is* `sub` without the
destination write.

---

## 4. `Op::IndirectJump` — a jump is not a call

`types.rs:258` (variant) · `types.rs:597` (Display) · `lift_x86.rs:2160,2163` (lifting)
· `use_def.rs:86` · `ast.rs:175` (`Stmt::IndirectGoto`) · `ast.rs:586` (lowering)
· `ast.rs:1068` · `interp.rs:324` · `value_number.rs:205`

The lifter previously produced `Op::Call` for `jmp *%rax` and `jmp *[mem]`, with the
comment *"downstream analyses treat both the same"*. They must not: a call returns and
a jump does not. The dispatch rendered as a value-producing call statement, so the
switch lowering could not recognise it as the terminator to drop and the phantom call
survived *inside* the recovered switch.

Targets are deliberately **not** carried on the op — where control goes is a property
of the graph, recorded once as CFG edges; what the instruction *is* belongs on the op.

---

## 5. Tooling — none of this is upstream

| path | lines | purpose |
|---|---|---|
| `tools/dectest.py` | 364 | scoped fixture runner — one function in **2.9 s** against the gate's ~2 min for 56 lanes |
| `tools/build_guard.py` | 144 | refuses to run against a `.so` older than its Rust source; resolves the `glaurung` CLI without an activated venv |
| `tools/ghidra_decompile.py` | 36 | Ghidra via PyGhidra |
| `tools/angr_decompile.py` | 57 | angr |
| `tools/roundtrip3.py` | 169 | `C -> binary -> C` for all three, side by side, per function |
| `tools/decbench_compare.py` | 121 | three-way metric tables |
| `tests/decompiler_fixtures/sets.toml` | 85 | 13 named, reproducible test sets |
| `python/tests/test_dectest_selection.py` | 235 | selection is fail-closed; a scoped run can never be mistaken for the gate |
| `python/tests/test_dectest_equivalence.py` | 87 | **proves a scoped verdict equals the gate's verdict** for the same function |

Two invariants worth preserving if this is rebased:

* **Selection is fail-closed.** A selector matching nothing is an error — "no
  regressions in 0 lanes" reads exactly like success.
* **A scoped run cannot become a baseline.** There is no `--write-baseline`, and the
  result map carries no `__toolchain__` fingerprint, so `fixture_harness` refuses it.

Also modified: `scripts/decbench-local-gate.sh` now sets up its own PATH, exec tmpdir
and staleness check, so it runs from a clean shell (it previously died with
`FileNotFoundError: 'glaurung'`).

---

## 6. Analysis documents

```
docs/analysis/decompiler/2026-07-27-three-way-roundtrip-diary.md   610 lines
docs/design/decompiler-plan-2026-07-27.md                          237 lines
docs/development/decompiler-testing.md
```

The diary is a function-by-function three-way read against Ghidra 11.4.2 and angr
9.3.0, plus source studies of both decompilers. **Its loop-form measurements are
probably now stale** — see §0(b).

Findings that are *not* affected by the upstream loop work:

* **Ghidra's `type_match` lead is largely a benchmark artifact.** The corpus is built
  `-g`, DecBench's ground truth *is* that DWARF, and Ghidra's default analyzers include
  the DWARF analyzer. Scored through one identical scorer with `--strip-debug` it drops
  to 0.000 on `structs` and 0.650 on `arrays` — below us. Do not chase its assisted
  number.
* **angr synthesizes recursive struct types with no debug info** (`linkedlist:list_sum`
  → `typedef struct struct_0 { struct struct_0 *field_0; unsigned int field_8; }`).
  Aggregates are therefore *not* inherently unrecoverable, which raises the ceiling
  previously assumed for our own inference.
* **We beat both on `switch_jt`** — 23 vs Ghidra 42 vs angr 45. angr declines that
  transform by design: its `LoweredSwitchSimplifier` refuses when
  `max_continuous_cases >= 6`, a threshold transcribed from GCC's own source.
* **Both competitors make structuring total by forcing a goto**, and Ghidra has only
  **eleven** collapse rules — the pattern catalogue is not the difference; not being
  able to get stuck is. (Ghidra `blockaction.cc:1877-1893`, `selectGoto` `:1260-1277`;
  angr `phoenix.py:188-238`, `_last_resort_refinement` `:3021-3141`.)
* **Neither models flags as a named enum.** `grep -rn '"ZF"\|"CF"\|"SF"\|"OF"'` over
  all ~150 Ghidra decompiler sources returns nothing.

---

## 7. Measurements — all against `b66a4cb`, all now needing a re-run

Established by a controlled run (stash, rebuild, measure, restore):

| | GED | type_match | byte_match |
|---|---|---|---|
| committed baseline at the time (`a1a8a87`, 9 commits stale) | 10.238 | 0.678 | 0.183 |
| **CONTROL — true master, no session work** | **12.678** | 0.678 | 0.197 |
| master + all session work | 12.080 | 0.685 | 0.198 |

Two things to carry forward:

* **The repository was carrying an unrecorded ~24 % GED regression** because the
  baseline was nine commits stale. `3227d43` upstream has since refreshed it.
* Behaviour (execution differential): **2 improvements**
  (`01_conditional_polarity:clang:O2:classify`,
  `08_indirect_dispatch:clang:O2:dispatch_switch`), **1 regression**
  (`05_cleanup_and_state_machine:clang:O0:fsm`).

`fsm` is the one outstanding regression. Its guard and switch arms are now correct C;
what remains is structuring debris — dead statements after `goto`, the shared epilogue
duplicated into each arm. That is region ownership, not the dispatch or flags work.

Also landed here: the stranded Phase 1.1 WIP from
`/nas4/data/workspace-infosec/glaurung-decbench`, consolidating `decompile_all` and
`decompile_many` onto `run_ast_passes` — all **4** call sites now share one pass list,
and `--all` / `--vas` produce byte-identical output. Combined with the dispatch work
this took `statemachine:clang:O0` from **42.00 to 11.00**. Check whether upstream
landed the same thing independently before re-applying.

---

## 8. Suggested order for whoever picks this up

1. `git fetch && git rebase origin/master` — **re-fetch first**; this tree went stale
   mid-session precisely because that was not done before starting implementation.
2. Drop the ternary/select work (§0a).
3. Rebase the rest; expect conflicts in the files listed in §0.
4. **Re-measure everything.** `tools/decbench_matrix.py --json` for glaurung, Ghidra
   and angr, then `tools/decbench_compare.py`. Do not trust any number in §7 or in the
   diary until this is redone against `fa2e6f6`.
5. Then decide what remains of the plan. Phase A (loop forms) is likely done upstream;
   Phase B (total structuring via goto virtualization) is not, and `fsm` is blocked on it.
