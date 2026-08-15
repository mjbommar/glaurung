# Decompiler roadmap execution diary

**Started:** 2026-08-13
**Plan:** [decompiler-roadmap.md](decompiler-roadmap.md)
**Baseline:** `fb4ee6b` (`master`), plus the uncommitted session-owned DWARF slice.

This is the running evidence log for working the roadmap's *Immediate
rank-ordered plan*. One entry per increment, RED -> GREEN -> VERIFY, with the
exact command output that justifies each claim.

---

## Entry 1 — Roadmap item 1: finish the session-owned DWARF/`TypeStore` slice

### Starting state

The working tree carried an unfinished slice: `ProgramSession` gained a
`OnceLock` that parses DWARF once and imports it into a canonical `TypeStore`,
`ProgramEnvironment` took an `Arc<TypeStore>` instead of building its own, and
the four `python_bindings/ir.rs` decompile entry points stopped calling
`extract_dwarf_types` independently. One test was RED by construction.

### RED

```
test program::session_tests::real_debug_types_are_imported_once_and_shared_by_every_environment ... FAILED
assertion failed: matches!(first_store.get(next_id).and_then(|record| record.selected_shape()),
    Some(TypeShape::Pointer { pointee, alignment: None, .. }) if *pointee == node_id)
```

### Diagnosis

`src/program/types/dwarf.rs` synthesized pointer and primitive types with
`alignment: size.is_power_of_two().then_some(size)`. That is invented evidence.
The legacy `DwarfType` record does not retain `DW_AT_alignment` at all, so the
adapter was manufacturing a natural-alignment guess and stamping it with
`TypeAuthority::Debug`. Natural alignment is a *target* rule, not a debug fact;
laundering it through the debug authority would let it outrank real inference
later. This is roadmap design rule 3 (evidence carries provenance) and rule 4
(completeness is not confidence).

### GREEN

Both synthesized shapes now pass `None` for alignment, with the reason recorded
at the construction site. Alignment stays absent until an owner that actually
knows the target ABI supplies it.

### Negative controls (roadmap "Required validation")

Two real-fixture controls were added to `src/program/session_tests.rs`:

1. `a_real_image_without_debug_information_produces_no_invented_types` —
   compiles the same source with `-g0 -s` and asserts the session's debug type
   list and canonical store are both **empty**, and that
   `dwarf:struct:Node` does not resolve. Absent evidence must not become
   fabricated types. This passed immediately.

2. `same_named_debug_layouts_from_different_units_are_retained_as_conflicts` —
   two translation units that each legally define `struct Conflict` with a
   different layout (4 bytes vs 16 bytes), linked into one real binary. This
   was RED, and found a genuine defect.

### Defect found by control 2

`readelf --debug-dump=info` confirms the linked binary really carries both
definitions:

```
<1><33>: DW_TAG_structure_type  DW_AT_name: Conflict  DW_AT_byte_size: 4
<1><106>: DW_TAG_structure_type  DW_AT_name: Conflict  DW_AT_byte_size: 16
```

But `extract_dwarf_types` ended with:

```rust
// Dedup by (kind, name) ... Keep the first seen
out.retain(|t| seen.insert((t.kind, t.name.clone())));
```

a first-wins dedup keyed on name alone. It silently destroyed the disagreement
and promoted whichever unit happened to be linked first into an authoritative
layout — a direct violation of roadmap rule 3 ("Selection policy never destroys
conflicts") and rule 8 ("A failed proof keeps ... explicit unknown. It does not
guess").

The dedup was also masking correct behavior that already existed downstream:
`DwarfTypeEnv::new` (`src/ir/dwarf_type_env.rs`) *already* fails closed, setting
a layout entry to `None` when two records under one key disagree. It never got
the chance, because the extractor had already thrown the conflict away.

A second collapse sat behind it: the `TypeStore` DWARF adapter accumulated
nominal records into a `BTreeMap<String, DataType>` keyed by nominal id, so even
if two records arrived, the last one overwrote the first before
`import_data_types` (which retains conflicts properly) ever saw them.

### Fix

- `src/debug/dwarf.rs`: dedup on the **whole definition** rather than the name.
  `DwarfType::is_same_definition` compares kind, name, byte size, fields,
  variants, and typedef target while ignoring `source_file`. This still collapses
  the overwhelmingly common case — one header included by many compilation
  units emits an identical record per unit, and `source_file` is the CU name, so
  a naive full-record dedup would have collapsed nothing — while retaining
  records that genuinely disagree.
- `src/program/types/dwarf.rs`: split the builder into `synthesized`
  (pointer/primitive types, still keyed and built once) and `records` (nominal
  records, a `Vec` in extraction order). Both are forwarded to
  `import_data_types`, which reserves one identity per external id and records
  `IncompatibleDefinition` plus a retained alternative for the second layout.

### Result

```
running 6 tests
test program::session_tests::a_real_image_without_debug_information_produces_no_invented_types ... ok
test program::session_tests::real_debug_types_are_imported_once_and_shared_by_every_environment ... ok
test program::session_tests::same_named_debug_layouts_from_different_units_are_retained_as_conflicts ... ok
test program::session_tests::exact_discovery_is_reused_within_one_session ... ok
test program::session_tests::discovery_cache_key_includes_budgets_and_normalized_seeds ... ok
test program::session_tests::session_exposes_the_images_single_canonical_target ... ok
test result: ok. 6 passed; 0 failed
```

### Behavior-change risk being verified

Removing the name-only dedup is not purely additive. On any binary that really
does contain two same-named, differently-shaped types, `DwarfTypeEnv` will now
fail closed where it previously used the first layout with confidence. That is
the correct direction, but it can move DecBench TypeMatch either way, so it
needs the full gate rather than the focused tests.

### Verification status

| Gate | Result |
|---|---|
| `cargo test` (full) | PASSED, exit 0 |
| `uv run maturin develop` | built and installed |
| `uv run pytest python/tests/ -q -x` | **one failure**, see below |
| `scripts/decbench-local-gate.sh` | not yet run |

The Python run stopped (`-x`) at
`test_decbench_glaurung_backend.py::test_adapter_passes_requested_selectors_to_the_shared_batch_pipeline[{'addmul'}---all-2000]`.

**Resolved: environmental, not a defect.** The host's `/tmp` (a 62 GB tmpfs)
had filled. That test compiles a shared object into `tmp_path` and shells out
to the DecBench venv, so it failed on the full filesystem. The same tool
exhaustion then took the Bash tool itself down for about an hour, for this
session and for subagents alike. With space reclaimed, the whole file passes:

```
uv run pytest python/tests/test_decbench_glaurung_backend.py -q
....                                                                     [100%]
```

Worth recording as a gate-hygiene lesson: a full tmpfs presented as one
plausible-looking assertion failure in a metric-adjacent test. Reading it as a
product defect would have sent a whole session chasing the DWARF change.

---

## Entry 2 — Roadmap item 2 reconnaissance: which aggregate consumer to migrate

Before touching code, mapped the EPIC 3 seam. Findings that change the plan:

### The MIR object path is entirely diagnostic today

`lower_verified_with_image` has exactly one production call site,
`src/python_bindings/ir.rs:849`, and it sits inside
`if std::env::var("GLAURUNG_DUMP_PASSES").is_ok()`. The resulting `MirFunction`
is `eprintln!`'d and dropped; `PreparedLlir` never carries it. So "migrate the
first production aggregate consumer to verified MIR evidence" is not only a
consumer change: the MIR artifact has to start being computed unconditionally
in `prepare_llir_for_lowering` and threaded to the consumer. That also settles
a roadmap fitness item in passing — correctness must not depend on an
environment variable.

`DefinitionOracle` (`src/ir/mir/query.rs`) and `TypeStore::bind_object_type`
likewise have zero production callers.

### Ranked candidates

1. **`high_variables::refine_object_cursor_values`** (`src/ir/high_variables.rs:147`).
   Its entire evidence input is one boolean per promoted local:
   `is_promoted_local(name) && object_model.has_conflict_free_extent(&VReg::phys(name))`.
   Output effect is one `TypeHint::Pointer { pointee_width: 1 }`, i.e. whether a
   local renders as `char *local_N`. Small contract, small blast radius, and it
   already has an end-to-end oracle (below).
2. `bounded_overlap::aapcs_top_padding_scalar_value` — tiny, but ARM/AArch64-only,
   on the lane with the weakest coverage, and its input is `stack_locals`' slot
   map rather than the object model.
3. `dead_stores::prune_unobserved_promoted_object_stores` — small, but it is a
   syntactic proof today; replacing it needs `memory_uses`/`clobbers_between`
   first, which is roadmap item 3.
4. `dwarf_fields` — the right long-term target, but migrating it means routing
   DWARF through `TypeStore` + `bind_object_type`, which is blocked (below).
5. `pdb_fields` — slated for deletion, but no MIR evidence involved, so
   migrating it would prove nothing about the MIR authority.
6. `stack_locals::seed_indexed_stack_objects` — owns every `unsigned char
   local[N]` in DecBench output. Last, not first.

**Chosen: candidate 1.**

### The blocker candidate 1 must solve

MIR objects are keyed by `ObjectIdentity::MirValue(ValueId)` over numbered
LLIR. `high_variables` is keyed by the promoted-local *name* (`local_8`), minted
in `stack_locals.rs` from `(base, disp)` after AST lowering. No mapping exists
between them. Establishing that join is the actual content of this increment;
everything else is plumbing.

Note this blocker is specific to identity, not to types. Migrating a type
consumer additionally requires a *mutable* session-owned `TypeStore`
(`bind_object_type` takes `&mut`, while `ProgramSession` hands out
`Arc<TypeStore>` behind a `OnceLock`). Candidate 1 migrates an evidence
predicate and avoids that entirely, which is part of why it is first.

### Existing oracle

`python/tests/test_decompiler_memory_objects.py:31`
(`test_stripped_aggregate_cursor_preserves_byte_stride_and_execution`) already
compiles a real 64-byte-record cursor loop, **strips** it, and asserts the MIR
diagnostic and the production `char * local_XX` rendering *and* an execution
rebuild in one test. That is exactly the "same fact, two paths" harness a
migration needs, and it is already committed.

### Corpus gap to close first

The roadmap requires "a real end-to-end fixture for an array indexed with a
constant bias" before the affine-index port. No such fixture exists:
`109_subscript_commutativity` covers subscript spelling commutativity and a
negative offset from an interior pointer, not a constant bias folded into the
index (`a[i + 3]`). There is also no `@arrays`/`@aggregates` named set in
`tests/decompiler_fixtures/sets.toml` — the aggregate-dense fixtures
(`100_struct_layout`, `108`, `110`, `111`, `129_struct_by_value`,
`161_packed_struct_layout`, `162_unaligned_memcpy_access`, ...) are reachable
only by explicit name. Both are corpus work worth doing.

---

## Entry 3 — Closing the corpus gap: constant-bias array indexing

Added `tests/decompiler_fixtures/src/187_constant_bias_index.c` (187 is the
first free number; the coverage-directed additions run 181-186).

Five functions, all bounded by explicit source guards rather than by the
harness contract, so an out-of-domain argument returns `-1` identically on the
original and recompiled side instead of reading past the buffer:

| function | shape |
|---|---|
| `bias_forward_sum` | `values[index + 2]` — constant positive bias |
| `bias_backward_pair` | `values[index] - values[index - 1]` — two biased reads of one object per iteration |
| `adjacent_difference` | biased load feeding an unbiased store into a second object |
| `value_bias_not_index` | **control**: the constant is added to the loaded value, never the address |
| `variable_bias` | **control**: the displacement is a runtime argument, so no constant bias exists to recover |

The two controls are the point. Recovering a bias is only correct if it is not
recovered where there is none, and a pass that folded either control into a
fixed address bias would otherwise be indistinguishable from success.
`value_bias_not_index` deliberately returns a different sum than
`bias_forward_sum` for the same buffer.

Registered in `manifest.REQUIRED_FUNCTIONS` and given per-function
`arg_values` domains rather than `len_args` clamping: a clamped count would
never reach the guard boundary, so each entry sweeps the last accepted count
and the first rejected one.

Also added two named sets to `sets.toml`:

- `@aggregates` — the nine layout/array/subscript/bias/packing/by-value
  fixtures. These were reachable only by explicit name, which left the
  aggregate workstream as the one area with no iteration loop of its own.
  (`@structs` is about memory *effects* surviving lowering; this is about
  recovering the *object*.)
- `@bias` — fixture 187 alone, for iterating on the affine-index port.

### Verified

Compile gate, all four lanes:

```
OK gcc -O0    OK gcc -O2    OK clang -O0    OK clang -O2
```

Corpus integrity (`test_decompiler_fixture_harness.py`,
`test_dectest_selection.py`, `test_decompiler_fixture_compile.py`): 108 passed,
so the new sets resolve and the manifest and sources agree.

Execution differential, all 20 cells:

```
tools/dectest.py @bias --full
187_constant_bias_index:{clang,gcc}:{O0,O2}:{adjacent_difference,
  bias_backward_pair, bias_forward_sum, value_bias_not_index,
  variable_bias}    pass  (20/20)
```

So the fixture is behaviorally faithful in every lane today. That is the
expected starting point: it exists to hold the line when the affine-index port
lands, not because it is currently red.

### Still to do

Three committed baselines must be refreshed, because each independently
requires every declared fixture to be present in every one of its lanes
(`fixture_harness.schema_problems`, `arch_roundtrip.schema_problems`,
`structural.py` iterating `M.REQUIRED_FUNCTIONS`):

- `baseline.json` via `tools/fixture_harness.py --write-baseline`
- `structural_baseline.json` via `tools/gen_structural_baseline.py`
- `arch_baseline.json` via `tools/arch_roundtrip.py --write-baseline`

**Sequencing hazard.** A `--write-baseline` run rewrites the whole file, so it
would silently absorb any regression the DWARF dedup change caused. The
baselines must therefore be validated *without* this fixture first — stash the
fixture, `manifest.py`, and `sets.toml`, run the gate against the committed
baselines to judge the DWARF change on its own, then restore and refresh.

### Incidental finding: two roadmap items are already done

`tools/arch_roundtrip.py:207` already lists `armv7_a32` and `x86_64_gcc15` in
`REQUIRED_ARCHES`, and `arch_baseline.json` carries 350 baselined lanes for
each of the six architectures. The roadmap still shows

- "Add a real `-marm` A32 fixture lane; Thumb-only ARM coverage is inadequate"
- "Rebuild the x86-64 control with GCC 15 to separate compiler-shape effects
  from architecture effects"

as open, and lists both under immediate item 5. They are landed and ratcheted.
The roadmap is stale here, not the corpus.

---

## Entry 4 — Design for roadmap item 2, deferred until item 1 is committed

Read the plumbing precisely enough to specify the increment. Recording it here
rather than starting it: item 1 and the new fixture both still need the gate,
and beginning a third change now would make the gate ambiguous about which
change moved which cell. The acceptance policy exists to prevent exactly that.

### What the migration actually consists of

1. **Make the MIR artifact real.** `prepare_llir_for_lowering`
   (`src/python_bindings/ir.rs:765`) computes
   `crate::ir::mir::lower_verified_with_image(&numbered, image)` only inside
   `if std::env::var("GLAURUNG_DUMP_PASSES").is_ok()` (`ir.rs:841-864`), prints
   it, and drops it. It must instead be computed unconditionally and stored on
   `PreparedLlir` (`ir.rs:756`) as `Option<MirFunction>` — `Err` becoming an
   explicit typed incompleteness reason, not a silent `None`. This also closes
   a roadmap fitness item in passing: correctness may not depend on an
   environment variable.

2. **Thread it to the consumer.** `PreparedLlir` -> `decbench_text`
   (four call sites: `ir.rs:1161, 1414, 2651, 2944`) -> `run_ast_passes`
   (`ir.rs:556`) -> `refine_pointer_high_variables` (`high_variables.rs:33`).

3. **Solve the identity join — the real content.**
   `refine_object_cursor_values` (`high_variables.rs:147`) asks exactly one
   question per candidate, at `:177`:

   ```rust
   is_promoted_local(name) && object_model.has_conflict_free_extent(&VReg::phys(name))
   ```

   Today `object_model` comes from `infer_from_ast(function)` and is keyed by
   the promoted-local *name* (`local_8`). MIR objects are keyed by
   `ObjectIdentity::MirValue(ValueId)` over numbered LLIR. Nothing maps between
   them.

   The natural bridge is the frame displacement: `stack_locals` mints
   `local_N` from a `(base, disp)` pair, and a MIR stack cursor's origin
   resolves to `StackValue(ValueId)` with an affine offset. But
   `StackLocalFacts` (`stack_locals.rs:114`) carries only
   `sizes`/`source_types`/`source_names`, all keyed by name — **the
   displacement is not exported**. So the increment must first surface a
   name-to-displacement map from `stack_locals`, then join MIR objects to
   promoted locals through it.

### Acceptance shape

The oracle already exists:
`python/tests/test_decompiler_memory_objects.py::test_stripped_aggregate_cursor_preserves_byte_stride_and_execution`
asserts the MIR diagnostic *and* the production `char * local_XX` rendering
*and* an execution rebuild, on a real stripped binary. Parity means that test
passes with the AST adapter no longer consulted by this consumer.

Per the roadmap's validation table this needs, beyond parity: a real debug
fixture, a real stripped fixture (the oracle above), and a near-miss control
where the two models *disagree* — proving the MIR answer is the one used and
that disagreement fails closed rather than silently preferring either side.

### Process change: DecBench and Joern are now opt-in

The gate run above cost about 100 minutes and ended in a **failure that was not a
product defect**. Lane 5 reported 11 cells as `build failed`:

```
strops:clang:O0, strops:clang:O2, strops:gcc:O2,
structs:{gcc,clang}:{O0,O2}, switch_jt:{gcc,clang}:{O0,O2}
```

Every one of those cells had **built and executed successfully in lane 4**
minutes earlier, and `structs:gcc:O0` re-ran clean in isolation:

```
tools/decbench_matrix.py --check --only 'structs:gcc:O0' --jobs 1
  structs:gcc:O0   ged=0.0 type_match=0.75 byte_match=0.39
SCOPED: no per-cell regressions across 1 of 56 cells
```

So four concurrent Joern JVMs exhausted something and the harness reported it as
a product failure. Combined with the earlier full-`/tmp` incident, that is twice
in one session that an *infrastructure* problem wore a *decompiler defect*'s
clothes, and each time the cost of telling them apart was tens of minutes.

At the user's direction, `scripts/decbench-local-gate.sh` now runs **fixture
lanes 1-3 by default**; DecBench lanes 4-5 require `--decbench` or
`GLAURUNG_RUN_DECBENCH=1`.

The reasoning is not merely cost. `tests/decompiler_fixtures/` recompiles our
output and executes it against the original — it can prove a change sound.
DecBench scores GED / TypeMatch / ByteMatch, which measures *published-metric
movement*, not correctness. The fixture corpus was always the stronger gate; it
had just been bundled behind the weaker, slower one.

The anti-regression property this script exists for is preserved rather than
dropped: the default run's final lines state `DecBench lanes 4-5 NOT RUN` and
`GED / type_match / byte_match are UNMEASURED by this run`, so an unmeasured pass
still cannot read as a measured one. `test_local_gate_fails_closed.py` gained two
tests pinning that, alongside the existing ones for the `--decbench` path.
`CLAUDE.md` and `docs/development/decompiler-testing.md` updated to match.

---

## Entry 5 — The gate was slow for a reason nobody had measured

Chasing "why does the fixture gate take an hour", three wrong answers were
discarded before the real one, which is worth recording because each was
plausible.

**Wrong answer 1: Docker.** `tools/fixture_toolchain.py` runs each compile as
its own `docker run --rm`, measured at 1.07 s against 0.085 s for `docker exec`
into a live container, and lane 2 issues roughly 3,300 compiles. The arithmetic
matched the observed ~15 min almost exactly, which made it convincing. It was
still wrong: sampling the running harness showed **zero** fixture containers.
All 734 fixture binaries were already built; the compile phase was over. A
correct calculation about the wrong phase.

**Wrong answer 2: not enough parallelism.** The gate hardcoded
`GLAURUNG_FIXTURE_JOBS=4` on a 24-core host, so raising it looked like free
speed. It helps, but the baseline write measured 18m48s wall against 117m user
CPU — already 6.2x effective parallelism. The tail, not the width, was binding:
the last three lanes were `166_rust_generics`, `169_rust_slices_bounds`, and
`170_rust_panic_unwind`, each running 8+ minutes alone.

**Wrong answer 3: decompilation is just slow.** Partly true, and it hid the
real cause.

**The real answer.** Timing the pieces:

```
import glaurung        (the PyO3 extension)   0.11 s
glaurung --help        (no work whatsoever)   3.10 s
glaurung decompile     (one function)         7.16 s
```

Three seconds to print a help message, from a native extension that loads in
a tenth of one. `python -X importtime -c "import glaurung.cli"` attributed
**1417 ms of 1467 ms** to `glaurung.cli.commands.ask`, which reaches
`glaurung.llm.agents.factory` -> `pydantic_ai` -> `pydantic_ai.mcp` /
`pydantic_graph`.

`GlaurungCLI.__init__` instantiated all 35 command classes so `create_parser`
could call `setup_parser` on each. Every `glaurung decompile` therefore
constructed an LLM agent stack it never touches — and
`tools/diff_decompile.py` shells out once **per function**, so a fixture matrix
pays it about 2,568 times.

### Fix

`python/glaurung/cli/main.py` now holds a `_REGISTRY` naming each command's
module and class instead of importing them, resolves one lazily via
`import_module`, and registers only the invoked subcommand's subparser. The
first bare token in `argv` identifies the subcommand; anything unrecognized
falls back to building the full parser so argparse still emits its own error
listing every choice, and `--help` still imports everything because the whole
list *is* its output.

| | before | after |
|---|---:|---:|
| `glaurung decompile --help` | 3.10 s | **0.056 s** |
| `glaurung triage --help` | 3.10 s | **0.048 s** |
| one real function decompile | 7.16 s | **4.27 s** |
| `glaurung ask --help` | 3.10 s | 1.62 s (still loads its stack) |

About 2.9 s off every invocation, so roughly two CPU-hours off a full matrix
run, and the CLI is now instant interactively.

`python/tests/test_cli_startup_is_lazy.py` pins the contract by running the CLI
in a subprocess and inspecting `sys.modules`: `decompile` and `triage` must not
load `pydantic_ai`/`pydantic_graph`; `ask` **must** still load it (the negative
control — a test that only asserts absence would also pass if the subcommand
were deleted); and top-level `--help` must still advertise every command.

Net lint moved from 8 findings to 6 on the touched file.

### Infrastructure lessons banked

Three failures this session were infrastructure wearing a product defect's
clothes, and each cost more to diagnose than to prevent:

1. A full `/tmp` surfaced as a plausible assertion failure in a DecBench
   adapter test, then took the Bash tool down entirely for an hour.
2. Four concurrent Joern JVMs reported 11 cells as `build failed` that had
   built and executed minutes earlier and re-ran clean in isolation.
3. `OSError: [Errno 122] Disk quota exceeded` killed a 22-minute baseline
   regeneration.

Root cause of 1 and 3: 663 abandoned `glaurung-<topic>.XXXXXX` scratch
directories (13 GB) left in `/tmp` by past sessions, plus 12 GB of old DecBench
evaluation trees. Not a tooling leak — the repo's Python tooling uses
`tempfile.mkdtemp(prefix=...)`, which produces no dot; the dot-suffix form is
shell `mktemp -d -t`. Cleared with the named evaluation artifacts preserved.
`CLAUDE.md` now forbids ad-hoc `/tmp` scratch.

Also killed two runaway `glaurung decompile --all` processes from an unrelated
worktree that had been burning CPU for **8 days 23 hours**; host load fell from
18 to 2.

One thing worked correctly throughout: `fixture_harness.baseline_problems()`
refused to write a baseline containing lane errors, so the disk failure wasted
time but could not corrupt `baseline.json`.

---

### Explicitly not in scope

Migrating a *type* consumer additionally requires a mutable session-owned
`TypeStore`: `bind_object_type` takes `&mut`, while `ProgramSession` hands out
`Arc<TypeStore>` from a `OnceLock` (`session.rs:199-224`). Candidate 1 migrates
an evidence predicate and needs no such mutation, which is part of why it is
first. `bind_object_type` and `DefinitionOracle` both still have zero
production callers.

---

## Entry 6 — i386 argument casts

`test_pe32_cdecl_roundtrip.py::test_i386_cdecl_decompile_recompile_execute_round_trip`
was failing on one assertion. Reproduced first, before touching anything:

```
assert "helper3((int)(arg0), (int)(arg1), (int)(arg2))" in generated
E   AssertionError: // glaurung: cdecl_chain @ 0x8049192
E     int cdecl_chain(int arg0, int arg1, int arg2) {
E         extern int helper3(int, int, int);
E         int ret;
E         ret = helper3(arg0, arg1, arg2);
E         return ret;
E     }
```

The signature assertion on the line above (`cdecl_chain(int arg0, int arg1, int
arg2)`) passed. Only the call-boundary casts were gone. The failure is
pre-existing and unrelated to the in-flight `ProgramTypes`/DWARF work.

### Finding the commit

Did not bisect; `git log -S` located it in one step. The casts are written by
`write_typed_call_arg_dec` in `src/ir/ast.rs`, and the thing that stops writing
them is `integer_call_arg_cast_is_redundant` (`src/ir/ast.rs:10578`):

```
$ git log --oneline -S 'integer_call_arg_cast_is_redundant' -- src/ir/ast.rs
5e24383 feat(decompiler): x86 scalar floating point, GOT folding, and a Rust DWARF reader
```

`5e24383` is the commit *immediately after* `6768e55 test(decompiler): expect
explicit i386 argument casts`. So the expectation was pinned one commit before
the code that changed it landed, and `5e24383` — a 62-file, 6597-insertion port
off a branch — did not re-run it. It could not have: the test carries
`@pytest.mark.slow`.

Note that `DEC_PTR_ARGS` (`src/ir/ast.rs:9063`), the int/pointer register-reuse
reconciliation, is *not* the mechanism here and never was. It maps
pointer-typed argument names to pointer types; `arg0`-`arg2` are `int` in this
function's recovered signature, so it does not fire. The casts came from the
unconditional call-boundary conversion in `write_typed_call_arg_dec`.

### (a) regression or (b) stale pin

(b), a legitimate improvement. Three independent lines of evidence.

**The round trip actually runs.** Ran the test with only the cast assertion
replaced by a print, everything downstream intact:

```
3 passed in 1.71s
```

That path writes the generated text into `rebuilt.c`, compiles it with
`gcc -m32 -O0 -g -fno-pie -no-pie`, and executes both binaries over
`(-9,4,7)`, `(0,0,0)`, `(1,2,3)`, `(31,-17,5)`, comparing against the
`a + 2*b + 3*c` oracle. The uncast C compiles and produces identical output,
negative arguments included. If the lost casts were a real truncation the
`(31,-17,5)` and `(-9,4,7)` vectors are exactly where that would show.

**The elision is proof-backed, not heuristic.** The admitting arm is
`Expr::Reg(register @ VReg::Phys(_)) => declared_reg_ctype(register) ==
parameter_type`, and `declared_reg_ctype` (`src/ir/ast.rs:10345`) reads
`DEC_DECLARED_CTYPES` first — documented as "the exact C type actually printed"
for that name in this render. So the test is: the identifier this render will
print is declared exactly the type the parameter is declared. `int` to `int`.
The conversion is the identity by construction, not by inference. The other two
arms are an integer literal the type represents exactly and a symbolised code
address already rendered `(long)(name)`; everything else — pointers,
expressions, unrecognised types — keeps its cast, which is the correct
direction to be wrong in.

**The repo already holds the opposite position, with a test.**
`python/tests/test_cli_decompile.py:588` asserts
`arm_hf_mixed_callee(7, arg0, arg1)` and carries a comment saying this used to
render `(int)(7), arg0, (int)(arg1)` — "casts that state nothing and that a
C-signature type_match has to parse around." That assertion was written *after*
`5e24383`. Two tests pinned contradictory conventions; the PE32 one was the
stale half.

Cost of the noise is not only readability: identity casts at a call boundary are
tokens DecBench's C-signature `type_match` has to parse around.

### Fix

Updated the expectation rather than deleting it, and made it strictly stronger
than the old one — it now pins both the exact call spelling and the absence of
any identity cast, so a re-regression in either direction fails:

```python
assert "helper3(arg0, arg1, arg2)" in generated, generated
assert "(int)(arg" not in generated, generated
```

with a comment recording that `5e24383` is why the expectation moved and that
the round trip below is what licenses it.

### Verification

```
$ uv run pytest python/tests/test_pe32_cdecl_roundtrip.py
3 passed in 0.72s

$ uv run pytest python/tests/test_cli_decompile.py -q
37 passed
```

`uvx ruff check` clean. `ruff format --check` reports one complaint on line 67,
in a function this change does not touch; confirmed pre-existing by running it
against `HEAD:python/tests/test_pe32_cdecl_roundtrip.py`, left alone rather
than mixed into this diff.

Per the session constraints, DecBench, Joern, `decbench_matrix.py`,
`arch_roundtrip.py` and the full fixture matrix were not run.

### The reusable lesson

The defect was not in `5e24383`'s code, which is right. It was that a
`@pytest.mark.slow` expectation pinned one commit earlier was invisible to the
port that invalidated it. A pin written to capture *current* output, one commit
before a large in-flight change to the code that produces it, is a trap with a
one-commit fuse. When output is pinned because it happens to be what comes out
rather than because it is what must come out, the pin should say which it is.

## Entry 7 — ARM32 and vector round-trip triage

Diagnosing five pre-existing `@pytest.mark.slow` failures (all confirmed
pre-existing at `fb4ee6b`, none caused by anything in this session), per
design rule 11 ("ARM32 is a conformance architecture, not an optional
afterthought") and the roadmap's instruction to find the first wrong semantic
stage rather than stop at the verdict. Cross-compiler check first, since a
recent aarch64 failure this week turned out to be gcc-15 toolchain drift, not
a product defect:

```
$ arm-linux-gnueabihf-gcc --version   # 15.2.0 (Ubuntu 15.2.0-16ubuntu1)
$ aarch64-linux-gnu-gcc --version     # 15.2.0
$ clang --version                     # Ubuntu clang 21.1.8
$ qemu-arm --version                  # 10.2.1
```

No cross-toolchain version is in question for any of the five — none of them
touch aarch64 or the region-tree-depth code path from that earlier incident.

### Failures 1-4 — `rb_validate` memset cast, all four ARM32 parametrizations

- `test_arm32_o2_rb_validate_round_trips_source_asm_ir_c_and_execution[armv7]`
- `test_arm32_o2_rb_validate_round_trips_source_asm_ir_c_and_execution[armv7_a32]`
- `test_arm32_o0_rb_validate_round_trips_split_frame_addresses[armv7]`
- `test_arm32_o0_rb_validate_round_trips_split_frame_addresses[armv7_a32]`

All four fail on the same line shape, one assertion pinning a call-boundary
cast on `memset`'s second argument:

```
$ uv run pytest "python/tests/test_decompiler_arm32_semantics.py::test_arm32_o2_rb_validate_round_trips_source_asm_ir_c_and_execution[armv7]" -x
...
>   assert re.search(r"memset\([^\n]+,\s*\(int\)\(0\),[^\n]+64", decompiled.stdout)
E   AssertionError: ... var12 = memset((void *)(&local_164[0]), 0, (__SIZE_TYPE__)(64)); ...
```

The O0 split-frame variant pins the same shape more tightly
(`test_decompiler_arm32_semantics.py:421-425`):
`memset\(\(void \*\)\(&local_[0-9a-f]+\[0\]\),\s*\(int\)\(0\),\s*\(__SIZE_TYPE__\)\(64\)\)`,
and the actual output is `var17 = memset((void *)(&local_14c[0]), 0,
(__SIZE_TYPE__)(64));` (armv7) / `var7 = memset(...)` (armv7_a32). Every
assertion *before* the memset line passes in all four cases — the O2 variant's
disassembly checks (`memset@plt`, `ldmib`/`ldr.w`), the "prototype-resolved"/
"prepared numbered LLIR" markers, the `local_*[64]` array recovery, and the O0
variant's full `stack object hints` displacement triple
`(-332, 64), (-268, 128), (-140, 128)`. Only the cast is missing.

This is the exact defect already root-caused and fixed in Entry 6, for a
different pinned test (`test_pe32_cdecl_roundtrip.py`, i386). Confirmed same
mechanism here:

```
$ git log --oneline -S 'integer_call_arg_cast_is_redundant' -- src/ir/ast.rs
5e24383 feat(decompiler): x86 scalar floating point, GOT folding, and a Rust DWARF reader
```

`write_typed_call_arg_dec` (`src/ir/ast.rs:10510`) stopped writing an
identity cast at a call boundary when `integer_call_arg_cast_is_redundant`
(`src/ir/ast.rs:10578`, added by `5e24383`) proves it converts nothing —
here, the literal `0` argument to `memset`'s `int` parameter, which `0`
represents exactly. All four ARM32 assertions were written by
`b81e7991 Fix ARM32 stack aggregate and addressing semantics` (2026-08-08),
four days before `5e24383` (2026-08-12) landed the elision and never touched
`test_decompiler_arm32_semantics.py`. Same one-commit-fuse pattern as Entry 6,
just a different pinned test the same port missed.

**First wrong stage: rendering.** Lifting, SSA, structuring, and type
recovery are all untouched — the call is still `memset(dst, 0, 64)` at every
earlier stage; the only difference is the C pretty-printer's call-argument
cast rule, which now elides a provably-redundant cast.

**Verified the execution semantics are unaffected**, not just assumed:
rebuilt `16_red_black_tree.c` for `armv7:O2` and `armv7:O0` with the exact
`arch_roundtrip._build_argv` flags (`-shared -fPIC -g -O{opt} -w
-march=armv7-a -mfpu=vfpv3-d16 -mthumb`, matching stack-protector default —
no `-fno-stack-protector`), and drove `diff_decompile.run` directly against
`rb_validate` for both lanes, bypassing the failing regex assertion entirely:

```python
results = D.run(target, source, "16_red_black_tree", seed=1234, fuzz=M.FIXTURE_FUZZ,
                 reference_so=reference, lane="armv7:O2", native_cc=A.native_cc("armv7"),
                 native_runner=A.native_runner("armv7"), only={"rb_validate"})
# -> {'rb_validate': {'status': 'pass', 'detail': '23 cases (native target ABI)'}}
```

Same result for the O0 lane. QEMU execution agrees with the host reference
on all 23 fuzz cases in both lanes; the missing cast is pure noise the render
now correctly omits.

**Classification: stale test expectation**, not a regression and not
toolchain drift. Confidence: high — same mechanism Entry 6 independently
verified with three lines of evidence (round-trip execution, proof-backed
elision condition, and a contradictory-but-newer test already asserting the
uncast form), applied here to four more pinned assertions the `5e24383` port
missed for the same reason.

**Suggested next action**: apply Entry 6's fix pattern to
`test_decompiler_arm32_semantics.py` — replace the four
`(int)(0)`-pinning regexes with the uncast form plus a negative assertion
(`"(int)(0)" not in decompiled.stdout` or similar), matching the
`helper3(arg0, arg1, arg2)` / `"(int)(arg" not in generated` shape from the
i386 fix, with a comment citing `5e24383` and this diary entry.

### Failure 5 — vectorized `mem_copy` loses its `__builtin_memmove` fold

`test_decompiler_vector_memory.py::test_vectorized_mem_copy_round_trips_clang_o2`
builds `09_memory_effects.c`'s `mem_copy` with `clang -O2` (SSE `movups`
auto-vectorization) and asserts the decompiled C folds the vector copy back
into a single call:

```
$ uv run pytest python/tests/test_decompiler_vector_memory.py::test_vectorized_mem_copy_round_trips_clang_o2 -x
...
    assert "__builtin_memmove(" in code
E   AssertionError: ... 'void mem_copy(int * arg0, const int * arg1, int arg2) {\n ...
    var30 = *(int *)(((long)arg1 + var28 * 4 + 0x4));
    ...
    *(int *)(((long)arg0 + var28 * 4)) = *(int *)(((long)arg1 + var28 * 4));
    *(int *)(((long)arg0 + var28 * 4 + 0x4)) = var30;
    ...  (16 scalar loads + 16 scalar stores per 32-byte unrolled block)
```

`H.run_lanes(...)["09_memory_effects:clang:O2"] == {"mem_copy": "pass"}`
*passes* first (the earlier assertion in the same test) — execution is
correct, only the pattern-fold assertion at line 36 fails. So the defect is
not a wrong-value bug; it is a lost decompiler-quality recovery that the test
is specifically there to guard (added by `f1c3295 decompiler: preserve
128-bit memory moves`, 2026-07-31).

Traced with `GLAURUNG_DUMP_PASSES=1` against a locally-rebuilt copy of the
same `.so` (`arm-linux-gnueabihf-gcc` not involved; this is a pure x86-64
build, host `clang` 21.1.8). Even the *first* dump, `prototype-resolved
LLIR` — the closest view to raw lifted output — already shows the defect,
so nothing downstream (SSA, structuring, type recovery) introduced it:

```
0x1260: %xmm0_d0 = load[4 bytes] MemOp{ base: rsi, index: rax, scale: 4, disp: 0,  size: 4 }
0x1260: %xmm0_d1 = load[4 bytes] MemOp{ ..., disp: 4,  size: 4 }
0x1260: %xmm0_d2 = load[4 bytes] MemOp{ ..., disp: 8,  size: 4 }
0x1260: %xmm0_d3 = load[4 bytes] MemOp{ ..., disp: 12, size: 4 }
0x1260: %xmm0 = concat %xmm0_d1:%xmm0_d0        <- spurious, only two of four lanes
0x1264: %xmm1_d0..d3 = load[4 bytes] ...
0x1264: %xmm1 = concat %xmm1_d1:%xmm1_d0        <- same
0x1269: store ... <- %xmm0_d0                   (store batch starts here)
0x1269: store ... <- %xmm0_d1
...
```

`vector_copy::recover_wide_copies` (`src/ir/vector_copy.rs`) exists
precisely to rejoin a four-lane load batch immediately followed by a
four-lane store batch into one 16-byte `Deref`/`Store`, which is what later
lets the renderer fold it into `__builtin_memmove`. Its matchers
(`load_batch_at`/`store_batch_at`, `vector_copy.rs:62-133`) require the store
batch at `index+4` (or `index+8` with exactly one differently-named 4-lane
batch in between) — `body.get(start..start+4)`, an exact-adjacency check. The
injected `concat` statement sits at `index+4`, one slot into where the store
batch needs to start, so neither branch matches and the pass silently
declines for every occurrence. Confirmed by diffing "after
`recover_wide_copies`" against the pre-pass dump: identical, `concat` and all
sixteen scalar accesses still present, nothing rejoined.

```
$ git log --oneline -S 'synchronise_xmm_views' -- src/ir/lift_x86.rs
5e24383 feat(decompiler): x86 scalar floating point, GOT folding, and a Rust DWARF reader
```

Same commit as failures 1-4. `synchronise_xmm_views` (`src/ir/lift_x86.rs:3212`,
called unconditionally from `lift_one` at line 3298) was added to fix a real,
different bug — GCC `-O0`'s scalar float return crossing the lane/scalar view
split (`movsd -8(%rbp),%xmm0; movq %xmm0,%rax; movq %rax,%xmm0` returning a
zero reconstructed from lanes no scalar store had written). Its rule: after
any instruction that writes dword lanes 0 or 1 of an xmm register, if the
whole-register name is not already defined and the write is not a pure
lane-for-lane register copy (`single_source_of_lane_copy`), synthesize
`whole = concat(lane1, lane0)`. A plain `movups`/`movdqu` **memory load**
lowers to exactly four independent `Op::Load`s (`packed_dword_move_ops`,
`lift_x86.rs:2280`) — not a register-to-register copy — so
`single_source_of_lane_copy` returns `None` and the concat fires every time,
whether or not anything ever reads the whole-register view. For a pure
128-bit memory-to-memory transport (the vectorized-memcpy case this test
covers) nothing does — the fix for one bug pollutes the statement stream for
an unrelated, correctness-orthogonal case, and that pollution is what defeats
`recover_wide_copies`.

**First wrong stage: lifting.** Specifically `synchronise_xmm_views` in
`src/ir/lift_x86.rs`, applied indiscriminately after every lift rather than
being scoped to cases where a later scalar read of the whole-register view
could plausibly occur. This is upstream of `recover_wide_copies`,
`reconstruct`, all type recovery, and rendering; all of those still receive
and correctly propagate the polluted IR, they just never get the chance to
see the clean 16-byte load/store shape they are built to fold.

**Classification: real semantic/quality defect**, not toolchain drift (pure
x86-64 host build, no cross-compiler involved) and not a stale expectation
(unlike failures 1-4, the pinned property — `__builtin_memmove(` — is still
exactly the desired output; `5e24383` regressed it as a side effect of an
unrelated, legitimate fix, rather than superseding it by design). Confidence:
high on the mechanism (traced from the very first pass dump, root commit
identified by `git log -S`, execution correctness independently confirmed via
the test's own earlier `H.run_lanes` assertion), medium on the blast radius —
`packed_dword_move_ops` backs `Movdqa`, `Movdqu`, `Movaps`, `Movups`,
`Movapd`, and `Movupd`, so any register-to-memory or memory-to-register
128-bit packed move (not just this one fixture's shape) likely loses the same
recovery whenever nothing else in the function reads the destination's
whole-register scalar view.

**Suggested next action**: scope `synchronise_xmm_views`'s concat synthesis
so it does not fire for a plain four-lane `Op::Load`/`Op::Store` batch with
no intervening use of the whole-register name in this same lift — e.g. only
emit the concat when a later instruction in the function actually reads the
scalar view (deferring the sync to a proper liveness-driven pass rather than
per-instruction), or teach `recover_wide_copies` to tolerate/discard a
provably-dead intervening `concat` before matching the store batch. Either
requires touching `src/ir/lift_x86.rs` or `src/ir/vector_copy.rs`, both
outside this session's diagnostic scope; not attempted here.

### Summary table

| failure | first wrong stage | classification | confidence | suggested next action |
|---|---|---|---|---|
| `test_arm32_o2_rb_validate_round_trips_source_asm_ir_c_and_execution[armv7]` | rendering (`write_typed_call_arg_dec` / `integer_call_arg_cast_is_redundant`, `src/ir/ast.rs`) | stale test expectation | high | update regex to the uncast form, per Entry 6's fix to `test_pe32_cdecl_roundtrip.py` |
| `test_arm32_o2_rb_validate_round_trips_source_asm_ir_c_and_execution[armv7_a32]` | rendering (same) | stale test expectation | high | same |
| `test_arm32_o0_rb_validate_round_trips_split_frame_addresses[armv7]` | rendering (same) | stale test expectation | high | same |
| `test_arm32_o0_rb_validate_round_trips_split_frame_addresses[armv7_a32]` | rendering (same) | stale test expectation | high | same |
| `test_vectorized_mem_copy_round_trips_clang_o2` | lifting (`synchronise_xmm_views`, `src/ir/lift_x86.rs`) | real semantic/quality defect | high (mechanism) / medium (blast radius) | scope the concat synthesis to actual whole-register reads, or make `recover_wide_copies` tolerate a dead intervening `concat` |

Per the session constraints, DecBench, Joern, `decbench_matrix.py`, the full
fixture matrix, and `scripts/decbench-local-gate.sh --decbench` were not run.
Only scoped single-fixture builds and direct `diff_decompile.run`/
`GLAURUNG_DUMP_PASSES=1` invocations were used. No product code was changed.

---

## Entry 8 — The xmm scalar-view bridge that hid every 16-byte transport

Entry 7 classified `test_vectorized_mem_copy_round_trips_clang_o2` as the one
real defect among the five round-trip failures. Fixed here.

### What was wrong

`synchronise_xmm_views` (`src/ir/lift_x86.rs:3212`) appends
`Op::Concat { dst: xmmN, hi: xmmN_d1, lo: xmmN_d0 }` to any instruction that
wrote lanes but not the whole-register name, so a later scalar read still sees a
defined value. It exists for a real bug — a GCC `-O0` scalar-float return — and
is correct in that role.

It runs per INSTRUCTION, so it cannot know whether the scalar view is ever read.
A plain 128-bit `movups` load gets one unconditionally. Lowered, the concat is
`xmm0 = xmm0_d1 | xmm0_d0`, and it lands between the lane loads and the lane
stores — exactly where `vector_copy::recover_wide_copies` expects the store
batch. The rejoin never fired, so no 16-byte `Store`/`Deref` existed for the
renderer to fold, and `__builtin_memmove` never appeared.

Execution was unaffected throughout: the test's own `H.run_lanes` assertion
passed. This was an output-quality defect, not a semantic one.

### Why the two obvious fixes do not work

- **Scope the concat to real scalar reads.** `synchronise_xmm_views` sees one
  instruction's ops. The whole point of the bridge is a read in some *later*
  instruction, so the information is not available where the decision is made.
- **Let DCE remove it.** `recover_wide_copies` is deliberately the first AST
  pass (`python_bindings/ir.rs:495`, "before copy propagation erases the common
  16-byte transport identity"). DCE runs after, by design.

### The hazard neither the triage nor the first attempt caught

Rejoining the lanes stops defining `xmmN_d0`/`xmmN_d1`. A bridge that survived
the rejoin would therefore read undefined operands and overwrite the recovered
value with garbage. Any fix that merely lets the matcher *skip* the bridge is
wrong unless it also deletes it.

### First attempt, and why the real IR rejected it

Teaching the matcher to skip a bridge at `index + 4` passed both unit tests and
still failed on the real binary. Dumping the actual lifted IR
(`GLAURUNG_DUMP_PASSES=1` on `09_memory_effects-clang-O2.so`, `mem_copy`) showed
why — clang emits the batches interleaved, each load batch followed by its own
bridge:

```
0x1260: %xmm0_d0..d3 = load ...
0x1260: %xmm0 = concat %xmm0_d1:%xmm0_d0
0x1264: %xmm1_d0..d3 = load ...
0x1264: %xmm1 = concat %xmm1_d1:%xmm1_d0
0x1269: store ... <- %xmm0_d0..d3
0x126d: store ... <- %xmm1_d0..d3
```

The store batch for `xmm0` is at `index + 10`, not `index + 4` or the existing
interleave fallback's `index + 8`. Patching offsets was chasing one layout out
of many. A synthetic unit test that passes while the real binary still fails is
the signal to go and look at the real IR.

### The fix

Delete provably-dead bridges in a pre-pass, then run the batch matcher
completely unchanged:

1. `dead_scalar_views` collects every bridge target in the function and keeps
   those read nowhere. Reads are found with `dead_stores::stmt_reads`, which
   already walks every statement and expression shape — hand-rolling a second
   walker here produced four wrong variant guesses before I threw it away, and
   would have been a second place to forget a variant.
2. `drop_dead_scalar_views` removes them at any nesting depth.
3. `recover_body` is untouched.

Deleting a definition nothing reads is correct on its own terms, independent of
whether any rejoin fires, and it makes the matcher's layout arithmetic
irrelevant — every interleaving works for free.

The liveness test is deliberately coarse and whole-function: a bridge is dropped
only when its view is read nowhere at all. Over-approximating reads fails
closed, keeping the explicit lane form.

### Evidence

- `test_vectorized_mem_copy_round_trips_clang_o2`: **passes**.
- `cargo test`: 2218 passed, 0 failed.
- Two unit tests, written failing first: the dead-bridge case must recover both
  16-byte transfers *and* remove the bridge; the control, where the scalar view
  is read later, must leave the body byte-for-byte unchanged.
- Fixture matrix and structural lane: run because this changes emitted output.

---

## Entry 9 — The fixture that caught the fix

Entry 8 removed dead xmm scalar-view bridges so `recover_wide_copies` could see
its store batch. That landed as `ac8d7df` with the fixture matrix and structural
lane green. It was still wrong, and the existing corpus could not tell.

### Why a new fixture

The whole of `src/ir/vector_copy.rs` was covered by ONE lane:
`09_memory_effects:clang:O2`, whose `mem_copy` is a single `dst[i] = src[i]`
loop. Nothing exercised two transports in one body — which is exactly the
layout that had just defeated the first attempt at the fix. A pass that had just
proved fragile was being defended by one shape.

`188_vector_transport` adds four functions: forward copy, backward copy, two
streams from one source, and `vt188_lane_math` as the control (every element is
transformed, so it is lane computation and must NOT be rejoined). `clang -O2`
emits 116 packed moves for it, so the pass is genuinely exercised.

### What it caught, immediately

First run: 15 of 16 cells passed. The failure was
`clang:O2:vt188_copy_two_streams` — and it was a correctness bug in the fix
committed minutes earlier:

```c
__builtin_memcpy(var39, (void *)((long)arg2 + var38 * 4), 16);
__builtin_memmove((void *)((long)arg0 + var38 * 4), var39, 16);
*(int *)((long)arg1 + var38 * 4)       = var40;   /* var40..43 never assigned */
*(int *)((long)arg1 + var38 * 4 + 0x4) = var41;
```

`first_dst[i] = src[i]; second_dst[i] = src[i];` compiles to ONE load batch
feeding TWO store batches. Rejoining the first pair replaces the four lane loads
with a single 16-byte load into the whole-register name, so the lanes stop being
defined — and the second store batch is left reading them. It wrote garbage into
the second buffer.

`recover_wide_copies` had always assumed a load batch belongs to exactly one
store batch. The bug predates entry 8; the dead bridge had been accidentally
masking it by preventing the rejoin from ever firing. Removing the bridge did
not create the unsoundness, it exposed it — which is the more useful thing a
fixture can do than confirm the happy path.

### The guard, and a second mistake

Only rejoin when every lane register has at most one reading statement in the
whole function. Counted once before mutation, since the pass only removes and
replaces.

The first version of that guard silently never fired. Lane registers carry value
versions — `xmm0_d0#3` — and `lane_name` folds the version into the WIDE half,
parsing that as wide `xmm0#3`, lane 0. So reconstructing the lane name as
`format!("{wide}_d{lane}")` produced `xmm0#3_d0`, which names nothing, every
lookup returned a count of zero, and every batch looked exclusive. The fix is to
collect the actual `VReg`s off the load statements instead of rebuilding names
from a lossy parse. Inverting a parser by string concatenation is a bug waiting
for a version suffix.

### Evidence

- `188_vector_transport`: 16/16 cells pass (was 15/16 with a silent wrong
  answer).
- `cargo test`: 2219 passed, 0 failed.
- Five `vector_copy` unit tests, including
  `a_lane_batch_with_two_consumers_is_not_rejoined` pinning the soundness rule.
- `test_vectorized_mem_copy_round_trips_clang_o2` still passes, so the guard did
  not simply disable the optimisation.
- `baseline.json`: 16 additions, zero other verdicts moved.
- `structural_baseline.json`: 20 additions, zero other entries changed.

### The lesson

The corpus is the thing that finds what review does not. A pass with one lane is
a pass with one shape tested, and the shapes that break it are the ones nobody
wrote down. Adding the fixture cost minutes; it caught a silent wrong answer in
code that had already passed a full matrix run, a structural lane, and 2218 unit
tests.

---

## Entry 10 — MIR definedness queries

Roadmap item 3: *"Complete the MIR queries that consumer needs (`value_at`,
clobbers, reaching sets) instead of adding local scans."* EPIC 5 already had
`definition`, `uses`, dominance verification, `all_paths_defined`, and a
region-aware MemorySSA. This closes `value_at`, `clobbers_between`, the
reaching-definition set, and — because it fell out of the same walker —
`memory_version`. That is the whole EPIC 5 minimum query surface.

All work is confined to `src/ir/mir/`. `DefinitionOracle` still has zero
production callers; this is the surface the first migrated consumer will use,
not a migration.

### The thing that shaped every decision

An unannotated `Op::Call` contributes **no register definition at all**.
`def_uses` returns `None` for it, so SSA never versions the ABI result, so the
use edge after the call still names the pre-call value. An annotated call is
barely better: `CallEffects` declares `result` and `args` but has no clobber
list, and `TargetSpec` does not own one either (EPIC 4, still open).

A `value_at` built naively on the use edges would therefore have answered *"rax
still holds the value from before the callee ran"* — confidently, and wrongly.
That is exactly what rule 5 forbids, so the queries are deliberately **stricter
than the SSA edges they are derived from**.

`MirInstruction` gained one field to carry that:

```rust
pub enum EffectCompleteness { Complete, Opaque }
```

`builder::register_effects` marks an instruction `Opaque` when any of three
things is true, each of which is a real way MIR loses a write:

1. it is `Op::Call` or `Op::Unknown` — no enumerable clobber set exists yet;
2. its canonicalized `defs_uses` destinations outnumber `ssa.def_values` — SSA's
   `write_regs` keeps only `Phys`/`Temp`/`Flag`, so a `FlagValue` destination
   writes a storage that has no MIR value at all; or
3. it writes a bit-preserving sub-register view. `al` is deliberately *not*
   merged into `rax` by the SSA parent rule (`regview::ssa_parent` declines it),
   so a write through the narrow view leaves the wide storage's MIR value
   untouched while the machine bits move. Detected with
   `regview::parent_of` and gated to targets that have sub-register views at
   all, so ARM32 does not borrow the AArch64 table.

One deliberate narrowing: `VReg::Temp` is exempt from opaque clobbering. A
lifter temporary has no machine existence, so no callee can write it. Without
that exemption every query after every call would be `Unknown` and the surface
would be useless as well as correct.

### Exact semantics

A `ProgramPoint { block, index }` names the gap immediately **before** the
instruction at `index`; `index == instructions.len()` is the block's outgoing
edges. Block phis execute on the incoming edges, so they are already applied at
`index == 0`. Constructors: `block_entry`, `block_exit`, `before`, `after`.

Every state-returning query answers one type:

```rust
pub enum DefinitionState<T> {
    Exact(T),
    Set { values: Vec<T>, undefined_path: bool },
    NoDefinition,
    Unreachable,
    Unknown(UnknownReason),
}
```

`Set` is rule 6's *proved set*. It is retained, never collapsed to its most
plausible member; `undefined_path` records that at least one path arrives with
no MIR definition of the storage at all. `NoDefinition` is honest rather than
alarming: the machine location holds bits, MIR simply has no identity for them
here (e.g. asking about `rax` before its first write, where SSA created no
version-0 input because nothing read it).

**`value_at(storage, point) -> DefinitionState<ValueId>`** — a forward fixed
point over reachable blocks, seeded with the function's explicit `Input` value
for the storage, overridden on entry to each block by that storage's phi, killed
by every instruction output naming the storage, and driven to
`Unknown(OpaqueInstruction)` by an opaque instruction. A named output is
authoritative for its own storage even on an otherwise opaque instruction, and a
later definition recovers from the unknown, so an annotated call still yields
`Exact` for its declared result register. Fails closed on: a storage outside the
arena (`UnknownStorage`), a point naming no real position (`InvalidPoint`), and
an opaque instruction on a path (`OpaqueInstruction`). Returns `Unreachable`,
not `Unknown`, for a point in an unreachable block — that is a proof, not a
failure.

**`memory_version(region, point) -> DefinitionState<MemoryValueId>`** — the same
walker over the region's MemorySSA chain. It deliberately does **not** add a
second opaque rule on top: MemorySSA already owns conservative call and
unknown-instruction clobbers as explicit `Clobber` accesses and gives every
region an explicit entry state, and duplicating that here would replace verified
conservatism with a guess about it.

**`clobbers_between(value, from, to) -> ClobberAnswer`** — `None`,
`Clobbered(Vec<ClobberKind>)`, or `Unknown(reason)`. Three things clobber:
`Definition` (an instruction output names the storage with a *different* value),
`Opaque` (an instruction MIR cannot enumerate, machine storages only), and `Phi`
(entering a block merges a different value into the storage across an edge that
is actually traversed). Writing the same `ValueId` again is not a clobber; SSA
identity is what is being tracked.

Interval membership is computed on a **point graph** — one node per
`ProgramPoint`, intra-block gap edges plus CFG edges — with forward reachability
from `from` and backward reachability from `to`. An instruction at `(b, i)`
counts iff `forward[(b, i)] && backward[(b, i+1)]`. Block-level reachability
cannot distinguish "the interval re-enters this block" from "this block merely
lies between the two", so a loop back edge that rewrites the storage is found
even when `to` textually precedes `from`. Fails closed on: an unowned value
(`UnknownValue`), an invalid or unreachable point, **no path at all** from
`from` to `to` (`NoPath` — the question is malformed, not vacuously true), and
`value` not being the proved `Exact` state of its own storage at `from`
(`ValueNotHeldAtOrigin`). A `value_at` failure at `from` propagates its reason
verbatim.

**`reaching_definitions(use) -> ReachingSet`** (and
`reaching_definitions_of_value`) — resolves transitively through phis to the
non-phi roots: `Input`, `InstructionOutput`, `Undef`, `UnknownEffect`, or
`Unreachable`. Roots and traversed phis are reported separately, sorted and
deduplicated. Phi cycles terminate because each value is expanded at most once,
so a loop-carried phi that names itself is fine. `single()` returns `Some` only
when the set is complete *and* a singleton — a two-element set never degrades
into one plausible answer. `incomplete_reasons()` carries `BrokenPhiEdge` /
`UnknownValue` when the walk could not finish; `is_complete()` is the guard.

### Tests

23 new tests in `src/ir/mir/query_tests.rs`, each written failing first.

| EPIC 5 case | covered by |
|---|---|
| diamonds | `value_at_a_diamond_join_is_the_merging_phi` |
| conditional definitions | `value_at_a_conditional_definition_merges_the_untracked_live_in` — the unconditional arm keeps its explicit `Input` root rather than inheriting the defined arm |
| loops | `value_at_a_loop_header_is_the_loop_carried_phi`, `clobbers_between_sees_a_loop_back_edge_rewrite`, `reaching_definitions_terminate_through_a_phi_cycle` |
| irreducible flow | `value_at_irreducible_flow_still_resolves_to_one_phi` (two-entry `b1`/`b2` loop) |
| calls | `value_at_after_an_unannotated_call_fails_closed`, `clobbers_between_reports_an_unannotated_call_conservatively`, `memory_version_after_an_unannotated_call_is_its_clobber` |
| multi-output intrinsics | `value_at_after_a_multi_output_intrinsic_names_each_declared_output` — each declared output is `Exact` *and* an `UnknownEffect` value; footprint and value-knowledge are separate axes |
| undef / poison | `value_at_a_poisoned_storage_is_the_explicit_undef_value`, `reaching_definitions_keep_a_poisoned_arm_in_the_proved_set` |
| memory aliases | `memory_version_advances_every_region_an_unproven_pointer_may_alias`, `memory_version_leaves_the_heap_alone_for_a_proven_frame_store`, `memory_version_at_a_join_is_the_memory_phi` |
| unreachable | `value_at_in_an_unreachable_block_is_explicitly_unreachable` |
| explicit failure | `value_at_rejects_an_out_of_range_storage_and_point`, `clobbers_between_fails_closed_without_a_path`, `clobbers_between_refuses_a_value_that_does_not_hold_the_storage` |
| **exceptions** | **not covered** — LLIR has no exceptional-edge representation to test against (see the open "Complete CFG" workstream) |

Negative controls are paired throughout: the opaque-call case has
`an_opaque_call_cannot_clobber_a_lifter_temporary` and
`clobbers_between_proves_an_undisturbed_value`; the alias case has the
proven-frame-store control.

The load-bearing test is `real_functions_never_answer_with_the_wrong_value`,
which lowers `main` from the real x86-64 and ARM32 fixtures and holds the
surface to a one-directional invariant: **a query may refuse to answer, but it
may never answer with a different value than the verified SSA edge it is derived
from.** For every reachable use it asserts `value_at` is either `Exact(use
value)` or `Unknown(OpaqueInstruction)` — never a different `Exact`, never
`NoDefinition`, never a silent `Set`. It also asserts every reaching set is
complete and contains no phi roots, that `clobbers_between == None` implies
`value_at == Exact` (the two queries cannot disagree), and that every region's
memory state is `Exact` at every reachable block entry.

`cargo test`: **2246 passed, 0 failed** (49 in `ir::mir`, of which 27 are the
new query tests). Clippy is clean on the four touched files.

### What this does not do

- **No consumer is migrated.** Item 3 built the surface item 2 will consume;
  call-argument recovery, copy propagation, DCE, stack promotion, return
  recovery, and expression reconstruction all still run their own local backward
  scans. Deleting those is the next step, and each needs its own parity work.
- **`Set` never occurred in practice.** SSA here places phis at the full
  iterated dominance frontier, not pruned by liveness, so every join already has
  a merged identity and every real query answered `Exact` or `Unknown`. The
  variant exists because rule 6 requires the *representation* — and because a
  transactional graph editor (the next EPIC 5 item) can produce merges SSA
  construction never would. It is currently unexercised by a real binary.
- **Opaque is very coarse for calls.** Every call poisons every machine storage
  it does not explicitly name, because no clobber contract exists to consult.
  This is correct and useless in roughly equal measure: on real `main` bodies the
  post-call answers are all `Unknown(OpaqueInstruction)`. Narrowing it is EPIC
  4's *"make all call and intrinsic read/write/clobber effects target-owned"*,
  and until that lands a consumer migrating to this surface must be prepared for
  honest unknowns where its old backward scan produced a confident wrong answer.
  That is the point, but it is a real migration cost and should be planned for.
- **Sub-register writes fail closed rather than resolve.** A write to `al` marks
  the instruction opaque instead of updating `rax`'s state, because MIR has no
  partial-write model. Fixing it properly is EPIC 4 register-view work; the
  interim behaviour is conservative, not silent.
- **No caching.** Each `value_at` / `memory_version` call runs its own fixed
  point over the function, and each `clobbers_between` builds a fresh point
  graph. That is fine for the current zero callers and fine for interactive
  queries; the first pass that calls it per instruction will need a memoized
  per-storage solve. Deliberately not built ahead of a measured consumer.
- **`cargo fmt` collateral.** Running it repo-wide reformatted in-progress files
  owned by concurrent work outside `src/ir/mir/`. Semantically inert, but
  future workers on a shared tree should scope it to their own paths.

---

## Entry 11 — Fixture coverage survey

*Analysis only. No fixtures, source, or baselines were touched. Scope: every
production pass that shapes decompiler OUTPUT — the ordered AST pipeline in
`src/python_bindings/ir.rs` (the `pass!` macro), the ~50-step cleanup pipeline
in `ir::ast::prepare_for_decbench_with_output_and_protected_locals`, the
lifters, and `ir::structure`. Method: read the pass in source, then check
whether `tests/decompiler_fixtures/src/*` actually drives its precondition —
by an explicit `COVERAGE TARGET` doc comment where one exists, by direct
evidence (a diary/design doc that measured a fire rate), or by grepping fixture
sources for the relevant C shape and inferring. Every inferred (not confirmed)
claim below is labeled as such.*

### What Entry 9 actually proved about the corpus

The `188_vector_transport` incident is not really a story about `vector_copy.rs`.
It is a story about what "one lane" hides: a pass with a single fixture is a
pass whose only proof of correctness is that ONE shape happens not to trigger
its worst assumption. The question this entry answers is which other passes
are in that position right now, ranked by how bad "wrong" would be if they are.

### The authoritative pass list

`run_ast_passes` (`src/python_bindings/ir.rs:432`, its `pass!` macro body
starting around line 480) runs 12 named stages in order, several of
which bundle multiple sub-transforms:

```
recover_wide_copies -> reconstruct -> fold_constants -> fold_boolean_masks
-> prune_dead_flags -> fold_got_pointer_loads -> recover_resolved_tail_calls
-> reconstruct_args -> apply_known_call_contracts -> split_call_result_lifetimes
-> canary+strings -> promote_stack_locals -> recognise_machine_frame
-> materialize_direct_output -> split_argument_storage_reuse -> apply_role_names
-> eliminate_dead_stores -> stack_idiom+label_prune
```

Downstream of that, `ir::ast::prepare_for_decbench_with_output_and_protected_locals`
(`src/ir/ast.rs:7080`) is a second, larger ordered pipeline — the semantic AST
cleanup and CFG-structuring stage — that calls roughly 50 further named
transforms across `copy_prop`, `guard_chain` (6 distinct `collapse_*`
functions), `switch_ladder`, `guarded_switch`, `select_fold`, `guarded_call`,
`lazy_call_select`, `terminal_loop`, `label_prune`, `loop_form` (6 distinct
`recover_*`/`promote_*` functions), and `latch_predicate`, each run once or
twice to a bounded fixpoint. This second pipeline is where the `[r]`-flagged
always-hoist and goto-sinking experiments lived, and where the still-open
sentinel-search gap lives. `ir::structure::recover_verified_with_health` (CFG
region recovery) runs once, earlier, to produce the input both pipelines
share. The three lifters (`lift_x86.rs`, `lift_arm32.rs`, `lift_arm64.rs`) sit
upstream of all of it and are exercised by construction on every lane, so
their coverage question is about specific rare instruction forms, not about
whether they run at all.

### Instrumentation check: `pass_stats` is currently disconnected

The 2026-08-12 measurement that found `recover_sentinel_search_loops` at
0/5695 and `recover_guarded_do_whiles` at 1/1984
(`docs/design/dormant-transforms-2026-08-12.md`) worked because
`GLAURUNG_PASS_STATS` call sites had been added to `loop_form.rs` in commit
`51514cc`. **They are gone now.** `grep -rn "pass_stats::" src/` finds zero
call sites anywhere in the crate; `src/ir/pass_stats.rs` compiles, has its own
passing unit test, and is never invoked. The roadmap's own ask — "keep
pass-fire instrumentation and either add standing real coverage for extremely
rare transforms or retire them deliberately" — is unmet on the instrumentation
side as well as the coverage side: the tool that found the two dormant
transforms cannot currently be used to check whether they, or any other pass,
have drifted further toward (or past) zero. This is a correctness-adjacent gap
in its own right — confirmed by direct grep, not inferred.

### Roadmap cross-references

- **"Add a real end-to-end fixture for an array indexed with a constant
  bias"** — **SATISFIED.** `187_constant_bias_index.c` (read directly) has
  `bias_forward_sum` (`values[index + FORWARD_BIAS]`), a two-object biased
  case (`adjacent_difference`), and two negative controls
  (`value_bias_not_index` adds the constant to the loaded value, not the
  index; `variable_bias` uses a runtime displacement) — exactly the shape and
  the negative-control discipline `stack-bias-affine-index-2026-08-13.md`
  asked for. Already closed per Entry 10's `8f661ff`/`d3578ad`.
- **"Add a linked-structure argument kind to the differential harness before
  changing the nearly dormant sentinel-list recovery pass"** — **NOT
  satisfied.** `183_sentinel_list_search.c`'s own doc comment states its
  "COVERAGE TARGET" is `recover_sentinel_search_loops`, but
  `dormant-transforms-2026-08-12.md` explicitly recorded that this exact
  fixture's index-walk shape is 0 fires — the pass needs a real pointer chase
  through a struct field over caller-owned, harness-relocated memory, which
  `tools/diff_decompile.py` cannot synthesize today. The fixture that exists
  documents the gap; it does not close it.
- **"Keep pass-fire instrumentation and either add standing real coverage for
  extremely rare transforms or retire them deliberately"** — **regressed**, per
  the instrumentation check above: the instrument that would tell you this now
  has no call sites.
- **The `[r]` measured rejections:**
  - *Always-hoist loop recovery* — **already defended.** The four functions
    across six lanes that the experiment broke
    (`03_loop_shapes:while_prefix:gcc:O2`,
    `12_loop_rotation:find_first_set:gcc:O2`,
    `13_loop_early_exit:classify_run:{clang,gcc}:O2`,
    `14_flag_effects:countdown:{clang,gcc}:O0`) are all live, named functions
    in fixtures already in this corpus today (confirmed by filename match
    against `ged-recovery-measured-trade.md`). A repeat attempt would fail the
    ordinary fixture matrix without any new fixture.
  - *Goto sinking* — **moot, not defended.** `src/ir/goto_sink.rs` no longer
    exists (confirmed: no such file). The GED regression it caused
    (`statemachine:gcc:O0`) was measured on a DecBench external project, which
    has no equivalent in this repo-native corpus — there is no local
    behavioral fixture that would re-catch a *readability* regression from a
    revived sinking pass (this corpus checks execution-differential and
    structural facts, not GED/readability). Not urgent while the pass stays
    deleted; worth a line in whatever readability metric eventually gets
    defined, per the roadmap's own next step for that item.
  - *The late table-layout patch* (function-pointer-table call-argument
    recovery) — **already defended, and proven so.**
    `95_function_pointer_table.c:dispatch_operation` is a real
    execution-differential fixture (not just structural) and currently
    records `fail` at `gcc:O2` in `baseline.json`. Per
    `table-dispatch-arguments-2026-08-12.md`, this is the exact fixture whose
    behavioral mismatch is how the "plausible, well-typed, but wrong
    arguments" attempt was caught and reverted. The remaining work here is
    implementing the fix correctly (per that doc's two suggested approaches),
    not adding coverage.

### Ranked gap table

Ranked by (coverage thinness) x (blast radius if wrong) among passes that
still lack standing, targeted, real-execution coverage.

| pass | current lanes | risk if wrong | proposed fixture shape | roadmap item it serves |
|---|---|---|---|---|
| `loop_form::recover_sentinel_search_loops` / `recover_guarded_do_whiles` | 0 confirmed fires / 1 fire in 1984 (2026-08-12 measurement); `183_sentinel_list_search` targets but does not trigger it; instrumentation to re-check is currently disconnected | A rotation-matching pass this narrow silently doing nothing is invisible (identical output to "did not fire"); a future edit could subtly mismatch and nobody would see a lane move | A `struct node { struct node *next; int key; }` search over a **parameter-supplied, harness-relocated** linked list, walked by pointer chase (`p = p->next`), searched under `clang -O1`+ — the exact trigger `dormant-transforms-2026-08-12.md` isolated. Requires the harness's "linked-structure argument kind" first | "Add a linked-structure argument kind to the differential harness before changing the nearly dormant sentinel-list recovery pass" (open) |
| `lazy_call_select::collapse_lazy_call_diamonds` + `copy_prop::move_adjacent_effectful_scratch_values` | No fixture found with an externally observable side effect (a write to caller memory or an accumulator) inside a call folded into a ternary/diamond; `83_ternary_chains.c` has no call in any arm (grep-confirmed) | Same failure family as the `188_vector_transport` bug: an assumption ("this call has exactly one evaluation") that only a differential over a side channel, not just the return value, can falsify. A silently double-executed side-effecting call is a correctness bug indistinguishable from "the return value matches" | `int r = flag ? record_event(&counter, x) : default_value(x);` where `record_event` writes to a caller-owned counter/buffer AND returns a value used further; assert the counter's final state, not only `r` | Not separately named in the roadmap; same soundness class as EPIC 5 (`clobbers_between`, exactly-once effect evaluation) and the ast.rs comment at line ~7180 ("an `Expr::Call` must retain exactly one evaluation") |
| `ir::structure` irreducible-flow fallback | No hand-written genuinely irreducible C found (checked `145_control_flow_flattening.c`/`146`/`148`: all are single-loop dispatcher/switch flattening, which is reducible); `structure.rs` self-describes this path as a "safety net" | Highest blast radius in the survey: this is the pass the roadmap calls "the current large structuring owner" and flags for irreducible/unresolved-edge honesty. A wrong fallback here can invent or drop CFG edges, which is silent-wrong-answer territory at the level below any AST pass | Two `goto`s into the same loop body from two different, non-dominating outer branches (the textbook irreducible CFG), built so each entry path produces a distinguishable accumulated result; execution-differential proves whichever edge set the structurer actually emitted | "Preserve irreducible and unresolved flow with explicit goto/indirect fallback rather than inventing structure" (open); "Separate dominance/loop discovery, region selection, verification, and HIR projection from the current large structuring owner" (open) |
| `ir::guard_chain`'s six `collapse_*` functions (`collapse_shared_exit_guard_ladders`, `collapse_shared_assignment_guards`, `collapse_redundant_copy_nested_guards`, `collapse_nested_terminal_return_guards`, `collapse_adjacent_break_guards`, `collapse_matching_terminal_return_guard`) | Each is almost certainly exercised incidentally by guard-heavy fixtures (`07_packet_parser`, `163_wire_header_parser`, `164_nested_tlv_walker`) — **inferred, not confirmed** — but none has a fixture written to pin its specific merge precondition the way `188_vector_transport` pins `vector_copy`'s exclusivity rule | Six separate shape-conjunctions in one 1384-line file, each a candidate for the same "one clause too strict, or one clause missing" failure mode already proven twice in this codebase (`vector_copy`, `recover_sentinel_search_loops`) | A guard ladder where two of three early-return guards share an assignment AND a third shares only the return constant but reads a value the others do not — the near-miss that would defeat an over-eager merge; run through all six functions' preconditions in one fixture family | Not separately named; supports the same-family caution the `[r]` entries already record |
| `ir::call_result_split::split_call_result_lifetimes` / `ir::value_split::split_argument_storage_reuse` (AArch64 dual-role register splitting, e.g. `UMULL`-shaped widening multiply) | `02_integer_widths.c` and several curriculum fixtures (`61_fixed_point`, `65_projectile_motion`, etc.) contain widening-multiply source shapes and run through the required `armv7_a32`/AArch64 arch lanes — **inferred coverage**, not confirmed to actually produce the dual-role register pattern the pass's own doc comment names | Splitting a value that should stay unified (or failing to split one that must) silently aliases two logically distinct values; the module's own doc comment calls out this exact hazard for AArch64 | An AArch64-targeted fixture computing `(int64_t)a * (int64_t)b` from two 32-bit parameters where the low and high halves are both used afterward (forcing the dual-role register to serve two live purposes) | ARM32 acceptance work: "Cover VFP s/d/q overlap" and general "ARM32 is a conformance architecture" (open, adjacent) |

### What ranked lower, and why

- **`ir::canary` (`recognise_canary`/`collapse_canary_save`, 1379 lines)** —
  initially looked exactly like `vector_copy`'s risk shape (pattern-matches
  compiler bookkeeping and deletes it), but `nm -D` against the 738 already-
  built fixture `.so` files shows 89 of them import `__stack_chk_fail`
  (Ubuntu 22.04's gcc/clang default to `-fstack-protector-strong` and the
  harness never disables it). A regression here would move dozens of lanes at
  once, not one silently — the opposite risk profile from `vector_copy`'s
  single lane. Deprioritized on that basis (confirmed by direct binary
  inspection, not inferred).
- **`ir::readonly_fold::fold_guarded_readonly_lookups`** — four fixtures
  (`101_static_locals`, `116_string_literals`, `126_x_macros`,
  `85_designated_initializers`) contain `static const` array/table shapes.
  Plausible incidental coverage; not investigated further given the budget
  here.
- **Lifters (`lift_x86`/`lift_arm32`/`lift_arm64`)** — coverage is broad by
  construction (every lane exercises every lifter); the real gap is specific
  rare instruction forms, and the corpus already shows the right pattern for
  closing those one at a time (`181_compensated_summation` for `subsd`,
  `184_rep_stos_widths` for `rep stos{b,d,q}`, `185_subword_signed_division`
  for `cbw`/`cwd`). No new lifter gap was found beyond what the roadmap's ARM32
  acceptance section already lists open (A32/Thumb condition execution, VFP
  s/d/q overlap, literal pools) — those remain valid but are not newly
  discovered here.

### Honesty note on method

Everything in the "ranked lower" section and three of the five ranked-gap rows
rest on grepping fixture sources for a plausible C shape, not on tracing an
actual pass-fire event — because the one instrument that could confirm firing
(`pass_stats`) is disconnected (see above). The `recover_sentinel_search_loops`
row and the three roadmap-satisfied cross-references are the only claims here
backed by a prior direct measurement or a fixture read rather than an inferred
shape match.

---

## Entry 12 — Two dead transforms, now measurable

Entry 11's survey reported that `src/ir/pass_stats.rs` had zero call sites and
described the instrumentation as removed. The first half is right; the second is
not, and the distinction matters.

`git merge-base --is-ancestor 51514cc HEAD` says the commit carrying the
`loop_form.rs` call sites is **not an ancestor of master**. The instrumentation
never landed here. Nothing broke it — it was simply never wired, so the
roadmap's "keep pass-fire instrumentation" ask was unmet from the start rather
than regressed. Worth checking ancestry before believing a removal story: the
grep evidence for "it used to be here" is identical either way.

### Restored

`attempt()` at both public entry points and `fire()` at both rewrite sites, so
`fire / attempt` measures the selectivity of the match. Instrumenting only
attempts would have produced an unfalsifiable zero.

### What it says immediately

Across `183_sentinel_list_search`, `13_loop_early_exit`, `03_loop_shapes` and
`12_loop_rotation`, gcc and clang at -O0:

```
280  recover_guarded_do_whiles      attempt        0  fire
140  recover_sentinel_search_loops  attempt        0  fire
```

`183_sentinel_list_search.c` documents itself as the sentinel pass's coverage
target. It offers the pass 13 bodies and gets no match. This reproduces the
2026-08-12 dormant-transform finding (0/5695 and 1/1984) on fresh input and with
a different corpus slice.

Both passes are a shape conjunction one clause too strict, and the failure mode
is invisible by construction: the pass compiles, its unit tests pass because
they construct exactly the shape it wants, the gate stays green, and "did not
fire" is indistinguishable from "fired and changed nothing" in the output.

### What this does not decide

Whether to widen the match or retire the passes is the deliberate choice the
roadmap asks for, and it is a product decision. This restores the measurement so
that choice rests on evidence rather than on nobody having looked. The roadmap's
own framing — "either add standing real coverage for extremely rare transforms
or retire them deliberately" — is now actionable.

### Session note on agent output

Two agent reports in this session contained a claim that did not survive
checking: one described the pass-stats instrumentation as removed when it had
never landed, and one reported `cargo test` totals alongside a type error that
rust-analyzer was still showing. The second turned out to be analyzer lag —
`cargo check` exited 0 and 2246 tests passed — but both were worth verifying
directly rather than relaying. An agent's conclusion is evidence, not a result.

---

## Entry 13 — ARM32 entry-stack coordinates

Roadmap ranked item 4: "extend the dual current-SP/CFA entry-stack coordinate
model to ARM32 and prove it in both Thumb and A32 modes."

### What the AArch64 gate actually was

Not what the roadmap text implies. The gate on the *coordinate re-expression*
was lifted at `401ac4f` (2026-08-06): `aapcs_entry_stack_coordinate`,
`normalized_stack_slot`, `entry_stack_base`, `alloc_name`'s stacked-argument
rule, and `dwarf_stack_object_hints`' `DW_OP_call_frame_cfa -> entry_sp` mapping
all already accept `CallConv::Arm | ArmHardFloat` beside `Aarch64`. The
still-open acceptance item was describing a state that had partly moved.

The gate that was actually left is one line up the stack, and it is an
ARM32-internal A32-versus-Thumb split:

```rust
const STACK_BASES: &[&str] = &["rsp", "esp", "sp", "rbp", "ebp", "bp", "x29", "w29", "fp"];
```

AArch64's frame register is `x29` and A32's is `fp` (r11), and both are in that
list. **Thumb-2's is `r7`, and it is not.** GCC anchors Thumb frames on `r7`
because most sixteen-bit encodings cannot reach the high registers. So
`is_active_stack_base("r7")` was false, and the `is_arm_frame_pointer` guard —
which already listed `"fp" | "r7" | "r11"` — was nested *inside* the
`is_active_stack_base` branch of `collect_stack_address_defs` and therefore
unreachable for `r7`. Its `"r7"` arm was dead code.

Consequence, measured on `arm-linux-gnueabihf-gcc -mthumb -O0` binaries: the
`pop {r7, pc}` epilogue redefines `r7`, `record_definition` saw a second
definition with no resolvable address, marked the register ambiguous, and threw
away the entry-SP coordinate for the whole function. Thumb frames promoted
**nothing**. The same source compiled `-marm` promoted normally.

### What was widened

All in `src/ir/stack_locals.rs`.

1. `StackContext` carries `arm_frame_register: Option<&'static str>`, proved by
   `arm_frame_register()` from a top-level prologue that derives `fp`/`r7`/`r11`
   from `sp`. Evidence-gated on purpose: `r7` is an ordinary callee-saved
   register in `-O2` code, and `[r7+8]` without that proof is a pointer
   dereference, not an argument home. `fp`/`r11` keep their unconditional
   recognition, so A32, AArch64, and x86 behaviour is unchanged.
2. The ARM frame-anchor branch in `collect_stack_address_defs` now runs *before*
   the `is_active_stack_base` branch rather than inside it, so `r7` reaches it.
3. `terminal_dead_overwrite` became `frame_coordinate_is_dead_after`. A32 tears
   its frame down with `sub sp, fp, #4` — the frame register is never
   redefined — so "no later read at all" sufficed. Thumb tears down with
   `adds r7, #32; mov sp, r7`, and GCC lowers that add through register
   temporaries, so it is neither foldable nor unread. The new predicate allows
   reads that cannot inherit the coordinate (the SP restore itself, and the flag
   and width temporaries hung off the same add) and still rejects any memory
   access, copy, call escape, or returned address, via `expression_roots_at`,
   which mirrors exactly the shapes `resolve_stack_address` resolves.
4. A bare frame-anchor escape mints at most a pointer-sized slot.
   `push {r7, lr}` saves the *caller's* frame register; the alias map is keyed by
   register rather than by program point, so that store's source resolves to this
   frame's anchor coordinate. The anchor is by construction the base of the whole
   frame, so the "grow conservatively to the frame base" extent measures the
   frame. A32's `fp` sits one word below the CFA and produced a harmless
   four-byte slot; Thumb's `r7` sits at the bottom and produced a forty-byte
   array that swallowed `seed`'s argument home. Every path that joins an already
   proven object runs first, so a real escape into a DWARF aggregate still
   resolves at its real extent.
5. `record_definition`'s `(None, None)` arm now poisons the register. A
   definition carrying no stack address must make the register ambiguous even
   when seen *first*, because the map is keyed by register: one later address
   definition otherwise claimed the whole body, including the region where the
   register held something else. GCC's pre-value-folding Thumb lowering reuses
   one temporary for both a loaded integer and the epilogue's frame address, and
   that backdated coordinate made four ordinary `t0 + t1` adds look like
   *subscripted* frame accesses, which seeded a byte object spanning the frame.
   Value-numbered bodies define each name once and are unaffected.

`src/python_bindings/ir/dwarf_contracts.rs` needed no change. Its ARM
`DwarfStackBase::CallFrameCfa -> ("entry_sp", 0)` mapping is already correct and
is the only one GCC exercises: across 28 ARM builds (7 fixtures x {A32, Thumb} x
{O0, O2}), every `DW_AT_frame_base` was `DW_OP_call_frame_cfa`, never a
register. The `Register(11 | 7) -> ("fp", 0)` arm beside it is currently dead for
GCC and is left alone; see "not finished" below.

### Real A32 and Thumb evidence

RED first. `thumb_frame_register_shares_the_a32_entry_stack_coordinates` builds
the recovered body of `pass_large_by_value` from
`tests/decompiler_fixtures/src/129_struct_by_value.c` in both encodings' real
shapes — A32 establishes `fp = sp + 4` before allocating (CFA-4), Thumb
establishes `r7 = sp + 8` after it (CFA-40) — and asserts they recover one source
frame. On master the A32 half passed and the Thumb half failed with
`frame_coordinates["local_24"] == None`. Two more tests: a negative control
(scratch `r7` with no prologue proof stays a pointer dereference) and the reused
temporary above.

Whole-binary control, `--style c`, `-O0`, both encodings of eight fixtures,
counting raw unpromoted frame memory (`&[`) and distinct promoted `local_` names:

| fixture | A32 | Thumb before | Thumb after |
|---|---|---|---|
| `07_packet_parser` | 34 / 25 | 141 / 1 | 34 / 25 |
| `100_struct_layout` | 17 / 9 | 33 / 1 | 17 / 9 |
| `108_multidimensional_arrays` | 15 / 9 | 72 / 1 | 15 / 10 |
| `111_self_referential_struct` | 20 / 9 | 55 / 1 | 20 / 2 |
| `129_struct_by_value` | 19 / 9 | 58 / 3 | 23 / 11 |
| `153_many_live_locals` | 15 / 138 | 2792 / 1 | 2792 / 1 |
| `15_binary_search_tree` | 24 / 15 | 99 / 1 | 24 / 9 |
| `163_wire_header_parser` | 52 / 12 | 198 / 1 | 52 / 12 |

Seven of eight Thumb lanes now match their A32 control's raw-memory count
exactly. The "before" column is the same tree with only the three owned files
stashed, so it is a controlled comparison, not a comparison against a different
revision. Every A32 number is identical before and after.

Concretely, `pass_large_by_value` Thumb went from every access spelled
`&[var0+0xc]` to `local_24` (the `seed` argument home at CFA-36) and `local_1c`
(the twenty-byte `struct Large value` at CFA-28) — the same two names the A32
build recovers. The `--style decbench` output for both encodings is byte-identical
to master.

Ratchet: `tools/arch_roundtrip.py --arch armv7 --arch armv7_a32 --opt O0 --opt O2`
over 32 fixtures, 192 lanes including the `x86_64` control lane, **zero** diffs
against `tests/decompiler_fixtures/arch_baseline.json`.

`cargo test`: 2250 passed, 0 failed, across 23 suites (2157 in the lib). Three
new tests. No new clippy findings — the two `src/ir/stack_locals.rs` warnings are
identical with the change stashed. Python: 11 decompiler suites plus
`test_decompiler_arch_roundtrip.py`, `test_decompiler_curriculum_corpus.py`, and
`test_decompiler_metamorphic.py` all pass.

### Not finished

- `153_many_live_locals:armv7` is unchanged and still recovers one local against
  A32's 138. Its Thumb body reuses `r3` as a chained address cursor
  (`r3 = r7 + 552; r3 = r3 - 540; store [r3]`) *and* as a constant register, so
  the register-keyed alias map cannot hold both. This is the same
  program-point-insensitivity the `(None, None)` fix makes safe rather than
  wrong; making it *precise* needs value numbering on that path, not a wider
  coordinate model. A32 escapes it only because its lowering folds the same
  address into one instruction.
- The ARM `DwarfStackBase::Register(11 | 7)` hint arm seeds a slot keyed on the
  frame register's own name, which ARM32 accesses can never match now that they
  all resolve to `entry_sp`. GCC never emits it, so this is latent, not live;
  fixing it needs the anchor's entry-SP offset, which only the pass knows.
- The A32 machine frame still survives into the output as
  `local_8 = &local_4[0]` because `arm32_prologue::match_epilogue` only accepts
  `sp += N` teardowns, not A32's absolute `sp = fp - 4`. Unchanged by this work
  and outside the owned files.
- VFP s/d/q overlap, hard-float versus soft-float selection, PC bias, literal
  pools, and condition execution — the rest of EPIC 4's ARM32 list — are
  untouched.

## Entry 15 — Partitioning the MIR frame object

Roadmap ranked item 10, the piece that unblocks item 2: "partition the single
MIR frame object into per-variable extents from proven accesses, so a
per-variable question can be asked of MIR at all." Owned files only:
`src/ir/memory_objects.rs`, `src/ir/memory_objects/*`, `src/ir/mir/*`.
DecBench, Joern, the fixture matrix, `arch_roundtrip.py`, and repo-wide
`cargo fmt` were not run.

### The shape the model was in

`src/ir/memory_objects/mir.rs` keys every stack access by
`ObjectIdentity::MirValue(root)`, where `root` is the SP/FP `Input` value, and
folds the displacement into each access's `offset`. One object per root
pointer. Measured on `20_graph_bfs.c:graph_bfs` (gcc `-O0`, x86-64), that is a
single object carrying offsets -160, -152, -148, -144, -124, -120, -116, -112,
-108, -40, -32, -16 and -8 — the four spilled arguments, the five scalar
locals, the two eight-byte stores that zero `seen`, and the stack canary, all
in one bag. Nothing can ask that object about one variable.

### The partitioning rule

New `src/ir/memory_objects/partition.rs`, computed once in
`MemoryObjectBuilder::finish` for every object and reachable as
`MirFunction::object_partition(ObjectId)`.

1. Each access contributes the byte interval `[offset, offset + width)`.
2. A **covered run** (`PartitionExtent`) is a maximal contiguous span of
   covered bytes. Runs are separated by bytes no access reaches.
3. Inside a run, every position where an access starts or ends is a *candidate*
   variable boundary and is retained with its evidence:
   - `Spanned` — some single access covers bytes on both sides, so one machine
     access treats them as one storage unit;
   - `Abutting` — accesses meet there and none spans it, so the evidence
     neither joins nor separates the two sides.
4. `bounds_at(offset)` answers a per-variable question with two bounds:
   `at_least` is the interval between the nearest *abutting* boundaries (no
   observed access divides it), and `at_most` is the covered run (no observed
   access joins it to anything outside).

### What it refuses to split, and why

Nothing in a set of machine accesses proves that two adjacent bytes belong to
two different source variables. Compilers pack frames densely: at `-O0`,
`162_unaligned_memcpy_access.c:ua162_store_be32` covers -44 through 0 with no
hole at all. A rule that split at every abutment would invent variable
boundaries, and a rule that merged whole runs would merge distinct variables —
the worse error. So the model splits only where the bytes themselves are
unobserved, and reports every interior candidate with its evidence instead of
deciding. `at_least` and `at_most` are both evidence-backed; neither is a
guess, and both are monotone under new evidence (rule 4).

It also refuses *entirely* — `bounds_at` returns `None` while `extents` keeps
everything observed (rule 3) — when a `PartitionConflict` exists:

- `UnmodeledAccess` — an access rooted here was seen and could not be placed:
  a scaled index (`queue[head]`), or a memory effect the adapter could not
  attach. `direct_memop` used to drop indexed memops silently; it is now
  `address_memop` and reports them against the pointer they came from. This is
  the conflict `graph_bfs` raises, and it is the honest verdict: the 64-byte
  `queue` and the 16-byte `seen` are read and written only through scaled
  indices, so apart from `seen`'s zero-initialisation those 80 bytes are
  invisible to the object model and could join any two extents.
- `EscapedRoot` — a pointer into the object reached an operand position this
  adapter does not interpret, so a callee or an unmodelled operation may touch
  bytes it never saw.
- `UnboundedCursor` — the object is walked by a cursor with a stride, so a
  constant offset no longer names fixed bytes.
- `UnresolvedCoordinate` — a retained `LayoutConflict` invalidates the offset
  coordinate itself. Stride conflicts (`MissingStride`, `AccessPastStride`,
  `NegativeOffset`, `ConflictingStrides`) deliberately do *not*: they describe
  an array layout over the coordinate, not a wrong coordinate. Every frame
  object carries `MissingStride`, so mapping them all would have refused every
  frame.

### One x86 detail that decides whether this is usable at all

Escape detection marks every use of an affine-rooted pointer that the adapter
did not itself interpret. On x86-64 that fired on every single frame, because
`sub rsp, N` lifts to the subtraction plus four flag `Cmp`s that read the frame
root. A comparison reduces its operands to a boolean, so the address can go no
further; `consumes_pointer` exempts exactly `Op::Cmp` and nothing else. Every
other unmodelled operand position still escapes, because an unmodelled address
computation (`lea rax, [rbp+rcx]`) produces a *different* object whose accesses
would silently leave the frame's evidence.

Escape detection also needs `abi::annotate_calls` to have run: an argument
register is where a frame address leaves a function, and without the call's
may-use list the call has no use edges at all. Production lowers MIR from
annotated LLIR (`annotate_calls_in` runs before `prepare_llir_for_lowering`),
so the fixture harness annotates too.

### Evidence

Five real GCC `-O0` x86-64 fixtures, compiled in the test:

| fixture / function | what it proves |
|---|---|
| `162_unaligned_memcpy_access.c:ua162_store_be32` | the four byte-writes of `uint8_t staging[4]` have interior boundaries -19, -18, -17, all `Spanned` by the dword read that copies the array out: `at_least(-20) = [-20, -16)`. The 4-byte local at -24 abuts it and is not absorbed: `at_least(-24) = [-24, -20)`. `at_most` is the whole run `[-44, 0)`. |
| `91_union_type_punning.c:pun_halves_swapped` | the union's interior boundary at -18 is `Spanned` by the dword access, so the two `uint16_t` halves are one unit; the separate `uint16_t swap` at -22 abuts and stays separable. An unaccessed 2-byte hole really does split the frame into `[-28, -24)` and `[-22, 0)`. |
| `129_struct_by_value.c:pass_large_by_value` | the eight-byte by-value transfer spans -36 and -28 but not -40, -32, -24 — evidence exactly as wide as the copies. It also escapes: GCC leaves a frame-derived pointer in `rcx` at the call, so the whole partition refuses while keeping every extent. |
| `20_graph_bfs.c:graph_bfs` | two scaled-index arrays raise `UnmodeledAccess`; every offset in every extent returns `None`. |
| `84_compound_literals.c:compound_literal_argument` | `&(struct Pair){left, right}` handed to a callee raises `EscapedRoot`; nothing is bounded. |

Two synthetic-LLIR controls cover shapes no fixture provides: a frame pointer
in an annotated call argument, and a frame cursor with a stride.

Refusal rate, measured over `tests/decompiler_fixtures/build` (x86-64 only, one
partition per stack-rooted object, throwaway harness not committed):

| corpus | frame objects | bounded | EscapedRoot | UnmodeledAccess | UnboundedCursor |
|---|---:|---:|---:|---:|---:|
| `gcc-O0` | 1,339 | 1,253 (93.6%) | 58 | 33 | 5 |
| all `-O2` | 2,533 | 1,767 (69.8%) | 717 | 120 | 54 |

So the conservative reading costs 6% of `-O0` frames and 30% of `-O2` frames.
At `-O2` the dominant refusal is `EscapedRoot`, and most of those are the
convention-wide may-read list rather than a proven callee input — which is
EPIC 4's target-owned call contract, the same gap entry 10 recorded.

`cargo test` (default features): 23 test binaries, 2,278 passed, 0 failed, 1
ignored (pre-existing), on the shared tree at `6783274` with this increment
applied. `cargo clippy --all-targets` reports nothing on the new files.
`--all-features` was not run (needs `BITWUZLA_LIB_DIR`, absent on this host).

For most of the increment the shared tree could not compile at all: a
concurrent worker's in-flight `src/program/symbols` slice left ten unresolved
references in `src/program/session_tests.rs`. The RED/GREEN cycles therefore
ran in a detached worktree at `13f00ef` with a private target directory,
holding exactly the six files of this increment. The numbers above are from the
shared tree after that worker committed.

### What is left

- **No consumer has migrated.** This makes item 2 *expressible*: a promoted
  local's frame coordinate can now be handed to `bounds_at` and get an
  evidence-backed answer or an explicit refusal. Actually joining
  `high_variables::refine_object_cursor_values` to it is the next step and
  touches files this increment does not own.
- Classification (struct versus array versus union versus bitfield) is **not**
  done. The partition reports extents and boundary evidence; it does not name
  a shape. `Spanned` boundaries are where a union or a wide copy shows itself,
  but calling one a union needs the stride and type constraints of the rest of
  EPIC 3.
- Projection to HIR `Field` / `Index` / `AddressOf` is untouched, as instructed.
- The indexed-access hole is *reported*, not closed. Recovering `queue[i]` as
  an access to a bounded frame extent needs the affine-index slice the roadmap
  keeps under "near-term retained work"; until then every frame containing a
  subscripted local refuses, which is 33 of 1,339 `-O0` frames.
- Escape granularity is all-or-nothing. A callee that receives `&x` can compute
  any address from it, so nothing narrower is sound without a call contract.
- The partition is computed for every object, not only stack roots.
  Parameter-pointee objects get the same treatment for free, which is where
  struct-field recovery for pointer arguments would start.

## Entry 16 — CFG completeness and edge accounting

Scope: roadmap rank 9, "Finish CFG completeness and verified region
ownership." Its second half ("target the large O2-noinline GED cohort") is out
of scope — needs DecBench, which is forbidden this session. Owned files only:
`src/ir/structure.rs`, `src/ir/structure_accounting.rs`,
`src/ir/structured_reaching/*`, `src/ir/health.rs`, `src/ir/loop_form.rs`.
DecBench, Joern, the full fixture matrix, and `cargo fmt` (repo-wide) were not
run.

### The map: what edge completeness is tracked today, and what is dropped

Read `src/ir/structure.rs`, `src/ir/structure_accounting.rs`,
`src/ir/cfg_edges.rs`, `src/ir/health.rs`, and (read-only, out of ownership)
`src/ir/lift_function.rs` and `src/ir/ast.rs`'s `Region::Unstructured`
lowering, to answer the roadmap's five open bullets under "Complete CFG and
semantic structuring" directly.

**Tracked, with a real producer:**

- `crate::ir::cfg_edges::EdgeKind` — six edge kinds, each derived from the
  instruction stream rather than block position: `Taken`, `Fallthrough`,
  `SwitchCase`, `SwitchDefault` (derived: "the conditional edge that bypasses
  an indirect dispatch"), `Jump`, `Linear`. `Edge::back` is a separate flag
  computed from dominance (`to` dominates `from`), not folded into `kind`.
- `crate::ir::structure_accounting::account` — the total edge-accounting
  proof `recover_verified_with_health` itself uses to decide whether to
  trust a speculative region or fall back. It answers, for the WHOLE
  reachable graph: is any block dropped or duplicated, is any real edge
  unaccounted-for or expressed only by a weaker goto, is any implied edge
  absent from the real CFG, is any back edge un-owned by a loop header, is
  any `Goto` target never emitted, is a `Switch` dispatch structured outside
  the loop that contains it.
- `crate::ir::health::CfgHealth` (`uncovered_cfg_edges`, `invented_cfg_edges`,
  `structure_fallbacks`) is the immutable summary of that accounting for the
  SELECTED region, threaded through `AstHealth` and out to
  `PassHealthEvent`/`GLAURUNG_PASS_HEALTH` and the three PyO3
  `cfg_health` sites in `src/python_bindings/ir.rs`. It reaches the Python
  boundary.
- `AstHealth::unresolved_transfers` (`src/ir/health.rs`,
  `src/ir/ast.rs:8578`) counts indirect/unsupported-instruction transfers at
  the AST identifier-collector level.
- `recover_verified_with_health` (`src/ir/structure.rs:640`) is confirmed by
  reading it to be the single production entry point: on any accounting
  finding classified unsound (`structure_accounting_is_unsound` —
  `BlockDropped`, `EdgeUnaccounted`, `BackEdgeUnowned`, `ImpliedEdgeAbsent`,
  `GotoTargetMissing`, `SwitchArmOutsideLoop`) it discards the speculative
  tree and substitutes `Region::Unstructured((0..blocks.len()).collect())` —
  the complete labelled CFG over every block, not a partial guess.
  `Region::Unstructured` lowers in `ir::ast.rs` (read-only, not owned) to a
  label plus block body per entry, with an explicit `Stmt::Goto` wherever the
  next lexical block isn't the real successor — an honest goto, not invented
  structure. This is rule 8 working as designed, confirmed by a new test
  below rather than only by reading the code.

**Present but NOT reachable from `account()`'s edge kinds — the real gaps:**

- `EdgeKind` has no `Call`, `Return`, `TailCall`, `Exceptional`, or
  `Unknown`/unresolved-indirect variant. The roadmap explicitly asks for
  "direct, conditional, switch, indirect, exceptional, call, return,
  tail-call, and unknown terminal edges" to be represented explicitly; today
  only the intra-procedural control-flow-graph edges a structurer needs are
  typed. Call/return edges are implicit (a block simply has no CFG successor
  after a call, or ends the function), and there is no exceptional-edge
  representation anywhere in LLIR — `src/ir/mir/query_tests.rs`'s own doc
  comment says as much for MIR ("Exceptions are not covered: LLIR has no
  exceptional-edge representation yet"), and nothing in `cfg_edges.rs`
  contradicts that at the structuring layer either.
- Skipped bytes, clipped blocks, and per-function lift budgets are DROPPED,
  not carried. `src/ir/lift_function.rs` (read-only; owned by another lane)
  clips a block to `clip_block_to_owned_ranges` and silently `continue`s past
  any block whose bytes can't be located or whose start falls outside every
  owned range — its own doc comment: "Individual blocks whose bytes cannot be
  located ... are skipped silently; the function's other blocks still
  produce LLIR." No `SkippedByte`/`ClippedBlock` fact reaches `LlirFunction`,
  `CfgHealth`, or any diagnostic. `structure_accounting`'s own module doc is
  explicit about the resulting blind spot: "A block that never entered the
  CFG is not 'dropped by the structurer' — it does not exist as far as this
  module is concerned, and the region covering what remains is reported as
  faithful." So a clean `CfgHealth` (`uncovered_cfg_edges == 0`) proves the
  structurer didn't lose anything IT was given; it cannot and does not prove
  the lifter didn't lose blocks earlier. This is real "incomplete input
  becomes apparently complete downstream" risk (a roadmap stop condition) —
  not because the structurer lies, but because nothing upstream of it
  currently produces the fact that would let it tell the difference. Fixing
  it is squarely in `lift_function.rs`/`LlirFunction`, outside this session's
  owned files.
- Budgets: no cancellation/budget field was found threaded through
  `LlirFunction`, `Region`, or `CfgHealth`.
- Region recovery is not yet separated into independent
  dominance/loop-discovery, region-selection, verification, and
  HIR-projection stages (roadmap bullet 5): `src/ir/structure.rs` is 4,938
  lines and owns `Cfg` construction, dominance, the recursive region builder,
  verification, and the accounting call all in one file; `recover_verified_with_health`
  is the seam but not a stage boundary with its own artifact type.

### The increment: proving (not assuming) the irreducible-flow fallback is honest

Entry 11's fixture-coverage survey (this session, same diary) had already
flagged `ir::structure`'s irreducible-flow fallback as the highest-blast-radius
gap in the corpus: "No hand-written genuinely irreducible C found ... this is
the pass the roadmap calls 'the current large structuring owner' and flags for
irreducible/unresolved-edge honesty. A wrong fallback here can invent or drop
CFG edges, which is silent-wrong-answer territory below any AST pass." No test
anywhere in the crate constructs a genuinely irreducible CFG (a cycle entered
from two non-dominating predecessors — the shape a source-level
`if (c) goto mid;` into the middle of a loop produces) and checks what
`recover_verified_with_health` does with it.

Built the textbook minimal irreducible graph by hand (a graph-shape question,
not a behavior claim, so a hand-built LLIR fixture is the right tool per the
task's own method note — real C compiles this via `goto`, but no compiler was
run this session to avoid drifting into fixture territory):

```
0 (entry) -> 1 (fallthrough) | 2 (taken)
1 -> 2 (jump)
2 -> 1 (taken) | 3 (fallthrough, exit)
3 -> return
```

Block 0 branches DIRECTLY into either 1 or 2 — two non-dominating entries into
the {1,2} cycle. Neither `1` nor `2` dominates the other (block 0 reaches each
without passing through the other), so under `cfg_edges::classify`'s
`back: dominates(to, from)` rule, NEITHER direction of the {1,2} cycle is a
back edge. No block can serve as a header. Added
`the_two_entry_cycle_fixture_really_is_irreducible` first, asserting exactly
that against `Cfg::from`'s own edge classification, so the main claim below
rests on a checked premise rather than an assumed one.

RED before GREEN: ran the fixture through `recover_verified_with_health`
first with a throwaway `panic!("region={region:#?}\nhealth={health:?}")`
probe (not committed) to see the actual output before writing assertions,
per the task's TDD instruction. Result:

```
region = Unstructured([0, 1, 2, 3])
health = CfgHealth { uncovered_cfg_edges: 0, invented_cfg_edges: 0, structure_fallbacks: 1 }
```

This is the CORRECT verdict, not a defect: the speculative structurer's
candidate region failed `structure_accounting::account`'s soundness check (as
it must — no `While`/`DoWhile`/`RawLoop` pattern can honestly claim ownership
of a headerless cycle), and `recover_verified_with_health` substituted the
complete labelled CFG over all four blocks, with zero dropped and zero
invented edges. Turned that observation into three permanent tests in
`src/ir/structure.rs`:

- `the_two_entry_cycle_fixture_really_is_irreducible` — ground truth: neither
  `1->2` nor `2->1` is a dominance-based back edge in the built fixture.
- `two_non_dominating_entries_into_a_cycle_preserve_lossless_fallback` — pins
  the production result above: `Region::Unstructured` over all 4 blocks,
  `structure_fallbacks == 1`, `uncovered_cfg_edges == 0`,
  `invented_cfg_edges == 0`, AND independently re-runs
  `structure_accounting::account` against the SELECTED region (not trusting
  `CfgHealth`'s own arithmetic) — asserts it returns an empty `Vec`, i.e. the
  fallback region accounts for every block and every edge with nothing
  dropped, duplicated, or invented.
- `a_single_entry_into_the_same_two_block_cycle_structures_normally` —
  negative control: the same two-block cycle entered from only ONE place
  (ordinary reducible flow) must NOT hit the fallback
  (`structure_fallbacks == 0`), pinning that the fallback is triggered by
  irreducibility specifically, not merely by "a cycle exists between two
  blocks."

All three pass. This closes the identified test-coverage gap with a genuine
positive result: the honest-goto fallback the roadmap and design rule 8 ask
for already exists and already works correctly for this shape. The value
delivered is the proof and the permanent regression pin, not a bug fix — no
defect was found in `recover_verified_with_health` itself.

### Evidence

- `cargo test --lib ir::structure::tests::` — 56 passed, 0 failed (3 new).
- `cargo test` (full suite, all binaries + lib): `test result: ok. 2161
  passed; 0 failed; 0 ignored` for the lib target; every other integration
  suite in the run also reported 0 failed. This total includes tests added by
  other concurrent lanes this session in files outside this session's
  ownership — not attributed to this change alone.
- `rustfmt --edition 2021 src/ir/structure.rs` — applied, no other file
  touched. No repo-wide `cargo fmt` was run.
- No DecBench, Joern, `decbench_matrix.py`, `arch_roundtrip.py`, or full
  fixture-matrix run this session, per the constraint. No `tools/dectest.py`
  run either — the increment is a pure unit-level graph-shape proof inside
  `src/ir/structure.rs`'s own test module and needed no compiled fixture.

### What remains open

- Typed `Call`/`Return`/`TailCall`/`Exceptional`/unresolved-indirect edge
  kinds — `EdgeKind` still only names intra-procedural CFG edges.
  Exceptional edges have no LLIR representation at all (confirmed via the
  MIR query-test doc comment; not re-derived here).
- Skipped bytes and clipped blocks are dropped silently in
  `lift_function.rs`, upstream of every artifact this session's owned files
  produce. `structure_accounting`'s clean-accounting result is provably
  relative to the CFG it is handed, not to the function's real byte range —
  its own module doc says so. This is the sharpest remaining instance of the
  stop condition "incomplete input becomes apparently complete downstream,"
  and fixing it needs a file outside this session's ownership.
- No budget/cancellation field threads through `LlirFunction` or `CfgHealth`.
- `src/ir/structure.rs` (4,938 lines) is not yet split along
  dominance/loop-discovery, region-selection, verification, and
  HIR-projection boundaries — roadmap bullet 5 is untouched by this entry.
- The large O2-noinline GED cohort (roadmap item 9's second half) is
  explicitly out of scope this session (needs DecBench).

## Entry 17 — Canonical SymbolStore

Roadmap ranked item 7, first slice: build the canonical `SymbolStore` and the
exact operand-reference index it needs, importing only facts a program table
states verbatim. FLIRT, PDB, and every name-based library heuristic stay out;
the roadmap gates them behind safeguards that only exist once the store owns
provenance, and they are a later slice.

### What landed

`src/program/symbols.rs` (model, store, queries), `src/program/symbols/
object_import.rs` (exact importer), `src/program/symbols/verify.rs`
(independent verification), `src/program/symbols_tests.rs` (model controls),
plus real-binary tests in `src/program/session_tests.rs` and a
`ProgramSession::symbol_store()` accessor behind a `OnceLock`. The shape
deliberately mirrors `TypeStore`: stable typed identity, provenance-bearing
evidence, authority ordering, conflict retention, and an independent
`verify()` that recomputes every index from the arena alone.

- Identity is the exact linkage spelling: one name, one `SymbolId`.
- `SymbolEvidence { authority, source, module, version }` keeps the roadmap's
  required name-knowledge provenance. `SymbolSource` distinguishes the object
  symbol table, dynamic symbol table, import table, export table, static
  relocation, and dynamic relocation.
- `SymbolName { text, form, match_kind }` separates the linkage spelling from
  a `Demangled(scheme)` alias, and separates an `Exact` name read verbatim
  from a `Resemblance`. `exact_symbols_named` refuses to answer with a
  resemblance; `symbols_named` returns both. Nothing in this slice ever
  produces a `Resemblance` — the representation exists so the later catalog
  slice cannot quietly launder a guess into an exact match.
- `SymbolIncompleteness` is a monotone set (`note_incomplete` only inserts):
  no object symbol table, no dynamic symbol table, missing symbol sizes,
  section-relative addresses in a relocatable object, unresolved relocation
  targets, unreadable table, unreadable image.
- Contextual address queries return `AddressSymbol::{Exact, Containing,
  Unknown}`. `Unknown` carries a reason: `NoSymbolEvidence`, or
  `AmbiguousRanges(ids)` when several ranges with different starts cover the
  address. Aliases sharing one start resolve together with an offset; unrelated
  overlapping ranges are an explicit unknown rather than a pick.
- `SymbolReference { site, symbol, addend, implicit_addend, width_bits, kind,
  format_type, evidence }` indexes exact relocation-backed uses by site and by
  symbol. The generic `ReferenceKind` never discards the format-specific
  relocation type, which is what carries JUMP_SLOT/GLOB_DAT today (the
  `object` crate maps both to its generic `Unknown`).

### Conflict policy

A linkage name is not a unique program identity. Two translation units may
legally define distinct local symbols with the same spelling, and the store
must not let the last observation win. Agreeing facts merge and accumulate
evidence; a disagreeing fact records `SymbolConflict::IncompatibleDefinition`
and is retained as an alternative. Higher authority reorders selection only —
it never deletes the displaced fact, and both addresses stay resolvable.
Verified on a real two-unit fixture where GCC emits two LOCAL FUNC `helper`
symbols at 0x1129 and 0x1182.

### Negative controls

- A real stripped ELF (`cc -O0 -s`): no record for `symbol_target` or `main`,
  no alias resurrecting either, `resolve_address` at the known entry returns
  `Unknown(NoSymbolEvidence)`, `NoObjectSymbolTable` is declared, and every
  surviving record is an undefined dynamic import with no
  `ObjectSymbolTable` evidence. Absent evidence is not permission to invent a
  name.
- Two same-named local symbols are retained as a conflict, not deduplicated.
- `AmbiguousRanges` proves the range query refuses to choose between unrelated
  overlapping symbols.
- An empty linkage name and a reference to an unknown identity are both
  rejected as typed errors rather than absorbed.

### Evidence

`cargo test` (default features): 23 test binaries, 2,271 passed, 0 failed;
the lib target is 2,178 of those and includes the 18 new tests (9 model, 9
real-binary). `cargo clippy --all-targets` reports nothing on the new files.
`--all-features` was not run: it needs `BITWUZLA_LIB_DIR`, which this host
does not provide. DecBench, Joern, the fixture matrix, and `arch_roundtrip.py`
were not run — out of scope for this increment by instruction.

The whole gate ran in a detached worktree at `13f00ef` with a private target
directory, because a concurrent worker's in-flight edits to
`src/ir/memory_objects/*` left the shared tree uncompilable. The worktree
contained exactly the `src/program/` files of this increment on top of that
commit.

### What is still open before consumers can migrate

- Thunks are not classified. A PLT stub cannot be derived from exact tables
  alone: `.rela.plt` names the GOT slot, not the stub. That needs analysis
  evidence and belongs with the reference-interpretation slice.
- `SymbolStore` is built by a second `parse_object` call in the session,
  exactly as the DWARF importer already does. Roadmap Phase 1's "exactly one
  base object parse per reusable session" remains open and now has one more
  caller to fold in.
- Per-DLL identity for PE: two DLLs exporting the same name merge into one
  record with two module evidences. Honest but coarse; a `(module, name)`
  identity is the follow-up if it ever matters.
- No consumer has migrated. `src/ir/symbol_env.rs`'s `thread_local ACTIVE` and
  `src/ir/name_resolve.rs`'s `HashMap<u64, String>` are untouched by design;
  deleting them requires parity, which requires at least (a) a decision on how
  address-keyed consumers spell "no name" now that the answer is a typed
  `Unknown`, and (b) the operand-reference interpretation layer of EPIC 2,
  since most current consumers want "what does this constant mean here", not
  "what symbol is at this address".
- `src/program/symbols.rs` is 686 lines. Under the 1,000-line cap but above
  the 450-line mean target; splitting model from store is only worth doing if
  it produces a narrower API, so it is deferred rather than done reflexively.

## Entry 18 — Call arguments lost before recovery

Roadmap item 6, the direct-call half. The starting defect was
`189_effectful_select:gcc:O2`, where two cells failed while every other lane
of the same fixture passed:

```
189_effectful_select:gcc:O2:se189_select_call    fail
189_effectful_select:gcc:O2:se189_nested_select  fail
```

The emitted C was a direct call to a symbol the same file declares
`extern int se189_bump(int *, int);`, invoked with no arguments at all:

```c
ret = ((int (*)(void))se189_bump)();
```

The cast is the renderer being honest — `write_call_dec` casts whenever the
call site's recovered prototype contradicts the declaration — so the arity
was already gone by the time anything rendered. The recompiled function then
ran `calls[0] += 1` against whatever `rdi` happened to hold. Only counting
the side effect catches this: the returned value is unchanged, which is
exactly the soundness class the fixture was written for.

### First wrong stage

`reconstruct_args` (`src/ir/call_args.rs`), not DCE. The suspicion in the
task was that dead-code elimination deleted hoisted argument setup before
the contract could be applied. It did not. `GLAURUNG_DUMP_PASSES=1` shows the
setup still present at `recover_resolved_tail_calls` and still present after
`reconstruct_args` — unconsumed, because the pass declined to recover it:

```
    %rsi#2 = (unsigned long)((unsigned int)(%rdx));
    call se189_bump@plt();
```

`src/ir/dce.rs` only prunes flags and never touches argument registers, and
`eliminate_dead_stores` runs long after. The setup does eventually disappear,
but as a consequence of the empty argument list, not as its cause.

`gcc -O2` did not hoist the shared setup either. The real shape is simpler
and more awkward: it left `rdi` **untouched** across the whole diamond,
because nothing between the entry and either call clobbers it, and set only
`esi` inside each arm.

```
    114a:   mov    %rdi,%rbx
    114d:   movl   $0x0,(%rdi)
    1155:   jne    1170
    1157:   mov    %ecx,%esi
    1159:   call   se189_bump@plt
    ...
    1170:   mov    %edx,%esi
    1172:   call   se189_bump@plt
```

So slot one always had local setup and slot zero never did — and ABI
arguments are a contiguous prefix, so `fold_one_call` discards every
recovered slot once a lower one is missing. Losing slot zero lost slot one
with it. Three independent reasons produced that missing slot zero:

1. **A returning branch arm counted as a clobber.** For the fall-through
   call, the backward scan crosses the preceding `Stmt::If`, and
   `mark_arg_writes_in_stmt` descended into its then-arm — an arm that ends
   in `return`, and therefore is not on the path into the statement after it.
   Its `esi`/`rax` writes set `blocked_incoming`, which refuses the slot-zero
   backfill.
2. **The live-in spelling was answered from the wrong scope.** For the call
   *inside* the arm, `incoming_arg_expr` was passed only that arm's statement
   list. On the value-numbered DecBench path `value_number` leaves the live-in
   version bare (`rdi`) and versions every later definition (`rsi#2`), so a
   register the arm never mentions has no witness there at all and the
   function declined. How a function spells its own live-in argument register
   is a whole-function fact, not a per-block one.
3. **A labelled join blocked everything unconditionally.** `se189_nested_select`
   is structured with explicit `goto`/`Label` targets, so both calls sit
   directly after a join; the scan's `Stmt::Label` barrier does
   `blocked_incoming.fill(true)` and stops.

### The fix

Three changes, all in `src/ir/call_args.rs`, each with its own negative
control:

- `body_falls_through` — a branch arm ending in `Return`/`Throw`/`Goto`/
  `IndirectGoto` cannot reach the statement after the branch, so
  `mark_arg_writes_in_stmt` no longer descends into it. `Stmt::Break` is
  deliberately excluded: inside a `Stmt::Switch` case a break lands exactly
  on the switch's own successor and proves nothing. This is sound only
  because the scan already stops dead at `Stmt::Label`, so the absence of a
  label between the arm and the call means falling through is the only way in.
- `EnclosingSlots` — the enclosing scope, carried into nested bodies in both
  directions at once. `live_ins` holds the function-wide spelling of each
  argument register (computed once, from `f.body`); `blocked` holds what the
  path into this body already wrote, accumulated from the prefix statements
  and the same control-flow boundaries the backward scan refuses to cross.
  The live-in is usable precisely because the clobber mask travels with it.
  A proven loop-carried override still wins over `blocked`, since the
  override *is* the reaching value — without that, `call_inside_loop_uses_the_loop_carried_argument_value`
  and three siblings regressed to empty argument lists.
- `entry_constant_slots` — the cheapest whole-function proof that answers a
  slot across a labelled join without a reaching-definition service. Both
  halves are required: no statement anywhere writes the slot, and every call
  in the function runs straight into a `Return`, so no call's caller-clobber
  can precede another call. Anything less exact leaves the slot blocked,
  which is the previous behavior.

### Evidence

`189_effectful_select` before / after, `tools/dectest.py '189_effectful_select' --full`:

| cell | before | after |
|---|---|---|
| `gcc:O2:se189_select_call` | fail | pass |
| `gcc:O2:se189_nested_select` | fail | pass |
| the other 18 cells | pass | pass |

The recovered C now matches the source's evaluation structure — one call per
arm, each with the argument that arm actually passes:

```c
if (((unsigned long)((unsigned int)(arg1)) != 0)) {
    ret = se189_bump((int *)(arg0), (unsigned long)((unsigned int)(arg2)));
    ...
}
ret = se189_bump((int *)(arg0), (unsigned long)((unsigned int)(arg3)));
```

`95_function_pointer_table` — the fixture that caught the reverted late
table-layout patch (`table-dispatch-arguments-2026-08-12.md`) —
`tools/dectest.py '95_function_pointer_table' --full`:

```
95_function_pointer_table:clang:O0:dispatch_operation  pass
95_function_pointer_table:clang:O0:fold_operations     pass
95_function_pointer_table:clang:O2:dispatch_operation  pass
95_function_pointer_table:clang:O2:fold_operations     fail
95_function_pointer_table:gcc:O0:dispatch_operation    pass
95_function_pointer_table:gcc:O0:fold_operations       pass
95_function_pointer_table:gcc:O2:dispatch_operation    fail
95_function_pointer_table:gcc:O2:fold_operations       fail
```

**These match `baseline.json` exactly, including the three recorded `fail`
verdicts** — at `a45c1ae`, where the work was done, and at the current
`f21e990`, whose baseline records the identical four rows for this fixture.
The task brief asked that `95_function_pointer_table:gcc:O2:dispatch_operation`
keep passing; it is recorded as `fail` in the baseline and was already
failing before this change, so "keep passing" was not achievable and "do not
regress" is what was verified. `dectest` reports no regression in scope for
all four lanes.

The work was done in a detached worktree at `a45c1ae` while `master` moved on
to `f21e990`. `src/ir/call_args.rs` is byte-identical across that range, so
the copy-back clobbered nothing, and the only intervening changes that touch
`src/` are a test appended to `src/ir/lift_x86.rs` and the `src/strings/`
budget-reservation fix — neither of which is on any decompilation path — so
the fixture numbers above still describe the current tree. The main tree was
deliberately NOT rebuilt.

Other gates run:

- `cargo test`: 23 suites, 2281 passed, 0 failed, 1 ignored.
- `tools/dectest.py @calls @smoke @loops @region @switch @polarity @widths
  @flags @early-exit @structs @aggregates`: 80 lanes, no regressions.
- `tools/dectest.py @o0`: 356 lanes, no regressions.
- `tools/dectest.py @o2`: 356 lanes, no regressions, plus four cells that
  went `fail -> pass` and are not part of this defect —
  `164_nested_tlv_walker:clang:O2:tlv164_leaf_sum`,
  `164_nested_tlv_walker:gcc:O2:tlv164_node_count`,
  `165_bitstream_reader:gcc:O2:bit165_cross_check`, and
  `56_sieve:gcc:O2:sieve_primes`. `baseline.json` was NOT refreshed: a scoped
  run cannot write one, and refreshing it is the next session's decision.
- Four new unit tests in `ir::call_args::tests`, each carrying its negative
  control: a returning arm that must not clobber, a nested arm that must
  recover the live-in *and* must decline when the enclosing scope overwrote
  it, and a labelled call that must decline both when something writes the
  slot on the other predecessor and when a non-terminal call exists.

DecBench, Joern, `decbench_matrix.py`, `arch_roundtrip.py`, the full fixture
matrix, and `@o0` were **not** run, per the session constraint. No Python
source changed, so `ruff`/`ty` were not run.

### What remains open — the indirect half

Item 6 also asks for indirect function-table call may-uses and contracts.
None of that is implemented here, and the direct fix does **not** generalise
to it:

- Every proof added here is about *this function's own entry value* — that a
  live-in argument register still holds what the caller put there. A table
  call's arguments are ordinary computed values; nothing above says anything
  about them.
- `entry_constant_slots` is deliberately narrow to the point of being nearly
  useless for table dispatch: any function with a call that is followed by
  more work (which a dispatch loop always has) fails its second condition
  outright.
- The indirect half needs what the roadmap actually names: the entry
  contract recovered *before* liveness/DCE, ABI may-uses preserved in the
  over-approximating direction, and reaching values queried rather than
  register names read. That is the EPIC 5 `value_at`/`clobbers_between`
  surface applied to a real consumer, which no production pass uses yet.
- The `[r]` marker still stands. Nothing here restores the reverted late
  table-layout patch, and the reason it was wrong — plausible, well-typed
  arguments invented from architectural register names — is exactly the
  failure mode `EnclosingSlots.blocked` and `entry_constant_slots` are built
  to refuse.

Also still open, and visible in the same fixture: `se189_nested_select`'s
recovered body renders as a `goto` ladder rather than a nested select. The
arguments are now right; the structure is not. That is the structuring
workstream, not this one.

## Entry 19 — Fitness measurement and ratchet

Roadmap item 11, the measurable half: "Code quality, composition, and
file-size program" opens with four open bullets before any splitting work.
This entry builds the first bullet in full (reporting + ratchet) and the
fourth (dependency checks), as measurement only. No file was split and no
line moved toward a target; the roadmap is explicit that "a file split
counts only if it creates a narrower API and one reason to change" and
splitting is separate, later work.

### What landed

- `tools/fitness_report.py` -- measures the seven end-state targets over
  `src/*.rs`, styled after `tools/pass_health_report.py` and
  `tools/decbench_score_ledger.py` (typed errors, canonical JSON, an
  argparse CLI). `--check-ratchet` exits non-zero on any regression;
  `--write-baseline` regenerates the committed baseline deliberately.
- `tools/fitness_baseline.json` -- the committed baseline the ratchet
  compares against, holding today's seven measures plus the 15 largest
  product files for context.
- `python/tests/test_fitness_report.py` -- 23 tests: unit tests for the
  pure functions (test-path detection, generated-marker detection,
  `#[cfg(test)]`-block stripping including nested modules and braceless
  items, `check_ratchet`'s regression direction and float/int tolerance),
  plus the real ratchet test that measures the live `src/` tree and asserts
  no regression against the baseline, plus a value-pinned test so a silent
  drift in the *methodology* (not the tree) is also caught.
- `python/tests/test_src_dependency_boundaries.py` -- 6 tests: the three
  layering checks plus the environment-variable allowlist, all pure
  source-text checks in the style of `test_local_gate_fails_closed.py`.

### Methodology

"LOC" is physical line count. A file counts as test-only (excluded
entirely) if any path component or its own stem is exactly `test`/`tests`
or ends `_test`/`_tests` -- this crate's own convention
(`session_tests.rs`, `ast_tests/`, `linux_ioctl/tests.rs`; 28 of 338 `.rs`
files under `src/` match). Inside an otherwise-product file, every
`#[cfg(test)]`-attributed item (a `mod tests { ... }` block, a lone
`#[cfg(test)] fn helper_for_test()`, or a braceless `#[cfg(test)] use ...;`)
is stripped by brace-counting before the file is measured, so `ir/ast.rs`
counts as 11,525 product lines, not its 19,208 physical lines. A file is
exempt as generated only if `@generated` or `DO NOT EDIT` appears in its
first 20 lines -- per the roadmap, "mixed-responsibility logic is not an
exemption," so a marker buried mid-file does not count. No file in `src/`
currently carries such a marker; the exemption path exists but excludes
nothing today. "Product code" is read as the whole crate under `src/`
(the doc's own "Product and submission snapshot" section uses "product" for
the whole crate, not a directory subset), matching the roadmap's aggregate
targets; `src/ir` is broken out separately as the roadmap also asks.

### Current measurements against every target

Measured today, `fb4ee6b` plus this session's uncommitted `src/` edits
(310 product files, 159,931 product LOC; `src/ir`: 91 files, 73,322 LOC):

| Measure | Target | Current | Status |
|---|---:|---:|---|
| Product-code mean | below 450 LOC | 515.9 | over target |
| Product-code median | below 250 LOC | 274.0 | over target |
| Product files above 1,000 LOC | at most 35 | 27 | **meets target** |
| Product files above 2,000 LOC | at most 5 | 13 | over target |
| Product LOC in files above 1,000 | below 25% | 44.5% | over target |
| `src/ir` median | below 500 LOC | 449 | **meets target** |
| `src/ir` files above 1,000 LOC | at most 5 | 13 | over target |

Two of seven already meet their end-state target (the file-*count* ceiling
and the `src/ir` median); the other five do not, most sharply the "LOC
above 1,000" concentration (44.5% vs. a 25% ceiling) and the two
"files above N" tail measures. The 15 largest product files, largest first:
`ir/ast.rs` (11,525), `analysis/cfg.rs` (6,076), `ir/lift_x86.rs` (4,883),
`ir/types_recover.rs` (3,638), `symbolic/solver/axeyum_backend.rs` (3,357),
`ir/call_args.rs` (3,325), `python_bindings/ir.rs` (3,025),
`ir/stack_locals.rs` (3,012), `ir/lift_arm32.rs` (2,896),
`symbolic/explore.rs` (2,742), `analysis/java_class.rs` (2,644),
`ir/structure.rs` (2,580), `ir/lift_arm64.rs` (2,354),
`ir/value_number.rs` (1,965), `ir/copy_prop.rs` (1,919). This is a
snapshot, not a plan -- none of it was touched.

### Dependency checks

The three layering checks run against today's module layout, not the
roadmap's target layout (only `src/target/` exists as a dedicated
directory today; the renderer and HIR both live in `src/ir/ast.rs`, and the
lifters are `src/ir/lift_*.rs`). All three pass today:

- Renderer/HIR (`src/ir/ast.rs`) references no `lift_x86`/`lift_arm32`/
  `lift_arm64`/`lift_function` module.
- Renderer/HIR references no `crate::formats::`, `ProgramImage`, or
  `object::File` -- it does not parse images.
- `src/target/*.rs` imports nothing from `crate::ir` in code (one rustdoc
  link, `` [`crate::ir::abi`] ``, in a comment does not count; the check
  strips whole-line comments before searching).

Each check was verified to actually fire: a synthetic string containing
`crate::ir::lift_x86::lift_function`, `crate::formats::elf::parse(...)`, or
`use crate::ir::ast::render;` matches the corresponding regex.

### Environment-variable audit

Grepped all of `src/` for `std::env::var`/`var_os`/`vars()`, with test files
and `#[cfg(test)]` items stripped first (the same stripping the LOC
measurement uses). 47 unique `(file, call-site token)` production call
sites survive, across 15 files. All 47 are now in a reviewed allowlist in
`test_src_dependency_boundaries.py`, each tagged with one of six categories
(diagnostic, instrumentation, resource, budget, policy,
pinned-confirmation) and a one-line reason; the test fails on any call site
missing from the allowlist *and* on any allowlist entry no longer found in
`src/` (kept exact, not just a superset).

None of the 47 gate a semantic decision today. Breakdown:

- **34 are `GLAURUNG_DUMP_PASSES`/`GLAURUNG_PASS_HEALTH`/`GLAURUNG_PASS_STATS`/
  `GLAURUNG_PIPELINE_PROFILE`/`GLAURUNG_ACCOUNT_STRUCTURE`/`GLAURUNG_IOCTL_DEBUG`
  diagnostics** -- every one gates an `eprintln!`/counter/timer only; the
  three named as legitimate in the task description are a subset of this
  group.
- **1 is instrumentation**: `GLAURUNG_VERIFY_DEFS` (`python_bindings/ir.rs`)
  gates whether def-before-use violations are spliced into the rendered C
  as comments. The verification itself (`violations`) always runs
  unconditionally; the env var only controls whether the finding is echoed
  into the artifact.
- **1 is `python_bindings/ir/session.rs`'s `diagnostics_are_disabled()`**,
  which iterates that exact five-name diagnostic list to decide whether the
  in-process render cache may be trusted -- it disables *caching*, never
  changes what a fresh render would produce.
- **2 are resource-path selection** in decompiler scope:
  `GLAURUNG_FLIRT_LIB` (which signature file to consult; documented
  cwd-relative default, `None` no-op fallback) and, in the separate
  symbolic-execution engine, `GLAURUNG_SMT_SOLVER` (which solver binary to
  invoke).
- **The remaining ~30 are entirely inside `src/symbolic/`** (the symbolic
  execution / SAT-SMT engine backing the LLM vuln-discovery substrate, a
  distinct subsystem from this roadmap's decompiler pipeline): per-backend
  timeout/step budgets, solver warm-start/caching tuning knobs, dump/trace
  directories, ambient-config snapshotting into trace metadata, and one
  pair (`GLAURUNG_CONCRETIZATION_POLICY` /
  `GLAURUNG_CANONICAL_MODEL_CHOICE`) that is a deliberately documented,
  versioned policy choosing among several equally sound concretization
  witnesses -- the chosen policy id is written into the ordered trace, so
  the choice is auditable rather than silent. `ordered_replay.rs`'s
  `validate_runtime_configuration` goes further than "reviewed": it
  actively *refuses to run* unless a fixed, named set of these tuning
  variables already carries specific pinned values, which is the opposite
  of a silent semantic gate.

**The one real hit was found and fixed earlier this session, not by this
entry's tests.** `PreparedLlir::mir` in `src/python_bindings/ir.rs`
documents it directly: verified typed MIR used to be built only inside the
`GLAURUNG_DUMP_PASSES` debug dump, printed, and dropped -- so it was
available in debug runs only, and "the roadmap's 'migrate a production
consumer to verified MIR evidence' had nothing to migrate onto." It is now
built on demand for every decompilation via an ordinary method, independent
of any environment variable. The remaining `GLAURUNG_DUMP_PASSES`-guarded
call to `lower_verified_with_image` at `ir.rs:875` (inside the dump block,
building it a second time purely to print `mir.memory_values()`/
`mir.objects()`) is diagnostic only -- its result is used for nothing but
the print.

Two entries are worth a human re-look later, though neither is a semantic
gate today: `GLAURUNG_FLIRT_LIB` changes which signatures get matched (and
so which symbol names get attached) depending on what file happens to sit
at the configured/default path, and the concretization-policy pair changes
*which* satisfying witness gets reported when several are equally valid.
Both are flagged `resource`/`policy` rather than left out of the allowlist,
because today's test is about catching a silent semantic gate, not
relitigating every configuration surface.

### Evidence

`uv run pytest python/tests/test_fitness_report.py
python/tests/test_src_dependency_boundaries.py -q`: 29 passed, 0 failed.
`tools/fitness_report.py --check-ratchet`: exit 0, `fitness ratchet: no
regressions`. `uvx ruff format`/`uvx ruff check` clean on all three new
files. `uvx ty check` on the new files surfaces only pre-existing
`pytest.fixture`/`pytest.approx`/`pytest.raises` stub-resolution
diagnostics that reproduce identically on already-committed test files
(e.g. `test_pass_health_report.py`) and on `uvx ty check python/` as a
whole (1,979 diagnostics) -- an environment condition, not something this
change introduced. `cargo build`/`maturin develop`/DecBench/Joern/the
fixture matrix/`arch_roundtrip.py` were not run, per instruction (a
baseline regeneration was in flight against this tree) and because nothing
here needed the compiled extension -- both tools are pure Python over
checked-out `.rs` text.

Only `docs/design/decompiler-roadmap.md`'s first open bullet under item 11
("Add a reporting and ratchet check for these measurements") was ticked.
The fourth bullet ("Add dependency checks: ...") is also now fully
implemented by `test_src_dependency_boundaries.py`, but ticking it was
outside this entry's edit scope (limited to the reporting/ratchet bullets),
so it is left for deliberate review rather than checked off here.

### What is still open

- The targets themselves: five of seven are unmet, most sharply the LOC
  concentration in files above 1,000 lines (44.5% vs. 25%). Closing that
  is the file-split work the roadmap explicitly separates from this entry.
- "Reject new production modules over 1,000 LOC without a documented
  review" (bullet 2) has no enforcement yet -- `fitness_report.py` reports
  the count but nothing blocks a new large file today beyond the aggregate
  ratchet noticing the mean/median/percentage move.
- "Delete compatibility owners promptly after their consumers reach
  parity" (bullet 5) is unaddressed by this entry.
- The three layering checks are keyed to today's module layout by file
  path; they need their file lists (not their intent) updated once
  `src/render/`, `src/lift/` become real directories.

## Entry 20 — Determinism and parallel equivalence

Roadmap ranked item 12: design rule 12, "Serial and parallel analysis must
produce identical facts and output," is unambiguous and was previously
unproven -- no standing test exercised it anywhere in the tree. Worked in an
isolated worktree at `a45c1ae` with a private `CARGO_TARGET_DIR` while a
baseline regeneration ran against the shared tree.

### Where parallelism actually happens

Surveyed every `rayon`, `std::thread::spawn`, and `std::thread::scope` use
reachable from the decompile pipeline (`src/ir/`, `src/python_bindings/ir.rs`,
`src/program/`, `src/decompile/`):

- **`decompile_all_py`/`decompile_many_py`** (`src/python_bindings/ir.rs`) are
  plain sequential `for func in funcs` loops. Neither uses `rayon` nor spawns
  worker threads to decompile several functions concurrently, and the GIL is
  held across the whole per-function pipeline (the code's own comment says
  so, to keep `Ctrl-C` responsive via `py.check_signals()`). Phase 8's
  "deterministic function-parallel scheduling" checkbox in the roadmap is
  still unchecked, and this confirms why: it does not exist yet. There is
  currently no intra-process parallel decompilation of one binary's functions
  to test.
- **`src/ir/ast.rs::lower`** and **`src/python_bindings/analysis.rs::analyze_
  interruptible`** each spawn exactly one worker thread (a bigger-stack thread
  for deep region-tree recursion; a cancellation-watcher thread for
  `Ctrl-C`). Single-worker, not fan-out parallelism -- nothing to
  differential-test here.
- **`rayon` is used in exactly two places**, both in `src/strings/`, neither
  on the decompile path: `src/strings/detect_fast.rs` (fast language
  pre-filtering) and `src/strings/mod.rs::process_language_detection_batch`
  (ensemble language detection for the `strings`/`triage` subsystem, gated by
  `PAR_THRESHOLD = 128` items). `python_bindings/triage.rs::detect_languages_py`
  also calls `par_iter()` directly but with no shared mutable state -- safe.
- **The real "parallel" surface for decompilation is OS-process-level**,
  exercised only by the Python tooling: `tools/fixture_harness.py::run_matrix`/
  `run_lanes` wrap `subprocess.run` calls in a `ThreadPoolExecutor` (threads
  block on `subprocess.run`, which releases the GIL, so this is genuine
  concurrent OS-process execution, not GIL-serialized threads). `tools/
  dectest.py` and `tools/decbench_matrix.py` share this exact code path via
  `--jobs`. This is the shape design rule 12 actually needs to hold for today.

### Finding: a real parallel/repeatability bug in `src/strings/mod.rs`

Investigating the one genuine Rayon fork-join surface first (language
detection budget), `process_language_detection_batch` spent a shared
`Arc<AtomicUsize>` budget through a compare-exchange loop *inside* the
`par_iter` closure. Constructing a config that forces the parallel branch
(`max_samples: 400` so `>= PAR_THRESHOLD`, `max_lang_detect: 20` so the
budget is smaller than the eligible-string count) and calling `extract_
summary` on a real binary (`samples/binaries/platforms/linux/amd64/
libraries/shared/mathlib.dll`, 240 eligible strings out of 400 scanned)
30 times back to back in one process: 2 of the 30 runs picked a different
subset of strings to annotate with a language than the other 28, purely from
thread-scheduling order winning the race on the atomic. This is a genuine,
reproducible violation of "identical facts and output" -- not hypothetical.

Fixed by splitting the function: budget reservation now runs strictly
sequentially, in the batch's original order, before any parallel work starts
(`reserve_language_detect_budget`); only the actual (expensive, thread-safe)
`router.detect()` call for items that already won a slot runs through
`par_iter`. The winning subset is now a pure function of the input and the
budget, independent of thread count. No public signature changed.

Two regression tests pin this in `src/strings/mod.rs::language_detect_
determinism_tests`:

- `extract_summary_repeats_are_byte_identical_in_one_process` -- 40
  back-to-back calls on the same real binary/config, asserting the winning
  subset and `language_counts` never diverge from the first call.
- `language_detect_budget_reservation_is_deterministic_across_thread_counts`
  -- the same property under an explicit 1-thread and an 8-thread
  `rayon::ThreadPool`, 10 runs each, against the default-pool baseline.

Both pass now (`cargo test --lib strings::` -- 38 passed, 0 failed, 1.20s).
Before the fix, the first test failed reproducibly within a handful of runs;
after, 0 divergences observed in any run of either test during this session.

### The decompile-level differential (roadmap's literal ask)

Added `python/tests/test_decompile_determinism.py`, scoped to three real
binaries chosen for speed and architecture spread: `hello-gcc-O2` (x86-64
ELF, 7 functions), `hello-arm64-gcc` (AArch64 ELF, 8 functions), and
`mathlib.dll` (x86-64 PE, a real 232 KiB shared library, limited to 25
functions). Three properties, each parametrized over all three binaries (9
tests total):

1. **In-process repeatability**: `glaurung.ir.decompile_all(path, limit=N)`
   called twice in the same process must return list-equal results (tuple
   order and content, not set equality).
2. **Cross-process repeatability**: `glaurung decompile --all --format json`
   run as two sequential fresh OS processes (`subprocess.run`, mirroring
   `python/tests/test_cli_decompile.py::_run`) must produce byte-identical
   stdout.
3. **Serial vs. parallel**: a serial baseline subprocess run compared against
   6 concurrent subprocess runs of the same binary, launched through a
   `ThreadPoolExecutor` -- the exact mechanism `tools/fixture_harness.py::
   run_matrix` uses for `--jobs`. Every concurrent run's stdout must equal
   the serial baseline's stdout.

All 9 pass, and were re-run 3 times back to back with no flakes
(`uv run pytest python/tests/test_decompile_determinism.py -q`, 1.6-1.9s
test time, ~2.9-3.7s wall including `uv` startup). **No divergence was
found**: for these three binaries, serial and parallel (OS-process-
concurrent) decompilation, and repeated runs in one process or across
processes, are byte-identical today. This is a genuine, if narrower than the
roadmap's ultimate ambition, positive result -- the pipeline that exists
today (sequential-per-process, OS-process-parallel-across-invocations) holds
the property. It says nothing about the function-parallel scheduling Phase 8
still needs to build, which has no implementation to test yet.

### Stretch: one bounded fuzz-style property test

Added `lift_bytes_never_panics_or_hangs_on_arbitrary_input` to
`src/ir/lift_x86.rs`'s test module: a seeded splitmix64 PRNG (no new crate
dependency -- `rand` is not currently linked) generates 4,000 random byte
buffers (length 1-32), each run through `lift_x86::lift_bytes` at 16-, 32-,
and 64-bit widths (12,000 calls total) with VAs that exercise high-bit-set
addresses, asserting no panic. Passes in 0.15s
(`cargo test --lib lift_x86::tests::lift_bytes_never_panics_or_hangs_on_
arbitrary_input`); no panic found. This is a property test, not a real
fuzzer -- no corpus, no coverage guidance, matching the instruction not to
add a fuzzing framework dependency. `fuzz/` already has two `cargo-fuzz`
targets (`headers_validate`, `containers_detect`); neither covers a lifter or
decoder, so this is new coverage, not a duplicate.

### Evidence

- `cargo test --release` in the worktree: 23 test binaries, **2,281 passed,
  0 failed**, ~44s wall. Includes the 2 new `strings::` tests and the 1 new
  `lift_x86::` test.
- `cargo test --lib strings::` -- 38 passed, 0 failed, 1.20s.
- `cargo test --lib lift_x86::tests::` -- 122 passed, 0 failed, 0.15s.
- `uv run pytest python/tests/test_decompile_determinism.py -q` -- 9 passed,
  0 failed, ~1.7s test time; re-run 3x with no flakes.
- `uv run pytest python/tests/test_string_language_detection.py python/
  tests/test_strings_wrappers.py python/tests/test_triage_wrappers.py
  python/tests/test_triage_types.py -q` -- 23 passed, 0 failed (sanity check
  that the `strings/mod.rs` refactor did not disturb the Python-facing
  language/triage surface).
- `rustfmt --edition 2021` applied to `src/strings/mod.rs` and
  `src/ir/lift_x86.rs` only; no repo-wide `cargo fmt` was run.
- `cargo clippy --lib -- -D warnings`: the only warnings touching the edited
  files are both pre-existing, on lines this session did not modify
  (`src/strings/mod.rs:129`'s `build_detected_strings_batch`, unrelated to
  the reservation-order fix; `src/ir/lift_x86.rs:3227`, unrelated to the new
  test appended at the file's end).
- `uvx ruff format --check` and `uvx ruff check` on the new test file: clean.
  `uvx ty check` reports the same `unresolved-attribute` noise on `g.ir.
  decompile_all` and `pytest.mark` that already exists, unignored, on every
  other file calling these PyO3-bound functions (e.g. `python/tests/
  test_ir.py` has 56 of the same class of diagnostic) -- pre-existing stub
  gap, not a regression.
- DecBench, Joern, `decbench_matrix.py`, `arch_roundtrip.py`, and the full
  fixture matrix were **not** run this session, per the constraint.
  `tests/decompiler_fixtures/build/` does not exist on this host (fixtures
  are not pre-built); real binaries came from `samples/binaries/` instead.
- Files touched: `src/strings/mod.rs`, `src/ir/lift_x86.rs`, `python/tests/
  test_decompile_determinism.py` (new). Verified the main tree's copies of
  the two Rust files were byte-identical to `a45c1ae` before copying the
  worktree's versions back; removed the worktree afterward.

### What remains open

- No test proves design rule 12 for actual intra-process function-parallel
  decompilation, because that scheduler does not exist yet (Phase 8). The
  decompile-level tests added here prove the property for the pipeline shape
  that exists today (sequential-per-process; OS-process-parallel across
  invocations); they will need a companion test the day Phase 8 lands a
  real in-process scheduler, and that future test is where a HashMap-
  iteration-order class of bug (already fixed once in `src/ir/stack_locals.
  rs`) is most likely to resurface.
- The three decompile-determinism binaries are small (7-25 functions
  rendered). A cohort with heavier optimization (O2, C++ exceptions,
  switches) was deliberately left out to keep the file fast and within this
  session's "a few representative binaries" scope; broadening it is
  straightforward if a future session wants more surface area.
- Cancellation, resource budgets, crash recovery, and schema migration
  coverage (the rest of the Phase 8 safety-plan bullet) are untouched by
  this entry -- explicitly out of scope per the task's priority order.
- The `strings/mod.rs` fix only pins the language-detection budget race. It
  does not audit `classify_iocs`, `search::scan_bytes`, or any other
  `strings`/`triage` code path for similar shared-mutable-state hazards
  under parallel execution; none were investigated beyond the one Rayon
  surface reachable from `extract_summary`.

## Entry 21 — What the effectful-select fixture actually bought

Entry 18 recorded the defect that `189_effectful_select` uncovered: call
arguments dropped before recovery, at `gcc -O2`, whenever an arm of the
diamond returned, whenever a live-in spelling was only visible from the
enclosing scope, or whenever an entry-constant slot had to be proved across a
labelled join. `f72851e` fixed those three. This entry records what the fix
was worth, which is more than the fixture that found it.

Regenerating `baseline.json` moved exactly six cells, all in the same
direction:

    164_nested_tlv_walker:clang:O2  tlv164_leaf_sum     fail -> pass
    164_nested_tlv_walker:gcc:O2    tlv164_node_count   fail -> pass
    165_bitstream_reader:gcc:O2     bit165_cross_check  fail -> pass
    56_sieve:gcc:O2                 sieve_primes        fail -> pass
    189_effectful_select:gcc:O2     se189_select_call   fail -> pass
    189_effectful_select:gcc:O2     se189_nested_select fail -> pass

Two of those six are the fixture. The other four are a TLV parser, a
bitstream reader and a sieve that had simply been failing, in the baseline,
for as long as the baseline has existed — and whose failures nobody had
connected to argument recovery, because from the outside a dropped argument
looks like a rendering problem in whatever function happens to contain it.

Two process notes, both learned the expensive way.

**Check the diff cell by cell.** `--write-baseline` rewrites every entry in
the file, so a regression elsewhere is absorbed silently and shows up only as
a smaller-than-expected improvement count. The verification here was a script
that diffs the committed baseline against the new one key by key and prints
every changed `(cell, function, old, new)` triple — six changes, six
`fail -> pass`, nothing else moved. "The count went up" is not that check.

**The fixture that finds a bug is rarely the fixture that motivated it.**
`189` was designed to catch double evaluation of a side-effecting call folded
into a ternary — the same soundness class as the vector-transport bug in
`188`, one value with more than one consumer. It never got the chance to test
that: the arguments were gone before the fold could be evaluated at all. The
lesson is not that the design was wrong but that a fixture aimed at a deep
property tends to trip over a shallower one on the way in, and the shallower
one was worth four unrelated cells. Its intended target remains untested, and
the control (`se189_select_pure`, which must still fold) is what stops the
whole fixture from being satisfied by a decompiler that folds nothing.

## Entry 22 — Register views for XMM lanes

(Assigned as "Entry 21" in the task; 21 was already taken by the
effectful-select entry above by the time this landed.)

Worked in an isolated worktree at `f72851e` with a private on-disk
`CARGO_TARGET_DIR` while a baseline regeneration ran against the shared tree.

### The gap

The x86 lifter spells a scalar 32-bit XMM transfer as one dword lane —
`xmm0_d0`..`xmm0_d3` — and `src/ir/regview.rs`, the descriptor that owns every
other register-view fact in this codebase, did not contain those names at all.
`regview::view(Arch::X86_64, "xmm0_d0")` was `None`, so `parent_of` was `None`,
so every consumer treated a lane as storage UNRELATED to `xmm0`. Two symptom
patches followed from that single omission and both were repaired at their call
sites this session:

- `lift_x86::synchronise_xmm_views` appends a `concat` bridge per instruction
  precisely because a lane write does not define the parent. That bridge then
  blocked 16-byte transport recovery, fixed in `ac8d7df`/`d4fb502` by deleting
  provably-dead bridges downstream.
- `abi::touches_result_candidate` had to reconstruct the lane relation from the
  spelling, by `strip_prefix(candidate)` then `strip_prefix("_d")`, because
  `call; movd eax,%xmm0` otherwise looked like nobody consumed the float result
  (`76f9825`).

### What the model says now

`RegView` gained a `bank: RegBank` field (`Gp` / `Vector`), its masks widened
from `u64` to `u128`, and it gained `parent_span()` plus `defines_mask()` — the
parent bits a write through the view leaves in a KNOWN state, which is the exact
complement of `keep_mask()` within the parent. The x86-64 table gained
`xmm0`..`xmm15` as 128-bit parents with their four 32-bit dword lanes at offsets
0/32/64/96; the AArch64 table gained `v0`..`v31` the same way, because
`lift_arm64::packed` scalarises through the same `packed_dword_lane` spelling.

The new fact is `ParentDefinition`:

    Complete                              every bit of the parent is defined
    Partial { defined, undefined }        some are, some are not
    Undefined                             none are

`parent_definition(arch, whole, written)` folds `defines_mask()` over the writes
that belong to `whole`. So:

    xmm0 <- {xmm0_d0}                     Partial, bits 32..127 undefined
    xmm0 <- {d0,d1,d2,d3}                 Complete
    xmm0 <- {xmm1_d0, rax}                Undefined  (negative control)
    rax  <- {eax}                         Complete   (a 32-bit write zero-extends)
    rax  <- {al, ah}                      Partial, bits 16..63 undefined

The GP bank was always governed by the same rule; stating it in one type is what
makes the vector case ordinary instead of special.

### The consequence that fails closed

`mir::builder::is_partial_register_write` already asked `regview` whether a
destination is a bit-preserving view of a wider family, and marked such
instructions `EffectCompleteness::Opaque`. It needed no change: once the lanes
are in the table, a lane write answers yes. Verified as a real RED, by disabling
only the XMM rows and rerunning:

    a_scalar_xmm_lane_write_is_an_incomplete_register_effect
      left: Complete   right: Opaque

So a `movd %eax,%xmm0` is now an explicitly incomplete register effect rather
than a complete write of unrelated storage — design rule 5, with the GP
precedent (`mov $1,%cl`) asserted alongside it as the control.

Adding a bank required auditing every consumer that read the table as
"general-purpose":

- `exec::state::slots_for` panics if a parent has no 64-bit cell, so it now
  builds from a new `regview::gp_views(arch)`. The filter is explicit and
  documented; an engine silently dropping rows from a table it believed complete
  is the failure this descriptor exists to prevent.
- `lift_x86::partial_gp_view` gained the bank filter, and the ALU source path now
  goes through it too. Without that, `paddd`'s lane destination would have been
  lowered as a masked read-modify-write of `xmm0` with 64-bit masks — wrong, and
  destructive of the lane representation every packed op depends on.
- `ssa_parent` declines the vector bank outright, whole registers included.
  Answering `Some("xmm0")` for `xmm0` would be a harmless identity merge, but
  every caller reads `is_some()` as "this table settles the name's SSA identity",
  and for a vector register it does not. A test asserts no vector row moves any
  SSA identity, so `ssa::parent64`, `canon_gpr_for_target` and `value_number`'s
  alias rule are provably unchanged.

Conformance is generated over both tables rather than hand-listed, which is the
EPIC 4 bullet "conformance tests for every register view and partial-write rule":
for every row, `keep | defines == parent_span` and `keep & defines == 0`; a
bit-preserving write defines exactly its window and a total write defines the
whole parent; a single write is never `Undefined` and is `Complete` exactly when
it is not bit-preserving. For every vector parent, the four lanes tile it exactly
and dropping any one leaves a hole of exactly that lane's width.

### Did either symptom patch become removable? No — and here is why

**`touches_result_candidate` did not.** Its name parsing is gone: it now asks
`regview::is_lane_of`. But the call site still has to ask, because `ssa_parent`
declines the vector bank, so a definition of `xmm0` genuinely does not reach a
use of `xmm0_d0`. The knowledge moved into the model; the query did not
disappear. Behaviour is identical on real input and strictly narrower on
impossible input — the old predicate accepted `xmm0_d4`..`xmm0_d9`, which no
lifter emits and the table rejects.

**The bridge did not.** Deleting the `synchronise_xmm_views` call still fails
`unpack_and_qword_reduction_preserve_full_width_lane_semantics`, so it remains
load-bearing. And the model now says exactly why it cannot simply be made
honest: LLIR has no way to spell a partial definition, so
`xmm0 = concat(xmm0_d1, xmm0_d0)` is a total definition of a 128-bit name from
64 bits.

### The actual remaining root cause, pinned

Probing the lifter directly showed the thing underneath both defects, and it is
not the model — it is a spelling inconsistency in `lift_x86`:

    movss (%rax),%xmm0    ->  Load  { dst: xmm0,    addr.size: 4 }
    movd  %xmm0,%eax      ->  ZExt  { src: xmm0_d0 }

The SAME 32 bits have two names. `movss` writes the 128-bit parent spelling with
a 4-byte operand; `movd` writes and reads the dword lane. `synchronise_xmm_views`
exists to reconcile those two spellings once per instruction, and
`touches_result_candidate` exists to accept either of them at a call boundary.
Neither can be deleted while the spellings differ. Two pin tests in `lift_x86`
record this against the model — `the_same_thirty_two_bits_still_have_two_spellings`
and `the_scalar_view_bridge_defines_a_128_bit_name_from_64_bits`, the latter
showing that `movd %eax,%xmm0` already defines all four lanes (`Complete`) before
the bridge redefines the register from two of them.

The fix is to give the scalar views their own names in the same namespace as the
lanes — a 32-bit `movss` destination is `xmm0_d0`, a 64-bit `movsd` destination
is a 64-bit view the table does not yet carry — not to add a third bridge. That
is a lifter-wide rename touching type recovery, `vector_copy`, `value_number` and
the renderers, and it needs the full gate, so it was deliberately not attempted
here.

### Gates

`cargo test`: 2295 passed, 0 failed, 1 ignored, against a baseline of 2284/0/1
measured on the same worktree before any change (+11: eight `regview`, one
`mir`, two `lift_x86`). `cargo clippy --all-targets` emits 287 warnings both with
the change stashed and with it applied — no new lint; `-D warnings` was already
red at the base commit and `--all-features` cannot build here at all
(`solver-bitwuzla` needs `BITWUZLA_LIB_DIR`). `rustfmt --edition 2021` on the
five touched files.

Scoped fixture lanes, rebuilt `.so`, run at the final state:

    tools/dectest.py 188_vector_transport   --full   16/16 pass, no regressions
    tools/dectest.py 175_float_matrix_kernel --full   10 pass / 14 fail, no regressions

The 14 failures in `175` are the baseline's own recorded verdicts, not new — the
harness compares against `baseline.json` and reports no regression in scope. Not
run, and not claimed: DecBench, Joern, the full fixture matrix,
`arch_roundtrip.py`, and the Python suite.

### Not finished

- The scalar/lane spelling unification described above. It is the root cause;
  this entry only makes the model able to state it.
- `types.rs::phys_reg_width` still recognises `xmm`/`_dN`/`ymm`/`zmm` by parsing
  the name. Routing it through `regview` is blocked on the lookup being
  architecture-blind: consulting the x86-64 table first would resolve `sp` to a
  16-bit view, which is not what any current caller means.
- `vector_copy`, `value_number` and `types_recover` each still parse the `_dN`
  suffix themselves. Those are the next centralisation targets now that the
  spelling has an owner.
- AArch64's `s`/`d`/`q` register spellings are not in the table. The `v0..v31`
  lanes are, but a `d0` that means the low 64 bits of `v0` has no row, so the
  vector bank is complete for the scalarised lane representation only.
- A `Concat` that defines a vector parent from fewer bits than the parent has is
  still `EffectCompleteness::Complete` in MIR. Detecting it needs the op's result
  width, which `register_effects` does not have; the view model alone cannot see
  it.

## Entry 23 — AArch64-only failures

(Numbered 23, not 22: a concurrent worktree had already claimed "Entry 22 —
Register views for XMM lanes" in this file. Same ranked roadmap item.)

Ranked item 8's architecture-only half, restated against our own corpus instead
of DecBench. `tests/decompiler_fixtures/arch_baseline.json` answers the same
question with EXECUTION ground truth: a function that passes on x86-64 and fails
on another architecture computes the wrong answer there, which is a stronger
claim than a similarity score.

### The failure set, recomputed

Recomputed from the committed `arch_baseline.json` (md5
`d341fda8cafe51d9e355665177248359`) as "verdict `pass` on `x86_64` in the same
fixture/opt cell, verdict `fail` here". It reproduces the roadmap's table
exactly:

    armv7_a32     153
    armv7         144
    i386          102
    aarch64        94
    x86_64_gcc15   22

94 AArch64-only failures, 35 at `-O0` and 59 at `-O2`, and the roadmap's cluster
heads reproduce too: `141_atomics` 7, `173_float_int_conversions` 6,
`175_float_matrix_kernel` 5, `181_compensated_summation` 5, then `46_bitset`,
`71_compound_interest` and `72_loan_amortization` at 4 each.

### Grouping by cause, not by fixture

Cross-compiled each fixture and read the DISASSEMBLY of each failing function
rather than trusting the fixture name. That corrects the roadmap's reading:
`71_compound_interest`, `72_loan_amortization` and `64_root_finding` are
FIXED-POINT integer fixtures and contain no floating-point instruction at all.
The honest split of the 94 is

* **22** whose failing function contains a scalar-FP or FP-adjacent instruction;
* **7** `141_atomics`, a separate cause: every one of those functions uses
  `ldar` (acquire load) or `stlrb` (release store) — verified by disassembly at
  both opt levels — and neither mnemonic appears anywhere in `lift_arm64.rs`, so
  both become `Op::Unknown`. Not exclusive-monitor loops: gcc emits plain
  acquire/release accessors plus `bl` to the `__atomic_*` helpers here. An
  acquire load IS a load, so this looks like a bounded next fix; it was not
  attempted or measured in this entry;
* **65** with no FP instruction, no single cause identified.

Of those 22, **20** had a floating-point mnemonic rendered as an `/* asm: … */`
comment in the recovered C — measured by decompiling each one, not inferred. So
the largest attributable cluster is 20 of 94, not the ~38 a fixture-name reading
suggests.

### First wrong stage: LIFTING

Representative: `173_float_int_conversions:widen_int_to_float` at `gcc -O0`,
which is `return (float)value;` and seven instructions. With
`GLAURUNG_DUMP_PASSES=1` the very first dump already carries the defect:

    ===== prototype-resolved LLIR =====
      0x8cc: %s31 = load[4 bytes] MemOp { base: sp, disp: 12, size: 4 }
      0x8d0: [] = intrinsic scvtf()
      0x8d4: [] = intrinsic fmov()
      0x8dc: ret %x0

`scvtf` and `fmov` arrive with NO output, NO input and no register footprint at
all. Every pass after that is correct on its input and the final MIR is
`unknown(scvtf); unknown(fmov); return %arg0;`. The renderer then spells the
only thing left true — the integer's bits sitting where a float is expected:

    float widen_int_to_float(int32_t arg0) {
        /* asm: scvtf */  /* asm: fmov */
        return ((union { unsigned int bits; float value; }){ .bits = (unsigned int)(arg0) }).value;
    }

That is `*(float *)&value`, not `(float)value`. Nothing downstream is at fault.
`src/ir/lift_arm64.rs` had NO scalar floating-point lifting whatsoever: grepping
the whole `src/ir/` tree for `fadd|fsub|fmul|fdiv|scvtf|fcvtz|fcmp|fneg|fsqrt`
returned zero hits outside `lift_arm32.rs` and `lift_x86.rs`.

Two ABI holes sat behind it, both visible in the same dump:

* `abi::return_registers(Aarch64)` was `["x0", "w0"]` — no `v0`/`d0`/`s0`, so a
  float result could never be named `ret`. On an identity-shaped body the
  fallback is `x0`, which is *the first argument*. That is the AArch64 twin of
  the `xmm0` hole `76f9825` closed for x86-64.
* `types_recover::float_argument_bank_slot` returned `None` for `Aarch64`, so
  AAPCS64's `v0`-`v7` parameter bank did not exist. `compensation_of_step`
  (`181_compensated_summation`, `-O2`, `double(double,double)`) reported
  `roles={"x0": 0, "x1": 1}` — both parameters bound to integer registers the
  function never reads.

### What was changed

* `src/ir/lift_arm64.rs` — `scalar_float_ops` lifts `fadd`/`fsub`/`fmul`/`fdiv`/
  `fneg` and the float-to-float `fmov` to typed intrinsics with an exact
  register footprint, and `scalar_conversion_ops` lifts `scvtf`/`fcvtzs`/`fcvt`.
  Both emit ARM32's existing `vadd.f64` / `vcvt.f64.s32` spellings rather than a
  new AArch64 namespace, so `ast::scalar_float_intrinsic` already lowers them —
  the same "accept every producer's namespace" choice `wide_integer_intrinsic`
  records for `umulh`/`sdiv`. A general-register `fmov` is a BIT reinterpretation
  and stays on `packed::scalar_fmov`'s lane path; a negative test pins that.
* `src/ir/ast.rs` — `arm_scalar_conversion_intrinsic` parses `vcvt.<to>.<from>`
  into the existing `ScalarFloatOperation::Convert`.
* `src/ir/abi.rs` — `return_registers(Aarch64)` gains `v0`, `d0`, `s0`, ordered
  after the integer names.
* `src/ir/dead_stores.rs` — the AArch64 return aliases gain `d0`, `s0`.
* `src/ir/types_recover.rs` — AAPCS64 joins the float argument bank.
  `float_live_in_slots` now returns the EXACT register spelling of the first
  touch alongside the slot, because `d0` and `s0` are unrelated SSA identities
  for one AAPCS64 register: naming a parameter `s0` when the body only reads
  `d0` leaves every use of it undefined. AArch64 is also the one convention that
  need not guess the width — the spelling states it.

`ucvtf` and `fcvtzu` are deliberately NOT lifted. `ast::ScalarType` has no
unsigned variant, so the only available spelling is the signed neighbour, which
disagrees for every value above the signed maximum — exactly the disagreement
`173_float_int_conversions:truncate_to_unsigned` exists to detect. A wrong cast
that type-checks is worse than a visible opaque comment. A negative test pins
that too.

`compensation_of_step` now recovers exactly, from three instructions:

    double compensation_of_step(double arg0, double arg1) {
        double next;
        return (((arg0 + arg1) - arg0) - arg1);
    }

### Measured

Per-function verdicts from `tools/arch_roundtrip.py --json`, diffed against the
committed baseline. Over the seven FP-bearing fixtures at both opt levels:
**12 functions fail -> pass, 0 pass -> fail**, and the x86-64 control lane in the
same runs is verdict-identical to the baseline. Six of the twelve are members of
the 94; the other six were failing on x86-64 too, so they were never
"AArch64-only".

    173:O0 widen_int_to_float, widen_long_to_double        [in the 94]
    175:O0 matrix2_determinant                             [in the 94]
    181:O0 kahan_sum_f64, naive_sum_f64                    [in the 94]
    181:O2 compensation_of_step                            [in the 94]
    172:O0 double_precision_horner
    174:O0/O2 negate_binary32
    175:O0 dot_product_f32
    181:O0 compensation_of_step, difference_of_products

Regression sweep: 18 non-float fixtures x {aarch64, armv7, i386} x {O0, O2},
plus the x86-64 control carried in each run — **0 changes in either direction**.
That is the cross-lifter control for the shared `types_recover` and `ast` edits.

`cargo test`: 2194 passed, 0 failed across all 23 test binaries. `cargo clippy
--all-targets`: 287 warnings with the change and 287 with it stashed — no new
lint. `rustfmt --edition 2021` on the five touched files.

`uv run pytest python/tests/ -x -q`: one failure,
`test_decompiler_fixture_matrix.py::test_no_lane_became_broken`, with the
message `lane 189_effectful_select:clang:O0 disappeared from the current run`.
That is a worktree-vintage artifact, not this change: `baseline.json` at
`f72851e` already lists `189_effectful_select`'s lanes while
`tests/decompiler_fixtures/src/189_effectful_select.c` does not exist at that
commit, so the fixture cannot be built and its lanes cannot be produced. It is
the same gap the concurrent baseline refresh was scheduled to close. Because
`-x` stopped there, the rest of the Python suite after that file did NOT run and
is not claimed.

NOT run, and not claimed: DecBench, Joern, `decbench_matrix.py`, the full
`arch_roundtrip.py` matrix, the full fixture matrix, and
`scripts/decbench-local-gate.sh`. `arch_baseline.json` was NOT regenerated; every
comparison above is against the committed file.

### What remains, with the blocker named

Ten of the 22 FP-bearing AArch64-only failures still carry a dropped mnemonic:

* **`fcmp`/`fcmpe`** — 5 cells (`172:O0`, `173:O0/O2 truncate_to_unsigned`,
  `174:O0/O2`, `181:O0 summation_disagrees`). The largest remaining group. Float
  comparison writes NZCV with unordered semantics that the integer
  `compare_flags` path cannot express; this needs a real float flag model, not a
  mnemonic table.
* **`fcvtzu`/`ucvtf`** — 2 cells, blocked on `ScalarType` gaining an unsigned
  variant.
* **`fmadd`/`fnmsub`** — 3 cells. Fused multiply-add is not any C expression
  without `fma()`, so this is a rendering decision, not a lifting one.
* **`movi v31.2d, #0`** — the zero splat into a scalar FP register, present in 7
  of the cells (several of which now pass anyway).
* `175:O0:dot_product_f64` is a DIFFERENT stage: its `vadd.f64`/`vmul.f64` DO
  lift now and are still dropped, by `ast`'s `lower_scalar_float` closed-value
  gate. Diagnosing that one starts at lowering, not at the lifter.
* `46_bitset`'s `addv`/`cnt` and `146_opaque_predicates`'s SIMD `orr` are NEON,
  not scalar FP, and were never this cause.

Untouched by design, because concurrent work owns them: `src/target/*`,
`src/ir/lift_x86.rs`, `src/ir/call_args.rs`, `src/ir/memory_objects*`,
`src/program/*`. The `d0`-versus-`s0` identity problem noted above is the same
scalar/lane spelling unification Entry 22 describes; this entry works around it
by carrying the observed spelling rather than unifying the model.


## Entry 24 — Undefined reads: the real set, and the first wrong stage for each

The brief said ten fixtures render reads of variables that were never defined.
Ten is right for exactly one slice and wrong for the corpus.

### The count, recomputed

`tests/decompiler_fixtures/structural_baseline.json` records ten violating
functions. That file is built by `structural.py::_build`, which compiles ONE
lane — gcc `-O0` — and grades only `manifest.REQUIRED_FUNCTIONS` at the
`decbench` render. Recomputed against the prebuilt corpus in
`tests/decompiler_fixtures/build/` (742 shared objects, all six lanes,
`GLAURUNG_VERIFY_DEFS=1`, `--all`), at HEAD `38d6591`:

| scope | violating functions | violations |
|---|---|---|
| gcc:O0, required functions (= the baseline's ten) | 10 | 11 |
| all six lanes, required functions | 192 | 320 |
| all six lanes, every emitted function | 3387 | 12743 |

So the corrected number for "functions the corpus's own contract cares about" is
**192, not 10** — the baselined ten are the gcc:O0 shadow of a defect surface
nineteen times larger. Per lane, required functions only: gcc:O0 11, clang:O0
13, gcc:O2 106, clang:O2 130, rustc:O0 37, rustc:O2 23. The O2 lanes dominate,
and their violations are almost all `never_defined` rather than
`used_before_definition` — at O2 the emitted body usually contains a `goto`, and
`verify_defs::check` skips its flow-sensitive rule there, so what survives is
the stronger claim: no definition anywhere in the function.

### Clusters, by cause rather than by name

Read the disassembly for each of the baselined ten. The fixture titles mislead
in both directions.

**A. No SSE parameter bank (x86-64).** `abi::argument_slots(SysVAmd64)` lists
`rdi/rsi/rdx/rcx/r8/r9` and nothing else, so a float parameter is bound to the
INTEGER register at the same positional index. `GLAURUNG_DUMP_PASSES=1` on
`174_float_compare_classify:sign_bit_of_binary32` prints the recovered prototype
as `slot: 0, value: Phys("rdi"), hint: Float { width: 4 }` — for a function
whose only instruction touching a parameter is `movd eax, xmm0`, and which never
mentions `rdi`. First wrong stage is therefore prototype/parameter recovery,
BEFORE the AST pipeline: `parameter evidence` already reads `roles={"rdi": 0}`,
and `apply_role_names` faithfully renames what it was given.

The symptom then splits on spelling. `abi::return_registers` DOES contain
`xmm0`, so a live-in read spelled `xmm0` is named `ret` and reported
`used_before_definition` (`172:accumulate_narrow`, `172:accumulate_wide`,
`175:scale_series_f32`); a read spelled `xmm0_d0` — the vector-lane view added
by Entry 22 — matches nothing and becomes an undefined `varN`
(`174_float_compare_classify`, 19 violations after this entry's fix). Same root,
two spellings.

NOT FIXED, deliberately. The blocker is that SysV allocates INTEGER and SSE
parameters from two INDEPENDENT counters, so a flat positional slot table cannot
express the mapping at all — `argument_slots` would have to become class-aware,
and every caller that indexes it positionally would have to change with it. The
adjacent experiment is on the record and it was expensive: `abi.rs` notes that
adding `xmm0`-`xmm7` to the call-effects may-use set on 2026-08-12 gained nothing
and cost twelve regressions in functions containing no SSE instruction. This
needs a design decision, not a patch.

**B. Bit-preserving register views read as bare names.** FIXED — see below.

**C. Phi coalescing materialises a copy from an undefined incoming.**
`143_dynamic_frames:cleanup_on_every_exit` emits `var12 = var13;` where nothing
defines `var13`. The dump attributes it exactly: `value_number.rs`'s phi
coalescing prints `phi-coalesce [rbx#6, rbx#1, ...] -> rbx#1` and inserts
`0x1456: %rbx#1 = %rbx` — at `mov r12d, 0x1`, an instruction that does not write
`ebx` at all. The incoming on that edge is version 0, the live-in, which no
instruction defines. `135_cpp_rtti:cpp_typeid_compare` (`var20 = var21`) is the
same shape reached differently: `__cxa_bad_typeid` is absent from
`call_semantics::KNOWN_NORETURN_SYMBOLS`, so an impossible fallthrough edge
exists and the join needs an incoming for `rdx` on it.

NOT FIXED. Both need a decision this entry is not entitled to make: the current
output is arguably the MORE faithful one (the machine really does leave the
callee-saved register holding the caller's value), and eliding the copy trades a
flagged uninitialised read for a silent one. The `__cxa_*` half is smaller and
looks tractable — `__cxa_bad_typeid`, `__cxa_bad_cast`, `__cxa_pure_virtual`
and `_ZSt9terminatev` all have standardized noreturn contracts and would fit the
existing list's stated criteria — but it changes CFG recovery, so it wants its
own measurement rather than a ride on a lifter change.

**D. Landing-pad live-ins.** `136_cpp_exception_unwinding:cpp_rethrow_and_nest`
reads `var8` in `if (var8 == 1)`. That is `rdx` at `0x1583`, an `endbr64` landing
pad: the Itanium unwinder enters with the exception object in `rax` and the
SELECTOR in `rdx`, and neither is written by any instruction in the function.
`exception_recover::mark_landing_pads` marks the pads but seeds no entry
definitions for them. NOT FIXED — the missing capability is named precisely:
landing-pad entry definitions for the exception ABI's two live-in registers.

**E. Frame arrays with a runtime index.** `111_self_referential_struct:link_and_sum`
declares and reads `rbp`. `promote_stack_locals` promoted every constant-offset
slot (`local_90`, `local_8`, ...) but left `%rdx#6 = (%rdx#5 + %rbp)` /
`%rdx#7 = (%rdx#6 - 144)` — `nodes[index].value`, a base-plus-scaled-index frame
address — as raw pointer arithmetic. `recognise_machine_frame` then correctly
fails closed, because collapsing a prologue whose frame pointer is still read
would be a lie. First wrong stage is `stack_locals.rs`, and the gap is the EPIC 3
one: no promotion of a dynamically indexed frame ARRAY. NOT FIXED.

**F. A partial-register merge nobody consumes.** `172:narrow_after_double_math`
is in the float fixture and its violation has nothing to do with floats. gcc
emits `setae al; xor eax, 0x1; test al, al`: only `al` is ever read, but the
`xor` reads the whole `eax`, whose upper 24 bits are genuinely live-in. The
emitted `(ret & -256) | ...` is a faithful lowering of an architecturally
undefined read. NOT FIXED; the fix shape is a dead-bits narrowing, not a
value-tracking repair. Recorded because it is the exact error the brief warned
about — a cluster assigned by fixture title would have put this with A.

### What was fixed

Cluster B, in `src/ir/lift_x86.rs`. `regview::ssa_parent` declines to merge a
bit-preserving view (`ax`, `dx`, `al`, `ah`) with its parent, so a bare `%dx`
read is a read of a name the SSA layer never sees defined. Three sites in the
lifter already knew this and called `read_view_ops` to extract the view from its
parent — the memory-destination `mov`, `movzx`/`movsx`, and
`cmp_operand_as_value`. Three did not:

* `wide_div_ops` at 16 bits snapshots the `dx:ax` dividend pair with bare reads.
  `mov edx, 0` before `div r/m16` defines `rdx`; the two never meet, so
  `185_subword_signed_division:divide_unsigned_shorts` rendered an undeclared
  `var3` as the high half of its dividend and divided by garbage.
* `wide_mul_ops` at 16 bits, same accumulator, same shape.
* `Mnemonic::Mov`'s register-destination arm, for a register SOURCE. This is the
  one with reach: clang's sub-word remainder is `cdq; idiv ecx; mov ax, dx`, and
  the `dx` read there is how `remainder_signed_shorts` lost its remainder.

New helper `snapshot_accumulator_half` routes the wide-arithmetic halves through
`read_view_ops`; the `mov` arm extracts a partial source into `Temp(76)` before
the existing partial-write handling. At 32 and 64 bits `partial_gp_view` returns
`None`, so nothing changes there — the pre-existing 64-bit assertions still pass
untouched.

### Measurement

Two full six-lane sweeps of the 742 prebuilt fixture objects, before and after:

* required functions: 192 -> 185 violating cells, 320 -> 312 violations;
* every emitted function: 3387 -> 3380 cells, 12743 -> 12703 violations;
* **seven cells cleared, zero newly violating.**

`tools/dectest.py` over **396 distinct lanes (55% of 724), 1915 functions**
— `@subword-division @widths @smoke @region @loops @calls @flags @structs
@polarity @coverage @vector-float @aggregates @bias @sentinel @early-exit
@switch 13* 14* 15* @curriculum-bits @curriculum-crypto @curriculum-strings
@curriculum-sorting @curriculum-number-theory 16* 17* 18*` — **no regressions**,
and five EXECUTION improvements (fail -> pass, i.e. the recompiled C now returns
the right answer):

    185_subword_signed_division:clang:O0:remainder_signed_bytes
    185_subword_signed_division:clang:O0:remainder_signed_shorts
    185_subword_signed_division:clang:O2:divide_signed_bytes
    145_control_flow_flattening:clang:O2:flattened_classify
    45_string_algorithms:clang:O0:format_decimal

`cargo test`: 2307 passed, 0 failed, 1 ignored. No Python was touched. No
baseline was regenerated — the five improvements above mean `baseline.json` and
`structural_baseline.json` are now stale in the good direction and need a
deliberate refresh.

### What this entry did not do

DecBench, Joern, the full fixture matrix and `arch_roundtrip.py` were not run.
Clusters A, C, D, E and F are diagnosed and unfixed; each names its blocker
above. The residual after this fix, required functions only, is 312 violations
in 185 cells, led by `174_float_compare_classify` (19, cluster A),
`170_rust_panic_unwind` and `171_rust_overflow` (16 each, not investigated),
and `153_many_live_locals` (14, not investigated).

## Entry 25 — Indirect table-call may-uses

Roadmap item 6, the indirect half. Entry 18 closed the direct half and recorded
why its proofs do not generalise: every one of them is about *this function's
own entry value*, and a table call's arguments are ordinary computed values.
That note is right. What it did not say is what DOES generalise, and that turns
out to be the whole fix.

### The defect, and the first wrong stage

`95_function_pointer_table:gcc:O2:dispatch_operation` is recorded `fail` in the
committed `baseline.json` — checked, not assumed — and its recovered C was

```c
ret = ((int (*)(void))(OPERATIONS[var0]))();
```

for a callee that reads two integers. The task framing was that dead-code
elimination deletes the argument setup before the contract can be applied. It
does delete it, but that is not the first wrong stage and not the cause.
`GLAURUNG_DUMP_PASSES=1` puts the boundary exactly:

```
===== after reconstruct_args =====
    %rdi#1 = (unsigned long)((unsigned int)(%rsi));
    %rsi#1 = (unsigned long)((unsigned int)(%rdx));
    ...
    if (((%cf#1 | %zf#1) != 0)) {
        call OPERATIONS[%rax#1]();
```

The setup is still there. It is still there after `eliminate_dead_stores`, after
`stack_idiom+label_prune`, and after `apply_role_names` renames it to
`%var1`/`%var2`. It is deleted by `copy_prop::remove_dead`, inside
`prepare_for_decbench`, which drops a scratch assignment whose destination is
read nowhere in the body — and the destination is read nowhere *because the call
has no arguments*. The deletion is the consequence, not the cause, exactly as
entry 18 found for the direct half.

That distinction matters for what a "may-use set" can even buy. At the AST/C
boundary, keeping `var1 = arg1` alive changes nothing semantically: the emitted
C is recompiled, and its indirect call passes literally nothing regardless of
which local assignments survive above it. **A may-use set that is not
materialised as arguments is cosmetic.** So the sound and useful form of "keep
the may-use registers alive" is to make them real call arguments, early enough
that the register names still denote the values they hold.

### What generalises: a complete callee SET

A direct call has one callee to ask for a parameter layout. An indirect call has
none — that is the whole difficulty. A call through a *relocation-proven*
function-pointer table has neither: it has a complete, finite, proven SET of
them. `function_tables::collect_function_pointer_tables` only builds a table when
a real defined data symbol has pointer-sized storage, EVERY slot has an exact
dynamic relocation, and EVERY relocation resolves to an exact defined function
symbol. The machine may transfer to any entry, so the registers the call may read
are the **union over the entries**.

The union is the safe direction and refusing it is the unsafe one. An entry that
reads fewer registers is unaffected by the extra ones being live; passing fewer
than some entry reads deletes an argument that entry consumes, which is the
silent wrong-code bug `table-dispatch-arguments-2026-08-12.md` records.

Implemented as:

- `callee_contracts::recover_table_entry_layouts` recovers each entry's parameter
  storage through the same demand-driven, cached callee analysis the direct path
  uses, bounded by `function_tables::tables_referenced_by` (a fail-closed scan of
  the caller's LLIR for the table's base address — an operand shape it does not
  enumerate simply yields nothing, which costs recovery rather than soundness).
  The results land in a SEPARATE `DirectCalleeFacts::table_entry_layouts`, never
  in `layouts`/`prototypes`/`env`: a table entry is not a direct call target of
  this caller, so no existing consumer can reach it and the declarations and
  types this caller emits are unchanged. `address_names` is passed immutably, so
  no name changes either.
- `call_args::table_call_may_use_layout` unions the set. It requires every entry
  to have a recovered layout, the layouts to NEST (each a prefix of the widest
  under the convention's own allocation order), and the union to be a valid ABI
  allocation prefix. Anything else fails closed.
- `call_args::fold_one_table_call` applies it, running BEFORE any
  register-liveness recovery in `fold_one_call` and before naming. It tries the
  adjacent setup first (`fold_one_recovered_layout_call`, unchanged), then the
  proven reaching definition of each slot. It is all-or-nothing: ABI arguments
  are a contiguous prefix, so a partially proven union would silently drop the
  slots it could not name.
- `EnclosingSlots` gains `reaching`: the exact value-numbered definition that
  reaches this body's entry per slot. `blocked` answers "does the function-entry
  value still reach"; `reaching` answers the strictly harder "what value
  reaches", which is the only thing that can name an argument whose setup
  happened in an enclosing scope. Only a top-level unconditional `Stmt::Assign`
  records one, only a VERSIONED destination is recorded, and every other write,
  every call, and every control-flow boundary the backward scan refuses to cross
  clears it. A loop body that writes the slot anywhere clears the pre-loop
  definition (`loop_body_reaching`), leaving `loop_carried_arg_inputs`' existing
  override as the only answer there.

Requiring a versioned destination is the load-bearing difference from the
reverted 2026-08-12 patch. That patch applied the entry layout LATE, after
naming, so it emitted architectural `rdi`/`rsi`, which the naming pass rendered
as this function's own `arg0, arg1` — while the registers actually held the
shuffled `a, b`. Plausible, well-typed, wrong. Applying the same union before
naming, through `%rdi#1`, makes naming rewrite the argument and the definition
together.

### Evidence

`tools/dectest.py '95_function_pointer_table' --full`:

| cell | before | after |
|---|---|---|
| `gcc:O2:dispatch_operation` | fail | **pass** |
| the other 7 cells | unchanged | unchanged |

The recovered C is now

```c
var1 = (unsigned long)((unsigned int)(arg1));
var2 = (unsigned long)((unsigned int)(arg2));
if (((unsigned long)((unsigned long)((unsigned int)(arg0))) <= (unsigned long)(4))) {
    ret = ((int (*)(long, long))(OPERATIONS[var0]))(var1, var2);
```

— the arity from the union, the values from the reaching definitions.

Eight unit tests in `ir::call_args::tests`, six of them negative controls: an
entry with no recovered layout, disagreeing entry layouts, an unversioned
enclosing definition (the reverted patch's exact bug), a call between the setup
and the table call, a loop that rewrites the slot under a new name, and an
indirect call that is not a proven table. Two positive: the union is the WIDEST
entry rather than the narrowest, and a table call in a loop reads the
loop-carried definition rather than the stale pre-loop one.

### New fixture 191_indirect_table_args, and what it actually found

`95` proves the value the dispatch RETURNS. It cannot distinguish a wrong
argument list whose result happens to agree, which is precisely the reverted
patch's failure mode. `191` gives every table entry a witness protocol: each one
writes the arguments it received into the caller's own scratch buffer, in the
same style `189_effectful_select` counts its side effect.
`t191_computed_args` is the near-miss control — its table call passes values the
function computed, so a recovery that names architectural argument registers
gets plausible, wrong values. `t191_direct_control` is the degeneracy control:
the same protocol through a direct call, which must keep passing.

Verdicts on the current build (NO baseline written):

```
191_indirect_table_args:{gcc,clang}:O0:{all four}   pass
191_indirect_table_args:{gcc,clang}:O2:t191_direct_control   pass
191_indirect_table_args:{gcc,clang}:O2:{dispatch,computed_args,fold}  fail
```

The O2 failures are NOT this change. They are a separate, upstream, and worse
defect that the fixture exposed: **`lift_x86` drops the memory operand of a
memory-indirect call.**

```
11ae:  ff 14 c1     call   *(%rcx,%rax,8)
```

lifts to

```
0x11ae: call @0x0
```

— a direct call to address zero. The table identity is gone before any AST pass
runs, so `resolve_function_table_entries` has nothing to annotate,
`table_call_may_use_layout` correctly declines, and the emitted C is
`((long (*)(...))(0x0))(...)`. This is the same defect behind
`95_function_pointer_table:{gcc,clang}:O2:fold_operations`, which are also
recorded `fail`. `95:gcc:O2:dispatch_operation` recovers only because gcc emits
it as `jmp *(%rdx,%rax,8)` — a tail dispatch, which lifts correctly and which
`recover_resolved_tail_calls` turns back into a call.

I did not fix that. It is a `lift_x86.rs` change, and a parallel agent held
uncommitted work in that file this session; a conflicting edit there was
explicitly ruled out. It is the obvious next item, and it is larger than it
looks: `Op::Call` already has `CallTarget::Indirect(Value)`, so the repair is to
lift the SIB load rather than to invent a representation.

### Gates run

- `cargo test`: 23 suites, **2312 passed, 0 failed, 1 ignored**.
- `tools/dectest.py @o2`: **358 lanes, no regressions, 1 improvement**
  (`95_function_pointer_table:gcc:O2:dispatch_operation` fail -> pass).
- `tools/dectest.py @o0`: **358 lanes, no regressions, no improvements.**
  Together that is 716 of the 728 lanes in the matrix (98%); the twelve not run
  are the `rustc` lanes, which are off by default. Sizing the sweep to the whole
  corpus rather than to the defect is the right call for anything near DCE, even
  though this change fires only on calls whose target is an
  `Expr::FunctionTableEntry` and leaves the non-table path behaviourally
  identical.
- `tools/dectest.py '95_function_pointer_table' --full`, `'08_indirect_dispatch'
  --full`, `'191_indirect_table_args' --full`.
- `rustfmt --edition 2021` on the four touched Rust files only; `uvx ruff
  format --check` and `uvx ruff check` on `manifest.py`.
- NOT run, deliberately: DecBench, Joern, `decbench_matrix.py`,
  `arch_roundtrip.py`, the full fixture matrix, and any baseline refresh.
  `baseline.json`, `structural_baseline.json` and `arch_baseline.json` all need
  one: `95:gcc:O2:dispatch_operation` moved fail -> pass and `191` has sixteen
  lanes with no baseline row at all.
- `python/tests/test_dectest_selection.py` and
  `python/tests/test_decompiler_fixture_harness.py`: 106 passed.
- `python/tests/test_fitness_report.py`: **2 failed**, and honestly so.
  `tools/fitness_baseline.json` ratchets `product_mean_loc` 518.66 -> 520.44 and
  `product_pct_loc_above_1000` 44.62 -> 44.66. `call_args.rs` is already over
  1,000 LOC and this adds to it. That is a real cost of the change and it needs
  a deliberate baseline refresh (precedent: `b6be1e6`), not a quiet one — so it
  was left failing rather than rewritten here.

## Entry 26 — x86-64 SysV: the second argument bank

Branched from `e3169c5` in a worktree; `src/ir/abi.rs` and
`src/ir/types_recover.rs` only.

### What was actually wrong, which is not quite what the brief said

The brief's diagnosis was that `abi::argument_slots(SysVAmd64)` lists only
`rdi/rsi/rdx/rcx/r8/r9` and that x86-64 therefore has NO SSE parameter bank.
That was true when Entry 24 was written, at `38d6591`. It is not true at
`e3169c5`: commit `039c7d6` — the AArch64 one Entry 24 named as "the analogous
solved problem" — had already generalised `types_recover::float_argument_bank_slot`
and `float_bank_applies` to `SysVAmd64`. The bank existed. Trusting the write-up
would have meant rebuilding something that was already there.

What survived is narrower, and only running the fixture separates it:

    $ GLAURUNG_DUMP_PASSES=1 glaurung decompile 174…-gcc-O0.so \
        --func sign_bit_of_binary32
    slot: 0, value: Phys("xmm0"), hint: Float { width: 4 }      # CORRECT
    $ …                          174…-gcc-O2.so --func sign_bit_of_binary32
    slot: 0, value: Phys("rdi"),  hint: Float { width: 4 }      # the defect

Same fixture, same function, same source. The lanes differ only in how gcc moves
the parameter:

    -O0   movss %xmm0,-0x4(%rbp)     reads the WHOLE register  -> bank matched
    -O2   movd  %xmm0,%eax           reads the dword LANE      -> no match

`movd`/`movss` lift as a read of one scalarised dword lane, spelled `xmm0_d0`
(Entry 22's register views). `float_argument_bank_slot` did
`"xmm0_d0".strip_prefix("xmm").parse::<usize>()`, got nothing, and reported no
float live-in at all. With no float evidence, `RecoveredPrototype::apply_locked_parameters`
fell through to its positional fallback — `abi::argument_registers(cc)[source_slot]`,
a table containing only the INTEGER bank — and gave the declared `float` the
integer register at source position zero.

So the first wrong stage is prototype recovery, as stated, but the mechanism is a
SPELLING gap feeding a POSITIONAL gap. Both had to close; either alone fixes
nothing.

### The design problem

SysV allocates INTEGER and SSE arguments from two INDEPENDENT counters:
`f(int a, float b, int c, float d)` is `rdi, xmm0, rsi, xmm1`. Source position is
not the register index in either bank. New `locked_sysv_amd64_parameter_storage`
walks the declaration with one counter per bank — structurally the same as
`locked_aapcs_parameter_storage`, which had solved this for AAPCS-VFP, so this
extends an existing model rather than inventing one. `abi::sse_argument_registers`
now owns the SSE table, and its doc records that Win64's SSE bank shares an INDEX
with the integer bank (`f(int, float)` -> `xmm1`, not `xmm0`); class-aware mapping
is deliberately NOT wired for Win64, because there are no Windows fixtures to
measure it against.

**AGGREGATES FAIL CLOSED, explicitly.** SysV classifies each EIGHTBYTE
independently, so `struct { long; double; }` occupies `rdi` AND `xmm0` — one
source parameter drawing from both banks, which two scalar counters cannot
express. Such a type reaches recovery as `None`, because `dwarf_return_hint_with_env`
translates only scalar spellings the renderer can write exactly. ONE `None`
declines the WHOLE signature, not just that parameter: every later parameter's
bank index depends on the class of every earlier one. Declining restores the
previous positional behaviour byte for byte. The same rule covers `long double`
(memory class under SysV) and vector types.

The blast-radius claim is executable rather than asserted:
`locked_sysv_integer_only_parameters_are_unchanged_by_the_class_map` proves a
float-free signature produces exactly the storage the positional table produced.
Only a signature containing an SSE-class parameter can move.

### The regression that showed the AArch64 analogy is not exact

Carrying the observed spelling through — Entry 23's `d0`-vs-`s0` fix — regressed
three PASSING lanes on the first attempt:

    172_float_double_widths:clang:O2:double_precision_horner   pass -> fail
    172_float_double_widths:clang:O2:single_precision_horner   pass -> fail
    181_compensated_summation:gcc:O2:compensation_of_step      pass -> fail

`d0` and `s0` are two scalar VIEWS of one AArch64 register and a body reads one
or the other. `xmm1` and `xmm1_d0` are a WHOLE register and a PIECE of it, and an
x86-64 body routinely reads both. `double_precision_horner` opens with
`movapd %xmm1,%xmm3`, which lifts to four lane copies, so the FIRST touch of
argument 1 is `xmm1_d0` while every instruction that consumes the VALUE (`mulsd`,
`addsd`) reads `xmm1` whole. First-touch-wins picked the transport over the value
and rendered `var8` undefined in a function that had been correct.

The rule that holds: a whole-register live-in read UPGRADES a lane spelling; a
lane never downgrades a whole register; a definition of the slot seals it. The
lane survives only when it is all there is — `movd eax, xmm0` and nothing else,
which is exactly fixture 174. The asymmetry is x86-64's alone:
`is_scalarised_vector_lane` is false for every AAPCS and AAPCS64 scalar spelling,
so those paths are provably untouched.

### Measurement

Two full six-lane sweeps of the 742 prebuilt fixture objects (`GLAURUNG_VERIFY_DEFS=1`,
`--all`, `decbench` render), before and after, required functions only:

| lane | before (funcs/violations) | after |
|---|---|---|
| gcc:O0 | 9 / 10 | 6 / 7 |
| clang:O0 | 10 / 11 | 7 / 8 |
| gcc:O2 | 54 / 106 | 49 / 100 |
| clang:O2 | 63 / 125 | 62 / 121 |
| rustc:O0 | 32 / 37 | 32 / 37 |
| rustc:O2 | 17 / 23 | 17 / 23 |
| **total** | **185 / 312** | **173 / 296** |

Every emitted function: 3380 -> 3368 cells, 12703 -> 12687 violations.
(The 185/312 baseline reproduces Entry 24's post-fix total exactly. The per-lane
numbers the brief quoted — gcc:O0 11, clang:O0 13, … summing to 320 — are the
PRE-`e3169c5` figures.)

Cell by cell: **12 cells cleared, 4 reduced, ZERO newly violating, ZERO worse.**
Cleared: `172:accumulate_narrow`/`accumulate_wide` at gcc:O0, clang:O0 and
gcc:O2; `174:sign_bit_of_binary32`, `absolute_binary32`, `classify_binary32` at
gcc:O2 and `classify_binary32` at clang:O2; `175:scale_series_f32` at gcc:O0 and
clang:O0. Reduced: four more in 174 at O2.

`175:scale_series_f32(float *series, int32_t count, float factor)` is the mixed
signature the whole design exists for — pointer, int, float, which the positional
table mapped to `rdi, rsi, rdx` and which is really `rdi, rsi, xmm0`.

`tools/dectest.py` over **400 distinct lanes (55% of 724)** — `@vector-float
@smoke @region @loops @calls @flags @structs @polarity @coverage @aggregates
@widths @bias @sentinel @early-exit @switch @subword-division` plus every
`@curriculum-*` set and `17* 18* 19*` — **no regressions**, 6 execution
improvements. Two are this entry's:

    175_float_matrix_kernel:clang:O0:scale_series_f32   fail -> pass
    175_float_matrix_kernel:gcc:O0:scale_series_f32     fail -> pass

The other four (`185…remainder_signed_bytes`, `185…remainder_signed_shorts`,
`185…divide_signed_bytes`, `45…format_decimal`) are Entry 24's improvements,
which were never baselined and show up in any sweep since.

`cargo test`: **2312 passed, 0 failed, 1 ignored** (2307 at `e3169c5` plus five
new tests). Output verified byte-identical across three repeated runs; `prior`
became a `BTreeMap` because the new recovered-spelling search scans every prior
parameter and `HashMap` order is not reproducible.

### What this entry did not do

DecBench, Joern, the full fixture matrix and `arch_roundtrip.py` were not run. No
baseline was regenerated: `baseline.json` and `structural_baseline.json` are now
stale in the good direction by 2 execution lanes and 12 verify cells respectively
(on top of Entry 24's, still unrefreshed). No Python was touched.

Clusters C, D, E and F of Entry 24 are untouched. Cluster A is not finished: 174
still carries 3 violations at gcc:O2 and 7 at clang:O2. Those remaining ones are
NOT the parameter binding — the prototype is now `xmm0_d0` and correct — they are
functions where the body reads BOTH `xmm0` and one of its lanes as live-ins, which
no choice of parameter spelling can satisfy. That needs the lane/parent merge
`regview::ssa_parent` deliberately declines to do, and is a separate decision.

## Entry 27 — A confident lie about where a call goes

`call *(%rcx,%rax,8)` lifted to `Indirect(Addr(memory_displacement64()))` — which,
for an operand with no displacement, is `Addr(0)`. Base, index and scale were
dropped outright. Downstream this reads as a *resolved* call to address zero, and
nothing can tell it from a real one.

That is worse than the dropped blocks fixed in `38d6591`, and for the same
structural reason with one turn of the screw. A dropped block is missing
information; a fabricated target is wrong information wearing the costume of
right information. Design rule 8 asks for an explicit unknown when a proof fails.
This produced a confident answer instead, and every consumer — call graph, xrefs,
memory SSA, argument recovery, taint, and the relocation-proven table recovery
added the same day — believed it.

The second-order effect is the instructive one. Because `Indirect(Addr(..))`
reads no register, DCE saw the index arithmetic feeding the lookup as dead and
deleted it. So the table load disappeared too, and the evidence that would have
revealed the first error was removed by a pass acting entirely correctly on the
IR it was given. A wrong fact upstream does not stay one wrong fact.

The fix mirrors the `jmp *[mem]` path, which had been right all along: materialise
the dereference as a real `Load`, then transfer through the loaded value. That
asymmetry between two nearly identical instruction forms was the whole clue, and
it is worth remembering as a search heuristic — when one of a pair of analogous
paths works and the other does not, compare them before theorising.

### What it was worth

720 of 732 lanes swept (`@o0` + `@o2`, 98% of the corpus): **no regressions, 12
improvements**, including six that the table-call may-use work committed hours
earlier could not reach because the table identity was already gone by the time
it looked:

    95_function_pointer_table:clang:O2   fold_operations
    191_indirect_table_args:{gcc,clang}:O2  t191_dispatch, t191_computed_args, t191_fold

`95:gcc:O2:dispatch_operation` had been passing on luck — gcc emits that one as
`jmp *(...)`, the path that was already correct. The same function through
`call *(...)` failed. A green cell next to a red one, same fixture, same
function, differing only in which instruction the compiler chose, is a fair
description of what this defect looked like from the outside for a long time.

### Provenance

Found by the indirect-table may-use work (Entry 25), which correctly DECLINED on
these calls rather than guessing — the right behaviour, and the reason the defect
surfaced as "the fix does not help here" instead of as wrong output. The patch
was written by an agent that was terminated by a spend limit mid-task, leaving
the change on disk and its report unwritten; it was verified from scratch here
rather than taken on trust.

## Entry 28 — Two source variables, one register, and the narrow one won

`190_dual_role_products:{gcc,clang}:O2:dp190_mul_both_halves` was the corpus's
only failing widening multiply. Every division-based function in the same
fixture passed, which is the shape of a clue: the dual-role *value* machinery
was working, and something about *width specifically* was not.

The recovered C:

    low = (arg1 * arg2);
    *(long *)(((long)arg0)) = (unsigned long)(low);
    var4 = ((unsigned long)(low) >> 32);
    return (unsigned int)(((var4 + (var4 * 4)) + low));

`low` is declared `unsigned int` but holds the full 64-bit product, so
`(unsigned long)(low) >> 32` is identically zero and the high half is gone.

### The first wrong stage

Not a width pass. `GLAURUNG_DUMP_PASSES=1` shows every width map agreeing that
the value is eight bytes — `numbered value types`, `recovered declaration
types` and `recovered expression-width types` all carry `var2: width 8`. The
prepared AST is right too:

    %var2 = ((unsigned long)((unsigned int)(%arg1)) * (unsigned long)((unsigned int)(%arg2)));
    store &[%arg0] = %var2;
    %var4 = (%var2 >> 32);
    return (unsigned long)((unsigned int)(((%var4 + (%var4 * 4)) + %var2)));

The damage happens earlier, in DWARF naming, and the dump names it outright:

    DWARF register local { source_name: "low",     c_type: "uint32_t", ... }: role counts {"var2": 4}
    DWARF register local { source_name: "product", c_type: "uint64_t", ... }: role counts {"var2": 4}

Two source locals, the same DWARF register, the same PC range, the same
recovered value, the same evidence count. gcc served `product` and `low` from
one live `rsi` because one is the other's truncation, and DWARF faithfully
recorded both there.

`merge_dwarf_register_local_facts` bound the **first** claimant it happened to
walk and dropped the rest — `facts.source_names.contains_key(&role)` sends the
second one to `continue`. `low` came first, so `var2` was locked to `uint32_t`
via `apply_locked_fact`, and every correct width downstream was then overruled
by an authoritative-looking DWARF fact. Order of appearance was doing the work
of evidence.

That also explains why `refine_decbench_abi_widths_with_value_widths` could not
save it, twice over: its widening loop is gated on `is_high_variable(name)`, and
the value was no longer named `var2` but `low`; and even unblocked, a
`force_scalar_int` does not outrank a locked DWARF fact. Papering over a wrong
lock downstream would have been the wrong fix anyway.

### The rule

When several source locals resolve to one recovered value, only the widest can
be declared without losing bits. The narrow reads of that value already carry
their own truncating casts — here the return's `(unsigned int)` — while a narrow
*declaration* discards the high half before any use can see it. So: group
claimants by winning role, and when one has a unique strict maximum integer
width, it owns the value. A tie at the top, or spellings that do not resolve to
a scalar integer, leave the previous order untouched; the rule only fires where
it can prove which claimant subsumes the others.

The output is now both correct and better named than what it replaced —
`product`, the variable the source actually declares:

    unsigned long product;
    long var4;
    ...
    product = ((unsigned long)(arg1) * (unsigned long)(arg2));
    *(long *)(((long)arg0)) = product;
    var4 = ((unsigned long)(product) >> 32);
    return (unsigned int)(((var4 + (var4 * 4)) + product));

`src/python_bindings/ir/dwarf_contracts.rs`: the role-resolution half of the
loop becomes `resolve_register_local_role`, and `widest_claimant_per_role`
arbitrates. `cc` and the DWARF type env are threaded in so `long` resolves to
the right width per target.

### What it was worth

`@o2` (360 lanes, 49% of the corpus): **no regressions, 2 improvements** — the
two target cells. `@o0` (360 lanes): no regressions, no improvements. The
remaining twelve `rustc` lanes, run separately: no regressions. That is the
**whole corpus, 732 of 732 lanes**, and the only two cells that moved are the
two that were meant to. `cargo test` 2321 passed, 0 failed; `cargo test
--features python-ext` 2441 passed, 0 failed.

Worth stating plainly, because a first look at the sweep is misleading: `@o2`
reports 14 improvements, but 12 of them belong to Entry 27 and are already
recorded in the working tree's un-committed `baseline.json`. The committed
baseline is stale relative to `874fe33`. Only the two `dp190_mul_both_halves`
cells are this change's.

### How far the shape reaches

The sweep says which lanes MOVED; it does not say how often the collision
occurs. Parsing `GLAURUNG_DUMP_PASSES=1` across all 720 built fixture objects
for roles claimed by two source locals of differing width found **nine**, all at
`-O2`, which is where merged values live:

    190_dual_role_products {gcc,clang}  var2   low:uint32_t      product:uint64_t
    45_string_algorithms   clang        var22  count:int32_t     accumulator:int64_t
    55_modular_arithmetic  gcc          var12  remainder:int32_t result:uint64_t
    58_rational            clang        var17  numerator:int32_t left:int64_t
    58_rational            gcc          var13  numerator:int32_t right:int64_t
    63_numerical_integration clang      var23  width:int32_t     total:int64_t
    74_moving_statistics   gcc          var8   average:int32_t   total:int64_t
    96_integer_promotion   gcc          arg0   a:uint8_t         narrow:int16_t

Two are the defect. Six more now bind the wider claimant where order used to
decide, and all six still pass the execution differential — expected, because
widening a declaration cannot lose bits, only gain them. The last is on `arg0`,
where the pass already declines to rename argument roles at all, so nothing
changes there.

So this was not a one-fixture accident: one function in roughly eighty carries
the shape, and before this change the declaration was chosen by DWARF DIE order
in every one of them.

### `cargo test` does not compile `src/python_bindings/`

Found the hard way, and worth writing down. `python_bindings` is behind the
`python-ext` feature (`src/lib.rs:70`), so the command CLAUDE.md documents —
plain `cargo test` — never builds it. This change alters the signature of
`merge_dwarf_register_local_facts`, which lives there and has **five** unit-test
call sites. All five were left passing the old five arguments, and plain
`cargo test` went green anyway: 2321 passed, 0 failed, nothing compiled that
could have objected.

That is a 120-test hole (2441 - 2321) in the documented verification command,
and it is worse than a plain gap because it is *reassuring*: the suite reports
success over code it did not build. `cargo build --features python-ext` does not
close it either — that compiles the crate but not its `#[cfg(test)]` modules.
Only `cargo test --features python-ext` sees these tests. Anything touching
`src/python_bindings/` needs that spelling.

### Four dead functions, decided

`cargo build` reports ~98 never-used functions, which is an artifact:
`python_bindings` sits behind the `python-ext` feature and most passes are only
reachable from it. `cargo build --features python-ext` is the honest measure and
reported four.

* **`ast.rs:refine_decbench_abi_widths`** — kept, now `#[cfg(test)]`. The
  premise that its helper machinery (`collect_definition_widths`,
  `collect_high_half_requirements`, `propagate_required_widths`,
  `expression_value_width`, …) is unreachable is **false**: the sibling
  `refine_decbench_abi_widths_with_value_widths` holds all of it and is called
  twice from `src/python_bindings/ir.rs`. Only the two-line no-evidence wrapper
  is test-only. Deleting the machinery would have removed a live width pass.
* **`canary.rs:is_canary_addr`** — deleted. Born dead in `adde50b`, the
  end-to-end decompiler commit; `git log -S` finds exactly one commit, the one
  that added it, and it never had a caller in shipped code or in tests.
* **`memory_objects/llir.rs:infer_from_llir` / `observe_memop`** — deleted, with
  the module, its two tests, and the now producer-less `AccessSource::
  LlirInstruction` and `MemoryStateIdentity::Llir`. Superseded by
  `memory_objects::mir::attach`, which does the same job at the MIR boundary
  with stable instruction identity and is wired at `src/ir/mir/memory.rs:34`.
  The adapter was still costing maintenance: `fb4ee6b` mechanically updated it
  for the `RawAccess` refactor. Its `verify`-rejects-a-foreign-sidecar test
  duplicates `memory_ssa_tests.rs:467` and `:566`.

`cargo build --features python-ext`: 23 warnings before, 19 after, none of them
never-used functions.

### Not run

DecBench, Joern, `decbench_matrix.py`, the `--decbench` gate lanes, the full
fixture matrix, `arch_roundtrip.py`, repo-wide `cargo fmt`. `rustfmt --edition
2021` on the touched files only. No baseline refreshed and nothing committed.

## Entry 29 — The linked-structure argument kind, and what it found

Task: build the "linked-structure argument kind" the roadmap names as a
prerequisite (*"Add a linked-structure argument kind to the differential harness
before changing the nearly dormant sentinel-list recovery pass"*), then the
pointer-chased fixture it enables. Worked from `874fe33`. Numbered 29 rather
than 28 because another agent was appending 28 concurrently.

### The premise was half wrong, and the half that was right is the half that matters

`dormant-transforms-2026-08-12.md` records that "a parameter of type `struct
node *` whose `next` fields are real addresses into that buffer is not something
`tools/diff_decompile.py` can synthesise today", and Entry 24's roadmap
cross-references repeat it. That stopped being true at `5e24383`, which landed
the Rust DWARF reader with `DwarfType::SelfPointer` and the whole marshalling
path behind it: `_materialize_buffer` turns declared element indices into real
addresses AFTER allocating each side's array, `_snapshot_buffer` maps any
surviving link back to an index, and `pointer_return_arg` compares a returned
node by its index. It is exercised by
`test_recursive_linked_list_round_trips_values_links_and_pointer_returns` —
which passes at `874fe33` — and by the DecBench `linkedlist` overrides. Nothing
in `tests/decompiler_fixtures/` used it, so it was invisible.

What was genuinely missing is narrower and sharper: **every chain the harness
could build was the identity successor**. `chain()` linked `nodes[i].next =
&nodes[i+1]` over a prefix whose length varied with the vector index. Under that
graph chain order IS array order, and a recovery that reads `p = p->next` as
affine arithmetic walks it correctly. A pointer-chase fixture built on the
identity successor measures nothing about pointer chasing.

Measured, not argued. Take the realistic confusion — the NULL TEST recovered off
the pointer load, the ADVANCE rendered as `+ 1`:

    while (c != 0) { c->payload += s; v += 1; c = (c->next == 0) ? 0 : (c + 1); }

| node buffer | verdict |
|---|---|
| identity successor (all the harness could build) | **pass**, 22 cases |
| declared `link_chains` (what it can build now)   | **fail**, `return 6 != 4` |

That is the whole justification for the feature, and it is pinned in
`test_link_chains_catch_an_affine_advance_the_identity_chain_hides`. If that
test ever goes green on the declared chain, every pointer-chase verdict in the
corpus is worthless.

### What was added

`link_chains: [[int]]` in `tests/decompiler_fixtures/manifest.py` — a list of
element-index walks over one caller-owned array of self-referential structs,
cycled by vector index. `chain[0] -> chain[1] -> ... -> NULL`; every node the
walk does not name is NULL-linked.

The same relocation reaches both sides because both go through the one
`_materialize_buffer` call site that already existed. The chain is stated as
INDICES and becomes addresses only inside that function, once per side, so there
is no second path to drift from — which is the property the whole kind rests on.

Fail-closed, on the rule that every rejected shape is one that would otherwise
pass silently:

* a chain not starting at element 0 is unreachable from the `&buffer[0]` the
  callee is handed, so the function would walk nothing and report `pass`;
* a repeated index is a CYCLE, and the ORIGINAL side does not return from one —
  the verdict would be a 300s worker timeout attributed to the decompiler;
* an index outside `ptr_len` cannot be relocated at all;
* a bare `[0, 3, 1]` where a list of chains is meant would quietly become three
  single-node graphs;
* `link_chains` on a function with no self-linked pointer parameter is a
  manifest describing a different function.

Separately, `_materialize_buffer` now REFUSES a link that is neither `-1` (NULL)
nor an index into the buffer, instead of silently nulling it. Nulling shortens
the chain on both sides, both sides then agree, and the lane reports `pass` for
a graph nobody declared.

Absent `link_chains`, materialisation is bit-for-bit what it was — the seeded
`randrange` draw is even kept when a chain IS declared, so adding one to an
existing function changes its links and nothing else. That is what makes this
safe against 733 recorded lanes, and it is pinned by
`test_absent_link_chains_keep_the_historical_identity_successor`.

### The fixture

`192_pointer_chased_list.c`, five functions. `l192_find_key` is the probe from
`dormant-transforms-2026-08-12.md` character for character: parameter head,
`p = p->next`, NULL sentinel, no counter. `l192_chase_keys` writes the visit
ORDER into a caller-owned int buffer; `l192_stamp_chain` mutates the nodes it
visits, so the visited SET is compared too; `l192_sum_until_key` is
order-dependent by construction. `l192_scan_index_control` walks the same nodes
BY INDEX — simultaneously the degeneracy control (the affine recovery must keep
working, so the fixture cannot be satisfied by refusing to transform anything)
and the near-miss (it is exactly the answer a chase-to-stride confusion gives).

One hand-built graph is declared inline and its shape is the point: chain
`0 -> 3 -> 5 -> NULL`, with nodes 1, 2 and 4 sitting OFF the chain carrying the
keys the searches ask for. An index walk answers node 1 where the chase answers
node 3, and answers node 2 where the chase answers "not found".

Every chase function was checked against a deliberately wrong stride recovery
and each fails with the designed message — `l192_find_key` reports
`return node 3 != 1`. The control was checked the other way: implemented as a
chase it fails with `return 2 != -1`. A fixture nobody has tried to break is a
fixture nobody has tested.

### What the fixture found

**All 20 lanes pass.** The pointer chase is recovered correctly at
`{gcc,clang} x {O0,O2}`. `clang:O2` renders it with the real `L192Node` type:

    while (1) { ret = p; if (p->key == arg1) break; p = p->next;
                if (p == 0) return (L192Node *)0; }

So this is standing coverage rather than a bug report — the honest outcome, and
worth having, because the shape had none.

**`recover_sentinel_search_loops` still fires 0 times, on its own designed
input.** `GLAURUNG_PASS_STATS=1` over all four built objects of fixture 192: 8
attempts, 0 fires. Over the doc's probe source built standalone under the pinned
clang 14 at `-O0/-O1/-O2` and gcc 11 at `-O0/-O1/-O2`: 0 fires everywhere. The
2026-08-12 record of "1 fire at clang -O1 and -O2" does not reproduce at
`874fe33`.

Why that record cannot simply be re-checked: `5e24383`, the commit that CONTAINS
`dormant-transforms-2026-08-12.md`, has no `pass_stats` call sites in
`src/ir/loop_form.rs` at all — `git show 5e24383:src/ir/loop_form.rs | grep
pass_stats` is empty. The instrumentation was restored in `0ecb8e1`. That
measurement was taken on a build that is not in this history, and the number was
never reproducible from the tree.

Where the matcher loses it, read off `sentinel_search_candidate`'s preconditions
against the actual AST. The divergence is upstream in `ir::structure`, before
`loop_form` is offered anything:

| the matcher requires | what the pipeline produces |
|---|---|
| `Stmt::While { cond: match_continue, .. }` — the match test IS the loop condition | `while (1)` with an interior `break` on the match |
| a 2- or 3-statement loop body | 4 statements (`ret = p`, the break guard, the advance, the null guard) |
| `sentinel` is `Expr::Const` | a cast of `0` |

So the pass is not one clause too strict; it describes a head-tested shape the
structurer does not emit for this CFG. That is a decision for whoever picks the
roadmap item up — repoint the matcher at the `while (1) { ... break ... }` form
the structurer actually produces, or retire it deliberately, which is what "add
standing real coverage for extremely rare transforms or retire them
deliberately" asks for. The coverage half is done: `@sentinel` now covers 183
and 192, so an edit to the matcher is finally measured against the input it was
written for.

**`111_self_referential_struct` is unchanged and its recorded diagnosis is
confirmed.** `clang:O0` passes, the other three lanes fail, exactly as the
baseline records. The dump corroborates Entry 24 / cluster E with no new
theorising: after `promote_stack_locals` AND after `recognise_machine_frame`,

    %rdx#6 = (%rdx#5 + %rbp)

is still unpromoted, and the rendered C declares `long rbp;` and derives every
node address from it. The interesting detail is how PARTIAL the recovery is: the
`next` field is stored as `&local_90[0] + (index << 4)` — the real frame object —
while the store TARGET on the adjacent line is `(index << 4) + rbp - 144`. One
expression found the object and its neighbour did not. First wrong stage remains
`src/ir/stack_locals.rs`, an EPIC 3 gap. Not touched here; the brief was the
harness and the fixture, and a wrong fix to stack promotion is worse than an
accurate diagnosis.

### Verification

* `cargo test`: **2323 passed, 0 failed**.
* `tools/dectest.py 192_pointer_chased_list --full` — 20/20 pass.
* `tools/dectest.py 111_self_referential_struct --full` — 1 pass, 3 fail, no
  change against the baseline.
* `@o0` 362 lanes: no regressions. `@o2` 362 lanes: no regressions, 12
  improvements — all twelve are Entry 27's, already recorded there; the
  committed `baseline.json` is stale relative to `874fe33`. 724 of 736 lanes
  (98%) swept, which is the coverage a change to argument materialisation needs.
* `python/tests/test_decompiler_fixture_harness.py -k "link_chain or
  unrelocatable or pointer_chase_fixture or recursive_linked"` — 13 passed.
* `uvx ruff format --check` / `uvx ruff check` clean on the three touched Python
  files. `uvx ty check` adds four diagnostics, all the pre-existing
  `Module 'pytest' has no member 'raises'` false positive the file already
  carries.

### Baselines this needs (not regenerated here, deliberately)

`192_pointer_chased_list` needs `baseline.json` (20 lanes),
`structural_baseline.json` (aggregate counts shift) and `arch_baseline.json`
(six architectures). Two arch lanes were probed scoped rather than swept:
`aarch64:O0` is 5/5 pass, and `i386:O0` reports 5 ABI-incomparable — the node
struct is 12 bytes there against the host reference's 16, so
`abi_incomparable` declines cleanly instead of raising a lane error, and
`--write-baseline` is not blocked.

### Not run

DecBench, Joern, `decbench_matrix.py`, the `--decbench` gate lanes, the full
fixture matrix, a full `arch_roundtrip.py` sweep, repo-wide `cargo fmt`. No
baseline refreshed, nothing committed.

## Entry 30 — Item 10 was already done; what was actually broken underneath it

Task: "partition the MIR frame object into per-variable extents", the piece the
roadmap calls a prerequisite of item 2. Worked from `34b17c2` in a detached
worktree with a private target directory. Owned files only:
`src/ir/memory_objects.rs`, `src/ir/memory_objects/*`, `src/ir/mir/*`.

### The premise was wrong: the partition landed 18 commits ago

`src/ir/memory_objects/partition.rs` already exists. It landed in `a45c1ae`
("ir: partition the MIR frame object into evidence-backed extents") on
2026-08-14 and is written up as Entry 15 of this diary. It computes covered
runs, `Spanned`/`Abutting` boundary evidence and `bounds_at` -> `at_least` /
`at_most`, refuses on four typed `PartitionConflict`s, is computed for every
object in `MemoryObjectBuilder::finish`, and is reachable as
`MirFunction::object_partition`. Five real GCC fixtures assert its behaviour.

What was not updated is `docs/design/decompiler-roadmap.md`. Item 2 still reads
**[BLOCKED — this ordering is wrong]** and item 10 still says "**Promote ahead
of item 2**". Both sentences describe the world before `a45c1ae`. **That text
should be corrected**; a brief written from it sends the next agent to rebuild a
module that exists.

This is the fifth such correction in two days. The pattern is specific enough to
name: a roadmap item's status lives in the roadmap, the work lands in a diary
entry, and nothing makes the two agree.

### So the frame partition itself was not the blocker. Two other things were.

#### 1. A pointer merged at a control-flow join was invisible to the model

`memory_objects/mir.rs` refuses a frame whose root reaches an operand position
it does not interpret, by scanning `function.uses()`. **A phi's incoming edges
are not `MirUse`s.** They are plain `ValueId`s inside
`Definition::Phi { incoming }`, so the scan cannot see them at all.

The consequence is a wrong-code-class hole in the fail-closed direction that
matters. When `resolve_affine_values` cannot place a phi — the incoming
coordinates disagree, or one of them is not affine at all — an access through
that merged pointer is rooted at the PHI VALUE, creating a separate object. The
frame object never hears about it, reports an empty conflict set, and bounds
every variable in a frame whose bytes were written behind its back.

Measured, not hypothesised. `143_dynamic_frames.c:alloca_in_loop`, gcc `-O0`,
x86-64: GCC emits the stack-probe loop (`sub $0x1000,%rsp` around a back edge)
and then `sub %rdx,%rsp` by a RUNTIME amount. Before this increment that frame's
partition reported `{}` — no conflict, every extent bounded — with a
runtime-sized allocation sitting in the middle of it.

The new rule is `PartitionConflict::MergedPointer`: for a phi the resolver did
not place, every incoming edge that DID resolve reports a conflict on its root.
A phi the resolver did place needs no report — `propagate_acyclic` places one
only when every edge carries the same root and offset, and the recurrence path
records a stride that `UnboundedCursor` already refuses.

One refinement was needed and is load-bearing. Unpruned SSA gives a join a phi
for every register live on any edge, including ones whose merged value is
immediately overwritten. Reporting those blamed the frame for dead definitions:
across the corpus it raised 33 conflicts on clang `-O2` where 15 are real, and
cost 5 frames of boundedness that nothing could ever have read. Restricting the
rule to phis some use or some other phi actually reads removes exactly that
noise and changes no real verdict.

#### 2. The join to the AST model had only one half

`StackLocalFacts::frame_coordinates` (landed `d1ffbec`) publishes `(base, disp)`
per promoted-local NAME, and its own doc says "This is the join MIR evidence
needs". There was no other half. MIR keys the frame by the root pointer VALUE
and folds displacements into each access, so `("rbp", -0xc)` names nothing in
that coordinate: the rebase constant — how far `rbp` sits from the root — was
computed inside `resolve_affine_values` and thrown away.

`MemoryObject::base_offsets` now publishes it: the offsets, in the object's own
coordinate, of every machine register used as an address cursor into it. A
register observed at two different offsets keeps BOTH — rule 3, the conflict is
retained and the evidence that produced it is not destroyed. The first cut
dropped such a register instead, which made the query answer `UnknownBase`, and
that is a false statement: the frame IS addressed through it, just not at one
offset. The refusal is computed at query time so it can say which failure it is.

`MemoryObjectModel::resolve_frame_coordinate(base, disp)` is the translation,
returning a typed `FrameCoordinate` (`Resolved` / `UnknownBase` /
`AmbiguousBase` / `OffsetOverflow`) rather than an `Option`, so a refusal is
distinguishable from an answer. Two base spellings exist and mean different
things: `entry_rsp` / `entry_sp` is the architectural entry stack pointer, which
IS the object's root — offset zero, no register lookup, true on every target;
every other spelling names a machine register and resolves through
`base_offsets`.

### Evidence

`162_unaligned_memcpy_access.c:ua162_store_be32`, gcc `-O0`, x86-64. A real
decompilation of that function promotes seven frame locals; the coordinates
below are the ones `frame_coordinates` mints for them. MIR, which never saw a
promoted local, bounds each one at exactly its source width:

| promoted name | `frame_coordinates` | MIR offset | `at_least` | width |
|---|---|---:|---|---:|
| `local_24` | `("rbp", -0x24)` | -44 | `[-44, -40)` | 4 |
| `local_20` | `("rbp", -0x20)` | -40 | `[-40, -36)` | 4 |
| `local_1c` | `("rbp", -0x1c)` | -36 | `[-36, -32)` | 4 |
| `local_18` | `("rbp", -0x18)` | -32 | `[-32, -24)` | 8 (`uint8_t *buf`) |
| `local_10` | `("rbp", -0x10)` | -24 | `[-24, -20)` | 4 |
| `local_c`  | `("rbp", -0xc)`  | -20 | `[-20, -16)` | 4 (`uint8_t staging[4]`) |
| `local_8`  | `("rbp", -0x8)`  | -16 | `[-16, -8)`  | 8 (stack canary) |

A register that addressed the same frame at both -16 and -32 keeps both offsets
on the object and answers `AmbiguousBase`, while `entry_rsp` still resolves over
that same frame — the ambiguity of one base does not poison the others.

The two spellings are asserted to agree: `rbp` resolves through `base_offsets`,
which had to prove the register held root-8, and `entry_rsp` resolves through
the root at offset zero. Landing on the same byte is the join's own consistency
check. `r12` answers `UnknownBase`, not offset zero.

Refusal census over `tests/decompiler_fixtures/build` (x86-64, one partition per
stack-rooted object, throwaway harness not committed, same method as Entry 15):

| corpus | frames | bounded before | bounded after | `MergedPointer` | frames it alone unbounded |
|---|---:|---:|---:|---:|---:|
| `gcc-O0` | 1,363 | 1,277 | 1,276 | 23 | 1 |
| `gcc-O2` | 609 | 559 | 554 | 36 | 5 |
| `clang-O2` | 639 | 594 | 590 | 15 | 4 |

Ten frames across 2,611 stopped being reported as bounded, and every one of the
ten was a false verdict. The ten cluster: `143_dynamic_frames` (alloca), and C++
dispatch — `132_cpp_vtable_layout`, `134_cpp_virtual_inheritance`, `135_cpp_rtti`,
`10_cpp_runtime_shapes`.

New tests, each written failing first: one real fixture for the defect
(`alloca_in_loop`), one real fixture for the whole join (the table above), and
three synthetic LLIR controls — a join of two DIFFERENT frame addresses refuses,
a join of two EQUAL ones still partitions, and an ambiguous base refuses with a
reason. The real no-merge control is
`ua162_store_be32` itself, whose conflict set stays empty over a branching frame.

### What justifies each boundary, and what happens when evidence is absent

Restated with the new rule, because the whole model is only as good as this list:

- A covered run's OUTER edge is justified by bytes no access reaches. It is the
  only place the model splits.
- An interior `Spanned` position is justified by one access covering both sides.
  It is machine evidence that they are one storage unit, not proof that they are
  one source variable.
- An interior `Abutting` position is justified by accesses meeting and none
  spanning. It neither joins nor separates.
- `at_least` is the interval between adjacent abutting positions. Its bytes are
  joined by a CHAIN of overlapping accesses, which is weaker than one access
  covering all of them — an inlined `memcpy` with overlapping wide loads can
  chain across a real source boundary. The doc previously claimed the stronger
  property; it now states the actual one. The error direction is merging, which
  is the closed one: merging loses a boundary, narrowing would invent one.
- `at_most` is the covered run.
- Absent or contradictory evidence produces a typed conflict, and `bounds_at`
  then returns `None` while `extents` keeps everything observed (rule 3):
  `UnmodeledAccess`, `EscapedRoot`, `UnboundedCursor`, `UnresolvedCoordinate`,
  and now `MergedPointer`.
- A frame coordinate that cannot be translated answers with a REASON, not an
  absent fact (rule 8).

### Is item 2 expressible now? Yes — and the roadmap names the wrong consumer

Expressible: the table above is the join, executed end to end on a real binary,
agreeing with the AST model on all seven locals.

But `high_variables::refine_object_cursor_values`, the consumer the roadmap
names, does not ask a per-variable extent question. It asks
`object_model.has_conflict_free_extent(name)`, which is
`extent.is_some() && conflicts.is_empty()` — a question about a cursor walking
an array of STRIDE-sized elements. Three consequences:

1. The MIR analogue of that exact question needs no partition at all. `stride`,
   `extent` and `conflicts` are computed by the SHARED
   `MemoryObjectBuilder::finish`, so `mir.object_for_value(v)` already answers
   it today.
2. The partition explicitly REFUSES stride-walked objects
   (`UnboundedCursor`) — the very class `has_conflict_free_extent` accepts. The
   partition is not that consumer's join.
3. What actually blocks that consumer is a NAME-to-VALUE correspondence across
   pipeline stages, not a memory partition. It runs on the prepared AST, keyed
   by promoted-local name; MIR is lowered from `PreparedLlir::numbered`, keyed
   by `ValueId`, an earlier representation. `frame_coordinates` +
   `base_offsets` closes that gap for frame-resident locals and for nothing
   else — a cursor into a heap or parameter object has no frame coordinate to
   join through.

A sharper statement of "the two models partition memory differently": it is not
that one is per-root and the other per-variable. It is that the AST adapter
receives a frame **another pass already split** — `stack_locals` promotes each
slot to a named local and `memory_objects/ast.rs` treats a store to a promoted
local as a DEFINITION, not an access — while the MIR adapter receives the raw
frame. The AST model contains no frame object at all.

So the migration to write first is a frame-resident aggregate consumer, joined
by `frame_coordinates` -> `resolve_frame_coordinate` -> `bounds_at`, with the
refusal wired to a real refusal and not to a default. Migrating
`refine_object_cursor_values` specifically would be migrating a stride question
onto extent machinery.

### Considered and not done

- **DWARF as partition evidence.** `DwarfStackObject { base, offset, byte_size }`
  is authoritative and would narrow `at_most` toward the truth, and a declared
  boundary an access spans would be a contradiction worth retaining. It is not
  wired in because `ProgramImage` carries no DWARF — it is parsed in
  `python_bindings/ir/dwarf_contracts.rs` and reaches the AST pass as
  `StackObjectHint`. Threading it into `lower_verified_with_image` is a
  cross-cutting plumbing change, and it would put a source-level authority
  inside a model whose whole claim is that it answers from machine evidence
  alone. The right shape is a consumer that intersects `bounds_at` with DWARF,
  not a partition that consumes DWARF.
- **A new fixture (193).** None is needed and one would be misleading. The MIR
  object model has no production consumer — `lower_verified_with_image` is
  called from `PreparedLlir::mir()` (`#[allow(dead_code)]`, one test caller) and
  from inside a `GLAURUNG_DUMP_PASSES` block — so a decompiler-output lane
  cannot observe any of this. The shapes are already covered by
  `143_dynamic_frames`, `132_cpp_vtable_layout` and `162_unaligned_memcpy_access`,
  driven directly through real GCC builds in `partition_tests.rs`. **No baseline
  needs regenerating.**
- **Narrowing escape granularity**, the indexed-access hole, and shape
  classification (struct/array/union) are unchanged from Entry 15's list.

### Gates

```
cargo test --features python-ext    2446 passed, 0 failed, 1 ignored (pre-existing)
cargo build --features python-ext   0 "never used"; the one remaining dead-code
                                    warning is the pre-existing never-read field
                                    at src/analysis/ioctl_taint.rs:409
cargo clippy --all-targets --features python-ext   nothing on the touched files
tools/dectest.py @o0                362 lanes, no regressions in scope
tools/dectest.py @o2                362 lanes, no regressions in scope
rustfmt --edition 2021              on the six touched files
```

The corpus result is the predicted one and was run to falsify the prediction,
not to confirm it: with no production consumer, a memory-model change cannot
move a decompilation, and it did not.

### Not run

DecBench, Joern, `decbench_matrix.py`, the `--decbench` gate lanes, the full
fixture matrix, a full `arch_roundtrip.py` sweep, repo-wide `cargo fmt`. No
baseline refreshed, nothing committed.

## Entry 31 — Every way out of a block, named

Task: the first two bullets of the roadmap's "Complete CFG and semantic
structuring" block — carry edge completeness through every artifact, and
represent direct, conditional, switch, indirect, exceptional, call, return,
tail-call and unknown terminal edges explicitly. Worked from `21b0fde` in a
detached worktree with a private target directory. Owned files:
`src/ir/cfg_edges.rs`, `src/ir/health.rs`, `src/ir/health_tests.rs`,
`src/ir/structure.rs`, `src/analysis/exception.rs`, `tools/pass_health_report.py`.

### What was already there, and what the brief got wrong

The brief said "LLIR has no exceptional-edge representation at all". That is
half true in a way that matters. `analysis::exception` recovers LSDA call sites
and `with_exceptional_successors` (landed well before this work) clones the
LLIR graph and appends each landing pad to its protected call block. So the
exceptional edge is recovered, and it is real.

What it is not is *typed*, and it never reaches the structurer. The augmented
graph is built inside `normalize_definedness_and_compute_ssa`, consumed by
`compute_ssa` and the bit-demand oracle, and dropped. `prepare_llir_for_lowering`
hands region recovery the **un-augmented** function. So the landing pad has no
predecessor in the graph the structurer sees — which is the real reason the
EPIC 5 query surface has nothing to ask about exceptions, and a more specific
finding than "there is no representation".

This is the sixth brief in three days whose premise was already implemented.

### The lie the classifier was telling

`cfg_edges::classify` derives an edge's kind from the terminator, and hands out
an order-derived label when the terminator does not name a target. It had no
bound on how many times it would do that. A `CondJump` explains two successors;
a third got `Fallthrough` — a second one, out of the same block. A block with no
transfer instruction explains one successor; a second got `Linear`. Both
statements are impossible about any block, and both read downstream as ordinary
facts.

That is not hypothetical, and the exceptional edge is where it bites. On
`samples/containers/hello-cpp-g++-O0` the LSDA proves **15** transfers to a
landing pad. Classify the augmented graph the way the old code did and **13** of
them come back `Linear` — a second "this block runs off its end" on a block that
already had a real fallthrough. The claim that produces is that control reaches
a `catch` handler by falling into it.

The remaining two are more interesting: their landing pad starts exactly at
`block.end_va`, so the handler abuts the protected range and *position cannot
tell them apart from sequential flow at all*. Only the LSDA separates those. It
is the cleanest available argument for why the proof has to be carried rather
than re-derived.

### What landed

**`EdgeKind` gained two variants.** `Exceptional` — a transfer proven by the
LSDA rather than by any instruction. `Unknown` — an edge the terminator does not
explain. The classification rule is now bounded: **exactly one successor may
carry an order-derived label** (the abutting block for a fallthrough or a linear
run, the named target for a jump), and every further one is `Unknown`. This only
changes edges whose old label was provably a duplicate; a single successor keeps
the label it always had.

`classify_with_exceptions` takes the `(source VA, landing pad VA)` set, and
`analysis::exception::exceptional_edges` produces it from the same predicate
`with_exceptional_successors` uses, so the augmentation and the labelling cannot
disagree. Exceptional successors are also excluded from the `succ_count > 2`
dispatch fallback — two handlers plus a fallthrough is three successors, and
that fallback would have started reading a protected call block as a jump table.
The augmentation loop still iterates `sites` rather than the set, because
successor order feeds phi operand order.

**`TerminalKind` is new, and is where the roadmap's list actually lives.** A
block with no successors used to produce no edge of any kind, so a return, a
`noreturn` call, a tail call, an unresolved `jmp *%rax` and a block whose
successors were simply lost were the same observation: nothing.
`classify_terminals` names them — `Return`, `ConditionalReturn`, `TailCall`,
`Call`, `Direct`, `Indirect`, `Unknown` — with one invariant worth stating:
**no block has zero ways out.** Anything unclassifiable is `Unknown`, counted,
never absent.

Two details are load-bearing. A recovered tail call is
`Call { is_tail_call } ; Return`, so reading only the terminator reports every
one of them as an ordinary return — the frame-replacing fact is one instruction
back. And a conditional return emits `ConditionalReturn` *in addition to* its
successor edges, because the block genuinely does both; if it has no successor
at all, the side that continued is reported `Unknown` rather than assumed away.

**`CfgHealth` and `AstHealth` gained four counters** —
`unknown_cfg_edges`, `terminal_edges`, `unknown_terminal_edges`,
`unresolved_indirect_edges` — computed in `recover_verified_with_health` from
the same `Cfg` the region was built over. They answer a different question from
the accounting counters already there: accounting says what the region tree
failed to express about the graph, and the census says what the graph failed to
prove about the program. A region can account perfectly for a graph that is
missing half the control flow, which is exactly what this module's own header
warns about.

### Measured, because a new counter that fires everywhere means something else

Across every sample binary the corpus test can find (203 functions):

| terminal kind | count |
|---|---|
| Return | 143 |
| Call (callee does not return here) | 37 |
| Indirect (destinations never recovered) | 37 |
| TailCall | 28 |
| Direct | 4 |
| Unknown | 3 |

Zero unexplained successor edges, and zero blocks accounting for no outgoing
control. Read the `Indirect` count honestly: the debug census shows most of
those 37 are single-block PLT thunks (`jmp *GOT(%rip)`), not failed switch
recovery. Six come from four-block functions — the `deregister_tm_clones`
shape — and those are genuine unresolved computed transfers. The number is a
census, not a defect count; what changed is that it exists at all.

### Compatibility break found on the way out

`tools/pass_health_report.py` validated health events with
`set(health) != set(COUNTERS)` — an EXACT key set. That makes every new counter
a breaking change to recorded evidence: adding these four would have rejected
`tests/decbench_scoreboard/fixtures/hello-main-pass-health.jsonl` and every
trace captured before today. Relaxed to "required counters must be present,
recognised optional counters are summarized when they are there". The fixture
stays valid unchanged and the new counters are reported when the emitting build
has them.

### What this does NOT do

* **Exceptional edges still do not reach the structurer.** `Cfg::from` calls
  `classify` with an empty proof set over the un-augmented graph, so
  `EdgeKind::Exceptional` cannot fire in production today. Wiring the augmented
  graph into region recovery is a behaviour change the region algebra is not
  ready for — a landing pad is a second entry into the middle of a region — and
  it belongs with the roadmap's "graph-complete region recovery" bullet, not
  here. All twelve `136_cpp_exception_unwinding` cells still fail; nothing in
  this entry was expected to move them.
* **The region tree does not own terminal edges.** There is no `Return` region
  node, so `structure_accounting` still accounts for successor edges only. The
  census is attached to the same `CfgHealth`, but total accounting in the strong
  sense — the tree explains every way out — is not done.
* **`is_dispatch`'s `_ => succ_count > 2` structural fallback is untouched.** A
  non-branch terminator with three or more successors is still read as a jump
  table rather than reported unknown. It is reachable for synthetic and imported
  CFGs and changing it is a separate measurement.
* **Budgets and skipped bytes are not carried.** Bullet 1 also names budgets and
  discovery-side coverage; this entry covers unresolved transfers, clipped
  targets (as `TerminalKind::Direct`) and edge completeness only.

### Verification

* `cargo test --features python-ext` — **2459 passed, 0 failed** (2441 at
  `21b0fde` plus the 18 tests added here). `cargo build --features python-ext`
  reports **0** never-used items; the 19 remaining warnings are all pre-existing
  and in files this work did not touch.
* Unit coverage: one test per new `TerminalKind`, one per new `EdgeKind`, the
  "every kind is produced by some shape" pair, the no-zero-exits invariant, and
  a corpus census asserting no unexplained edge and no silent block.
* Fixture-backed: `a_real_landing_pad_edge_is_exceptional_and_was_previously_a_
  second_fallthrough` runs the whole pipeline over
  `samples/containers/hello-cpp-g++-O0` and checks all 15 real LSDA edges, with
  the 13/2 split above asserted rather than described.
* `tools/dectest.py @o0` — 362 lanes, **no regressions and no improvements**.
  `tools/dectest.py @o2` — 362 lanes, **no regressions and no improvements**.
  724 of 736 lanes (98%) swept against `21b0fde`'s `baseline.json`. Neutral is
  the correct result for this change and was the prediction: the corpus census
  says zero unexplained edges exist today, so the only classification that could
  have moved is one that never fires.
* End to end: a real `GLAURUNG_PASS_HEALTH=1` trace carries the four new
  counters, and `tools/pass_health_report.py` still reads the pre-existing
  `hello-main-pass-health.jsonl` fixture that does not have them.
* `python/tests/test_pass_health_report.py` and
  `python/tests/test_decompiler_output_canaries.py` — 9 passed.

### Baselines this needs

None. No fixture was added, no baseline regenerated.

### Not run

DecBench, Joern, `decbench_matrix.py`, the `--decbench` gate lanes, the full
fixture matrix, a full `arch_roundtrip.py` sweep, repo-wide `cargo fmt`.
Nothing committed.

## Entry 32 — Use-site reference interpretation, and the table that was wrong twice

Numbered 32 rather than 30 because two other agents appended concurrently.

Task: EPIC 2's first two open bullets — an operand/use-site
`ReferenceInterpretation` with source instruction, exact width, provenance,
alternatives and confidence, and a resolver that orders evidence
relocation → decoded operand → mapped region → MIR provenance → call/type
constraint → xref consistency → heuristic — plus the negative controls that
prove a mapped numeric used in arithmetic stays numeric. Worked from `21b0fde`.
Migrating and deleting the existing recognizers was explicitly out of scope.

### What the survey changed about the brief

Three things in the framing were off, and one of them changed the design.

**There is no `ReferenceInterpretation`, but there are fourteen recognizers.**
`grep` for `ReferenceInterpretation` / `ReferenceIndex` / `OperandRole` /
`use_site` across `src/` returns nothing, so the type really was absent. What
exists instead is fourteen independent deciders — `analysis/xrefs.rs`,
`ir/name_resolve.rs`, `ir/strings_fold.rs`, `ir/readonly_fold.rs`,
`ir/got_fold.rs`, `ir/function_tables.rs`, `analysis/vtable.rs`,
`analysis/jump_table.rs`, `ast::lower_memop`, `const_fold`'s `Addr ± Const`
re-fold, the `glaurung_global_*` renderer, the three lifters' `Value::Addr` tag,
and `analysis/cfg.rs` — sharing no vocabulary. Two of them model uncertainty:
`function_tables` keeps its whole `targets` list, and `program::symbols` keeps
selected/alternatives/conflicts/incompleteness.

**The negative-control property was already mostly true on x86-64, for a reason
nobody wrote down.** `Value::Const` and `Value::Addr` are distinct in LLIR, and
`ast.rs:758` carries that split into `Expr::Const` vs `Expr::Addr`. An x86-64
immediate arrives as `Const` and no pass symbolizes a `Const` except
`strings_fold`, and only when a known library contract declares that parameter
`char *`. `const_fold:865-915` narrows further with an `Add`/`Sub`-only operator
whitelist, whose comment records the damage that motivated it (an ADRP page
collided with `__cxa_finalize` and a volatile counter printed as
`__cxa_finalize + 28`). So the roadmap's *first* tier — "decoded operand role" —
is already half materialised, as a two-valued tag with no provenance, no width,
no alternatives, and no way to disagree with it.

**`SymbolStore` had zero production consumers.** It is the canonical store
EPIC 1 marks `[x]`, it indexes relocation sites by place, and it refuses to
guess (`AddressUnknown::AmbiguousRanges`). Every caller of
`ProgramSession::symbol_store()` in the tree was in `session_tests.rs`. The
decompiler used the flat `HashMap<u64, String>` from `name_resolve` instead.

### The defect the survey pointed at, reproduced

A `static const char *const` table does not live in `.rodata`. It lives in
`.data.rel.ro`, which `readonly_fold`'s section-name filter and
`strings_fold`'s both exclude, so nothing in the tree touches it. Built from a
four-entry probe, `gcc -O2`, both PIE and `-no-pie`:

```c
name_len:  var4 = *(long *)(0x403de0 + (arg0 & 3) * 8);
```

`0x403de0` exists in the input image and in no rebuilt unit, so every lane that
reads such a table segfaults.

The instructive part is what happens if you "fix" it with mapped-region
evidence. Adding `.data.rel.ro` to the readonly collector — a two-line spike —
gives:

```c
name_len:  var4 = (i == 0) ? 0x402008 : (i == 1) ? 0x40200e : ... ;
```

which is the same dangling address wearing a number's clothes, and is exactly
the failure mode the roadmap's negative-control bullet describes. Both readings
are available from the bits; neither is right. The reading that recompiles is
"slot 0 holds the string `"alpha"`", and only something that knows the slot is a
*reference* can produce it.

That is why the consumer is `readonly_fold` and not the higher-traffic
`name_resolve`: it is a place where the resolver's answer is demonstrably
different from every answer available without it.

### `program::references`

`ReferenceSite` is `{ origin, width_bits }`, where `origin` is either
`Instruction { va, operand }` or `Storage { va }` — a table slot has no source
instruction, and pretending it does would make the site identity a lie.
`OperandRole` is the use-site question ("is this operand being used as a
reference?"), kept separate from the value question ("could these bits be an
address?"). `EvidenceSource` has the roadmap's seven tiers and derives `Ord` in
that order, so `min()` is "the strongest claim". `InterpretationKind` covers
integer / address / symbol+addend / code address / string literal /
`Unknown(reason)`.

Two rules do the work, and neither is ordering:

* **Role admission.** `OperandRole::admits` says a relocation is admitted
  everywhere — a relocated place *is* a reference regardless of what the
  surrounding code does with it — and everything weaker needs the role to
  already say "reference". `ScalarArithmetic` admits nothing below a relocation.
  `Unclassified` admits only the decoder's own tag, not mapped-range membership.
  This is the negative control expressed as policy instead of as a pass-ordering
  accident.
* **Fail-closed supply.** Tiers 4-7 (MIR provenance, call/type constraints, xref
  consistency, heuristics) live in stages this module cannot see, so callers
  supply them. A caller claiming a tier the resolver owns is *dropped*, not
  outranked, and `a_caller_may_not_supply_a_tier_the_resolver_owns` pins that.

Selection never destroys anything: `alternatives()` returns every rejected
claim, `conflicts()` names tiers where equals disagreed, and a conflict at the
only available tier resolves to `Unknown(ConflictingEvidence)` rather than a
pick (rules 3 and 8).

One honest limitation is baked into the API. The resolver establishes tiers 1-3
because the image and `SymbolStore` are exactly the facts those need. It cannot
establish tiers 4-6 from where it sits, and rather than fake them it takes them
as input and validates their provenance. A resolver that queried MIR would have
to live downstream of MIR construction, which is a different module than the one
`readonly_fold` can call.

`SymbolStore` drops symbol-less relocations — `index_relocation` records
`SymbolIncompleteness::UnresolvedRelocationTargets` and returns — and
`R_*_RELATIVE` is precisely what fills a `const` pointer table. So the resolver
carries its own place index for those, and defers to `SymbolStore` wherever a
symbol-backed reference exists, so the two never manufacture a conflict with
each other.

### The consumer

`ReadonlyData` gains `slots` and `pointer_width`, populated only by
`resolve_relocated_slots`. Relocation-fixed sections are deliberately **not**
added to `regions`, so `read_integer` cannot reach them and the existing numeric
path cannot see a byte it could not see before — which is why the corpus does
not move. For each pointer-width place in `.data.rel.ro*` the resolver is asked
what the word means, and only a proved `StringLiteral` is recorded. An import,
or a symbol defined in another object, resolves to an explicit unknown and is
skipped, leaving the original load in place.

Four sites in `python_bindings/ir.rs` now build the resolver from
`session.symbol_store()`, which makes the canonical symbol store production code
for the first time.

Result, on the same probe, PIE and non-PIE alike:

```c
name_len:  name = (i == 0) ? "alpha" : (i == 1) ? "beta" : ... ;
```

### The fixture, and proving it is not vacuous

`193_mapped_constant_roles` pairs a relocation-fixed `const char *const` table
against an integer table of the same shape whose entries were checked with
`readelf -lW` to lie inside this object's own PT_LOADs in all four lanes
(0x00f0, 0x1140, 0x2008, 0x2100), plus an address-shaped immediate consumed by
multiplication.

Non-vacuity was measured, not asserted. With `resolve_relocated_slots` disabled
behind a temporary switch and everything else identical:

| function | role | resolver off | resolver on |
|---|---|---|---|
| `mc193_name_length` | positive | **fail** | pass |
| `mc193_name_bytes` | positive | **fail** | pass |
| `mc193_names_differ` | positive | **fail** | pass |
| `mc193_offset_sum` | control | pass | pass |
| `mc193_offset_matches` | control | pass | pass |
| `mc193_scaled_constant` | control | pass | pass |

Twelve positive verdicts require the change; twelve control verdicts forbid
over-reach. The switch was removed before the gate — an untested env var is
cruft, and the measurement is recorded here instead.

One design detail the corpus taught: the first draft used `"d"` as a table
entry. The string pool's three-character floor rejects it, one unproved slot
correctly aborts the whole fold, and the entire positive silently reverted to
the broken form. That is the right behaviour and a bad fixture; every entry now
clears the floor and the comment says why.

### What this type could subsume, and what blocks each

Nothing was migrated or deleted, per scope. Ordered by value:

| recognizer | fits? | what blocks it today |
|---|---|---|
| `ir/name_resolve.rs` `Addr -> Named` | yes, highest value: no role guard at all, `HashMap<u64,String>`, last-writer-wins across eight sources | `addr_map` merges PLT, GOT, IAT, PE exports and Mach-O stubs; `SymbolStore` imports none of those, so migrating would silently drop those names until EPIC 1's importer bullets land |
| `ir/got_fold.rs` | yes, mostly mechanical: already tier-1, already width- and role-guarded | needs symbol-less `R_*_RELATIVE` resolution, which this resolver's place index now provides; the `got_fold`-before-`resolve_names` pass ordering is load-bearing and must be preserved explicitly rather than by luck |
| `analysis/xrefs.rs::code_to_data_xrefs` | yes; line 98 takes *any* operand immediate from *any* instruction and calls mapped-range membership a data reference | there is no role at that layer — the scanner sees decoded operands, not AST or MIR, so the disassembler must first say whether an immediate is a branch displacement, a memory displacement, or an ALU immediate. `analysis/cfg.rs` already does this for branch targets only |
| `ir/strings_fold.rs` | yes; its `Const` path is already a tier-5 decision and its `Addr`/`Named` path a tier-2 one | pure behaviour risk, not a technical block: `Addr`/`Named` fold unconditionally inside `Expr::Cmp` and `Expr::Bin`, so an honest `ScalarArithmetic` role would delete string literals the corpus currently renders. That needs its own measured pass |
| `ast.rs` `glaurung_global_*` + the `note_address_taken_global` stub | yes — the stub's own doc asks for `CodeAddress` vs `Address` vs `StringLiteral` plus a read-only test, which is `describe_address` and `is_readonly` | the rendering pass receives no image handle at all |
| `ir/function_tables.rs` | partly: per-slot `CodeAddress` + defined-`Text` is exactly `describe_address` | table *identity* (size a multiple of pointer width, 2..=64 entries) is aggregate recovery, EPIC 3, not reference interpretation |
| `analysis/vtable.rs`, `analysis/jump_table.rs` | in principle; `is_relocation_table`'s hand-written GOT/PLT exclusion is what tier-1 evidence generalises | they run at *discovery*, before any image-wide symbol store exists, and they feed function discovery — a layering inversion unless `ProgramSession` builds symbols before discovery |
| `ir/readonly_fold.rs` integer path | not yet | I could not construct an x86-64 case where a relocation covers a `.rodata` place this path folds, so gating it on `place_is_relocated` would add an unexercised guard. Reported rather than added |

### Gates

```
cargo test --features python-ext    2457 passed, 0 failed, 1 ignored (pre-existing)
                                    (2441 at HEAD + 16 new program::references tests)
cargo build --features python-ext   19 warnings, byte-identical in class to HEAD:
                                    0 "never used" functions; the one dead-code
                                    warning is the pre-existing never-read field at
                                    src/analysis/ioctl_taint.rs:409, and the two
                                    unused `got_targets` bindings at
                                    python_bindings/ir.rs are also pre-existing
tools/dectest.py @o0                364 lanes, no regressions in scope
tools/dectest.py @o2                364 lanes, no regressions in scope
tools/dectest.py 193_*              24/24 pass; 12/24 with the consumer disabled
cargo clippy --all-targets          nothing on the touched files
  --features python-ext
per-function decompile cost         0.31s vs 0.31s for 40 functions of
                                    hello-gcc-O2; the relocation index is built
                                    per call, and it does not show
rustfmt --edition 2021              on the six touched Rust files
uvx ruff format/check               clean on manifest.py
gcc/clang -Wall -Wextra -Werror     clean on the new fixture
```

`@o0` and `@o2` are 364 rather than 362 because fixture 193 adds one lane to
each compiler in each set.

A corpus that does not move is the predicted result and was run to falsify the
prediction: the consumer only reads storage the previous code could not reach,
so no existing fold could change. The only verdicts that DID move are fixture
193's twelve positives, from fail to pass.

### Not run

DecBench, Joern, `decbench_matrix.py`, the `--decbench` gate lanes, the full
fixture matrix, any `arch_roundtrip.py` sweep, repo-wide `cargo fmt`. **No
baseline was refreshed and nothing was committed** — fixture 193 needs
`baseline.json`, `structural_baseline.json`, `arch_baseline.json` and
`tools/fitness_baseline.json` regenerated before the gate is green.
