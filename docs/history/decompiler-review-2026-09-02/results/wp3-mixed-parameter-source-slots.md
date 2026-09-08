# WP3 mixed-parameter source slots

Commit `02376480` repairs source-parameter identity after mixed ABI-bank
projection. AAPCS hard-float can place source `arg0` in `s0` while placing
source `arg1` in core register `r0`. SSA correctly records `r0` as core-bank
machine slot zero, and prototype recovery correctly names it source slot one,
but role projection previously merged those meanings. The rendered `arg1`
therefore carried slot zero, so the signature exposed only `arg0` and then
declared and read an uninitialized local `arg1` in the body.

`ValueIdentities::with_source_parameter_slots` now installs the prototype's
source-role slots after raw-to-role projection. These facts are authoritative
for the already-named `argN` roles and replace stale bank-local slots rather
than unioning them into ambiguity. Both production identity projections apply
the source slots: the temporary sidecar used by post-naming AST passes and the
final prepared-AST sidecar used by declaration planning and rendering. Raw
machine identities retain their original bank-slot facts.

The focused identity contract was observed red before implementation because
the API did not exist. It proves that raw `r0` remains machine slot zero while
its mixed-bank role `arg1` becomes source slot one. Focused validation used:

```text
cargo test --features python-ext --lib ir::value_number::tests::
60 passed; 0 failed; 4,606 unrelated library tests filtered out

cargo test --features python-ext --lib identifier_census_
3 passed; 0 failed; 4,663 unrelated library tests filtered out
```

The defect was reproduced from a clean isolated build of pushed commit
`7d7660bb`, excluding every shared-worktree edit. After `uv run maturin develop`,
a strict current-tree A/B reversed only `src/ir/value_number.rs` and
`src/python_bindings/ir/pipeline.rs`:

```text
uv run python tools/dectest.py \
  172_float_double_widths:armv7:O0:accumulate_narrow \
  --full --show --allow-stale

parent: fail -- float accumulate_narrow(float arg0), local int arg1 is uninitialized
tip:    pass -- both float arg0 and int arg1 are signature parameters
```

The directly relevant blast radius also improved without additions:

```text
uv run python tools/dectest.py @vector-float --arch armv7 \
  --full --jobs 4 --allow-stale

16 binary lanes selected
baseline regressions: 3 -> 2
removed: 172_float_double_widths:armv7:O0:accumulate_narrow
added: 0
```

An isolated archive of `02376480` records 5,195 declared Rust tests, 2,488 in
`ir`, and zero outside every gate; all six census checks pass after committing
the generated baseline inside that archive. Concurrent uncommitted tests were
not included.

No broad suite, full fixture corpus, DecBench, or Joern ran. This closes one
WP3 identity handoff and one real mixed-hard-float regression; it does not
complete the wider SSA migration or the remaining ARMv7 float failures.
