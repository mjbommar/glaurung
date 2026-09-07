# WP3 vector-copy origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `02b0da5c` makes the enabled packed-vector transport consumer transparent
to statement origins. Attributed four-lane loads and stores now rejoin into the
same 128-bit operations as unattributed statements, nested attributed control
owners remain intact, and each synthesized operation receives the deterministic
union of the instructions it replaces. When a proved-dead scalar-view bridge is
removed, its origin joins the recovered wide load rather than disappearing.

This closes one bounded omission from the WP3 wildcard-consumer audit. It does
not add expression origins, define non-contiguous source-line rendering, or
complete authoritative SSA consumer migration.

## TDD and correctness boundary

Two attributed tests were observed red before the production migration:

- a scalar-view bridge was removed but its instruction owner was lost; and
- an attributed transport nested in an attributed `if` remained as eight lane
  statements because raw statement matching hid both the owner and its children.

The nested test also exposed a pre-existing safety-accounting defect:
`stmt_reads` already traverses structured children, while the vector pass
recursed over those children a second time. A single nested consumer was counted
twice and falsely rejected. The replacement counter walks each semantic
statement exactly once. A new two-destination nested control proves that two
real consumers are still counted separately and therefore still block the
unsafe rejoin.

The transport proof remains exact: four adjacent dword lanes, one wide-register
identity, one consuming store batch, and no additional lane consumer. Origin
transparency does not relax any of those requirements.

## Evidence

Focused Rust coverage:

```text
cargo test --features python-ext vector_copy::tests -- --nocapture
8 passed; 0 failed
```

Release build and complete stripped/debug differential:

```text
uv run maturin develop --release
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 17 improvements; 0 infrastructure problems
```

That result is exactly neutral against the preceding indirect-result boundary.

The complete Rust gate is green:

```text
cargo test --features python-ext
library: 4,266 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The mandatory post-commit whole Python suite completed red in 46 minutes 22
seconds:

```text
221 failed; 4,584 passed; 77 skipped; 128 deselected; 876 xfailed
```

After normalizing pytest's final summary suffix, its 221 failing-node set is
exactly identical to the preceding indirect-result run: zero added and zero
removed nodes. The reported undeclared-local regression is not present in
either run, and the focused eight-cell invariant confirms the current release
build directly:

```text
uv run pytest python/tests/test_decompiler_emission_invariants.py::test_every_local_used_is_also_declared -q
8 passed
```

The older eight-cell `stack_3` / `local_c` report came from a 2026-09-05 log and
is not a current open regression.

## Next ordered increment

Continue the enabled wildcard audit in `src/ir/select_fold.rs`. Boolean-mask
folding is already origin-transparent, but guarded-select return recovery,
created-select return folding, diamond recognition, and synthesized statements
still inspect or replace raw nodes. Preserve exact origin unions without
weakening purity, immediate-return, promoted-local, or same-destination proofs.
