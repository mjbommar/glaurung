# WP3 typed-call select expression origins

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `c504e5f8` makes the typed call-argument renderer recognize a select
through an expression-origin carrier. Its authoritative parameter conversion
therefore remains on each conditional arm, where C type-checks it, instead of
moving outside a machine-word reconstruction of the whole select.

No parameter inference changes. The callee's exact prototype still chooses the
destination type, pointer/integer arm conversion remains explicit, and the
conditional retains lazy evaluation.

## Focused TDD

The new contract renders one authoritative `void *` call with a mixed stack-
address/integer select, first plain and then with an `OriginSet` around the
select. Before the repair, the attributed form changed from:

```text
consume_pointer((zf_0 ? &local_16[0] : (void *)(7)));
```

to the noisier representation round trip:

```text
consume_pointer((void *)((zf_0 ? (long)(&local_16[0]) : 7)));
```

After changing only the select reader to use the semantic view, the two renders
are byte-identical. Focused results:

```text
attributed_typed_call_select_is_render_byte_neutral: pass
declared_pointer_call_keeps_parameter_types_when_result_needs_conversion: pass
decbench_casted_select_converts_pointer_and_integer_arms_before_selection: pass
```

Each command selected exactly one Rust test with 4,677 unrelated tests filtered
out.

## Release real-binary evidence

After `uv run maturin develop --release`, the nearest compiled guarded-call
select witness passes:

```text
uv run --no-sync pytest \
  python/tests/test_decompiler_guarded_call.py::test_guarded_call_select_retains_both_value_edges -q
1 passed
```

The release extension included unrelated concurrent Rust edits in the shared
worktree, so this is scoped regression evidence rather than a clean-tip
performance measurement.

## Scope

This closes one bounded WP3 typed-call renderer consumer. It does not alter
call contracts, pointer inference, select construction, or universal
expression attribution.
