# WP3 call-analysis origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `82a95253` closes six related statement-origin omissions as one bounded
WP3 batch. The call-analysis pipeline now sees through origin carriers when it:

- inventories register names used to identify a function's live-in values;
- decides whether a call's ABI result is consumed and attaches its destination;
- rejects frame-load substitution across an aliasing store;
- advances enclosing blocked-slot and exact reaching-definition state;
- forwards a prototype-proven SysV `xmm0:xmm1` result; and
- proves variadic arity from a literal `printf`-family format.

Mutations use the semantic statement in place, so the original statement
carrier remains attached. Recognition boundaries are otherwise unchanged.
This increment deliberately batches one cohesive family instead of paying the
whole-repository validation cost after each small reader migration.

## Focused TDD and module evidence

Six tests were independently observed red before their production changes:

```text
an_origin_wrapped_consumed_call_result_is_attributed_in_place
sysv_origin_wrapped_aliasing_store_blocks_frame_load_substitution
origin_wrappers_do_not_hide_register_names_from_call_recovery
origin_wrappers_do_not_hide_enclosing_reaching_definitions
origin_wrapped_sysv_sse_pair_result_still_forwards
origin_wrapped_printf_call_keeps_format_proven_argument
```

The completed batch passes the full local module and the cross-module origin
slice:

```text
cargo test --features python-ext ir::call_args::tests --lib --quiet
109 passed; 0 failed

cargo test --features python-ext origin --lib --quiet
54 passed; 0 failed
```

Formatting and patch-integrity checks pass for all five changed files.

## Release fixture evidence

After `uv run maturin develop --release`, the call-focused debug comparison
covered 16 lanes across fixtures 11, 81, 113, and 195. It reports five current
baseline regressions:

```text
11_call_shapes:clang:O2:call_fold_wide_result
195_by_value_aggregates:{clang,gcc}:{O0,O2}:bv195_make_mixed
```

These are not attributable to this batch. A release rebuild with every
production change in this commit reversed reproduces identical decompiled C
and the same failure for `call_fold_wide_result`. The four `bv195_make_mixed`
cells already have an independent parent/tip A/B in the preceding pair-return
record and arise in the separate SplitBanks path.

The stripped comparison over the same four fixture groups reports eight
existing aggregate-return divergences and zero infrastructure problems.

## Broad gates

The complete Rust gate passes:

```text
cargo test --features python-ext
library: 4,297 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The 109 call-analysis tests themselves complete in 0.20 seconds. The broad
Rust gate's identity-retrieval target takes 529 seconds, which is why it is
retained as a once-per-batch integration gate rather than an inner-loop gate.

The mandatory whole-Python post-commit gate improves the accepted boundary by
two exact nodes with no additions:

```text
uv run pytest python/tests/
209 failed; 4,596 passed; 77 skipped; 128 deselected; 876 xfailed
failure-set delta: 0 added; 2 removed
```

The removed tests are:

```text
test_aarch64_optimized_indirect_tail_dispatch_round_trips
test_optimized_tail_dispatch_recovers_portable_local_function_table
```

A focused release parent/tip A/B proves both removals belong to this commit.
With the batch present both tests pass. With only this commit's production
changes reversed, both fail: the attributed indirect table call loses its
result destination, the output returns an uninitialized `ret`, and native
execution returns 100 where the original returns 0.

## Next ordered increment

The enabled semantic-consumer audit selects `src/ir/lazy_call_select.rs` as the
next cohesive WP3 family. It is active in both AST preparation and the DecBench
renderer path, and its result inventory, recursion, adjacent folding, goto
census, diamond matching, and replacement construction still inspect raw
statements. Migrate those surfaces and their consumed-origin unions together.
Keep stack promotion and SplitBanks work isolated from concurrent lanes; do not
treat their current fixture failures as authority to broaden this origin-only
batch.
