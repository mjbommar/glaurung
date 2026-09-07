# WP3 output-value origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `025937a7` closes seven statement-origin omissions across four related
output-value consumers:

- `src/ir/direct_output.rs` now sees attributed promoted return slots, void
  result-save bridges, and returns whose machine value must be cleared. It
  removes the same semantic statements as before while retaining the owner of
  an in-place return rewrite.
- `src/ir/caller_arity.rs` now derives fixed arity from attributed balanced
  SysV stack-call sequences.
- `src/ir/ast/param_spills.rs` now recognizes, rewrites, and removes
  attributed named and frame-object parameter homes without dropping the
  owner of the surviving return.
- `src/ir/value_split.rs` now sees attributed wide definitions when deciding
  whether one ABI register has distinct parameter and result lifetimes.

These repairs prevent provenance from reintroducing invented locals, stale
return values, pointer-host truncation, under-arity declarations, or conflated
wide result storage.

## Focused TDD

All seven cases were observed red before their corresponding repair:

```text
attributed_unread_promoted_return_slot_is_removed
attributed_void_result_save_restore_is_removed
attributed_return_value_is_cleared_without_losing_its_owner
attributed_stack_call_sequence_keeps_its_arity_evidence
attributed_named_parameter_home_is_coalesced
attributed_frame_object_parameter_home_is_coalesced
attributed_wider_definition_remains_role_split_evidence
```

The focused Rust results at the completed source state are:

```text
cargo test --features python-ext attributed_ --lib -- --nocapture
62 passed; 0 failed; 4,259 filtered out; 0.23 s test execution

direct_output module: 13 passed
caller_arity module: 3 passed
value_split module: 10 passed
param_spill filter: 2 passed
```

## Release real-binary evidence

The release extension was rebuilt after the final Rust edit. The host
call-shape fixture and two architecture-sensitive Python checks pass:

```text
uv run python tools/dectest.py 11_call_shapes --full --jobs 4
52 functions passed across GCC/Clang O0/O2; 6.99 s

uv run pytest -q \
  python/tests/test_decompiler_arch_roundtrip.py::test_aarch64_o0_distinct_call_result_types_round_trip \
  python/tests/test_decompiler_arm_frame_spills.py
2 passed; 1.80 s
```

## Boundary discovered by the wildcard audit

The remaining raw consumers are not all equivalent. Reader-only and in-place
rewrites can use `Stmt::semantic()` or `semantic_mut()` directly, as this
increment does. `src/ir/callee_return_bank.rs` and related result-composition
paths instead insert stores, replace returns, and may copy structured paths.
They must not be migrated by mechanically unwrapping statements: the plan's
fold, hoist, and duplication ownership policy must be explicit first so every
synthesized statement receives the correct deterministic origin set.

## Broad gates

The fast tier completed after the source commit:

```text
uv run pytest python/tests/ -m 'core and not decbench' -n auto
2,756 passed; 60 failed; 43 skipped; 13 xfailed; 3:07
```

The extended tier also completed:

```text
uv run pytest python/tests/ -m 'not core and not fixtures and not decbench' -n auto
1,394 passed; 43 failed; 33 skipped; 2 xfailed; 8:04
```

The shared checkout is not at a green repository baseline: both failure sets
includes the concurrent source-semantics dialect/fitness/generated-reference
work, stale history and test-census ledgers, and already-recorded decompiler
ratchets. None of the seven new focused tests failed, and both directly
affected release checks pass. This result is evidence of the current branch
state, not a green claim and not yet an isolated parent/tip attribution. The
extended tail was real work rather than a hang: its Docker-backed fixture
compilations rotated through distinct fixtures before reaching the terminal
summary.

Parallel pytest disables timing measurements from `pytest-benchmark`;
performance evidence remains a separate serial gate.

## Next ordered increment

Finish classifying the remaining wildcard sites into transparent readers,
in-place rewrites, folds, hoists, and duplication. Define and test the latter
three ownership contracts in `src/ir/ast/origin.rs`, then migrate
`callee_return_bank` and the related result-composition surface before starting
expression ownership. Do not assign synthesized owners ad hoc.
