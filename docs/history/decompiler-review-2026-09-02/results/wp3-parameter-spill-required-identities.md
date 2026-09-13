# WP3 parameter spills require identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `aa342508` removes display-name authority from parameter-home
coalescing. Named promoted homes, immutable frame homes, source parameters,
straight-line aliases, and the store-to-assignment conversion now require the
pipeline-owned `ValueIdentities` sidecar. In particular, `local_N` no longer
proves promoted storage and `argN` no longer proves a parameter slot.

The generic no-sidecar preparation API now declines parameter-home coalescing
instead of guessing. Tests that require the optimization call the preparation
pipeline with explicit parameter, promoted-object, and SSA value identities.
This keeps compatibility rendering safe while preserving the optimization in
the real decompiler pipeline, which already owns the sidecar.

## Red/green evidence

When no-sidecar preparation first stopped guessing, the two positive
preparation contracts remained uncoalesced and failed as expected. The casted
i386 pointer-home control also remained unprocessed. After moving those
contracts onto explicit identities:

```text
ir::ast::param_spills::tests: 8 passed, 0 failed
ir::ast::tests::prepare_*:    20 passed, 0 failed
parameter_home_exposed_by_folding_is_coalesced_after_copy_fixpoint: pass
a_cast_pointer_spill_does_not_turn_a_pointee_store_into_home_assignment: pass
```

After a fresh release build, `tools/build_guard.py` reported fresh with native
SHA-256 `5b483b198005adbe60472654dcec1b8879aad530c7c74a826041d0b191498a2c`.
Three directly owning binary checks passed:

```text
test_real_stripped_x86_word_parameter_home_recovers_short
test_real_arm32_byte_spills_recover_narrow_parameters
test_real_arm_hard_float_call_round_trip
```

No broad Rust, Python, fixture, DecBench, or Joern suite ran.

## Scope

This closes the prepared-AST parameter-spill consumer's dependence on display
names. The generic preparation API still has other optional-sidecar passes;
declaration planning, naming, copy propagation, and universal origin coverage
remain WP3 work.
