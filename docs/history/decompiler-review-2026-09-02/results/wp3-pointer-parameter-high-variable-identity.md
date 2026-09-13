# WP3 pointer-parameter identity preservation

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `0ae50561` fixes a real identity-handoff regression between recovered
prototype types and prepared-AST high-variable refinement. The initial
declaration map correctly recovered `arg0` and `arg1` as byte pointers, but
`refine_pointer_high_variables_with_identities` cleared every pointer-like fact
with an exact SSA identity. That rule was intended to discard stale speculative
`varN` classifications; it also discarded prototype-qualified source
parameters and could not reconstruct pointer evidence learned before value
numbering.

The cleanup now excludes values carrying an authoritative parameter slot.
Local `varN` pointer guesses still undergo the existing definition/use
revalidation and ambiguous identities still fail closed.

## Red and green evidence

The new focused unit contract was observed red before the repair:

```text
cargo test --features python-ext \
  ir::high_variables::tests::recovered_pointer_parameter_survives_high_variable_revalidation \
  --lib -- --exact --test-threads=1
FAILED: expected Pointer { pointee_width: 1 }, got None
```

After the repair:

```text
cargo test --features python-ext ir::high_variables::tests:: \
  --lib -- --test-threads=1
39 passed; 0 failed; 4807 filtered out

uv run pytest -q python/tests/test_decompiler_observable_parameter_width.py -x
3 passed

uv run pytest -q python/tests/test_decompiler_declaration_authority.py \
  python/tests/test_decompiler_return_reaching_definitions.py -x
7 passed

cargo check --features python-ext
pass

uv run python tools/dectest.py @smoke \
  --arch i386 --arch armv7 --arch aarch64 --arch x86_64_gcc15
SCOPED: 16 lanes of 3304 (0%) -- no regressions in scope
```

The motivating stripped GCC `-O2` fixture now renders
`byte_only(char *arg0, char *arg1, signed char arg2)` again. Its Python test
recompiles the emitted C and compares execution for four byte-string cases;
the adjacent `full_word` control proves a genuinely wide parameter is not
narrowed.

A fresh native extension passed `tools/build_guard.py`. The required
whole-Python fail-fast gate passed every earlier test and stopped at 17% on the
existing committed `arch_baseline.json` versus `baseline.json` disagreement
for fixtures 157, 172, and 81. This commit changes neither ledger.

This advances WP3's exact parameter-role handoff and restores visible type
quality. It does not complete WP3's remaining semantic-reader audit,
invalidation, or origin coverage, nor WP6's general constraint solver.
