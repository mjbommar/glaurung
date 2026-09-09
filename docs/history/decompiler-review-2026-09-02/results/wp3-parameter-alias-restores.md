# WP3 immutable parameter-home restores

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `9f04c1a1` fixes the reaching-definition refusal that kept an ARM O0
hard-float parameter spill alive after its expression-origin migration. An
exact `arg = home` copy restores one proven alias from the other; it does not
destroy their equality and therefore is not an independent write for the
reverse interference query.

The change is deliberately narrow. A different value assigned to the argument
still records a write, subsequent reads still block unsafe substitution, and
unstructured control flow uses the same exact-restore exception while retaining
its existing fail-closed behavior. The named parameter-home pass can therefore
rename the immutable home to the source argument and delete the resulting
self-assignment.

This is one completed WP3 consumer repair, not completion of stable identity or
universal origin attribution.

## Observed-red and focused verification

Two contracts were observed red before the implementation:

- `restoring_an_argument_from_its_home_is_not_a_conflicting_write` showed that
  structured reaching incorrectly called an exact restorative copy a clobber.
- `parameter_restore_from_immutable_home_does_not_block_coalescing` showed the
  consequence at the consumer: the parameter store survived and the return
  continued to read the synthetic local.

After the repair:

```text
cargo test --features python-ext --lib ir::structured_reaching::tests:: --quiet
9 passed; 0 failed; 4,705 filtered out

cargo test --features python-ext --lib ir::ast::param_spills::tests:: --quiet
6 passed; 0 failed; 4,708 filtered out
```

Filtered tests were not executed.

## Exact-release fixture checkpoint

A clean detached worktree at exact commit `9f04c1a1` was built with:

```text
uv sync --locked --dev
uv run maturin develop --release
```

The single owning real-binary check then passed:

```text
uv run pytest \
  python/tests/test_cli_decompile.py::test_real_arm_hard_float_call_round_trip -q
1 passed
```

This fixture compiles and decompiles the real ARM hard-float caller, requires
the recovered call to use `arm_hf_callee(x, y)`, recompiles the pseudocode, and
checks runtime behavior. It is evidence that the redundant `local_c` and
integer/float union spill path is gone for this capability.

No broad Rust, Python, fixture, architecture, DecBench, or Joern suite was run.

## Next boundary

Continue WP3 one identity consumer at a time. Prefer the next concrete
real-fixture failure with a traceable spelling-based refusal; retain exact
observed-red unit coverage and one owning release fixture instead of widening
the test surface prematurely.
