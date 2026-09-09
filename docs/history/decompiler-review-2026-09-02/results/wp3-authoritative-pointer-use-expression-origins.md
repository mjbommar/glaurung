# WP3 authoritative pointer-use expression origins

Commit `1cf04dd8` makes high-variable pointer refinement inspect direct callee
targets and forwarded register arguments through their semantic expression
views. Independent `Expr::Origin` carriers no longer hide either a catalog
contract such as `strcmp(const char *, ...)` or a recovered project-local
callee parameter type.

## Observed defect

The existing statement-origin test was strengthened so the call target and
forwarded argument carry separate origins. Before the repair, the recovered
callee contract no longer refined `arg0` to `int *`; its type was absent solely
because the argument was attributed. The repaired test passes. The catalog
test independently attributes `strcmp@plt`, its register argument, and its
literal argument, covering the target lookup side of the change.

## Focused evidence

All commands used `TMPDIR=/home/mjbommar/.cache/glaurung/tmp`.

```text
cargo test --features python-ext --lib \
  ir::high_variables::tests::attributed_authoritative_callee_refines_a_forwarded_argument \
  -- --exact
RED: expected Some(4), observed None
GREEN: 1 passed; 0 failed; 4,679 filtered out

cargo test --features python-ext --lib \
  ir::high_variables::tests::authoritative_call_parameter_refines_a_direct_function_argument \
  -- --exact
1 passed; 0 failed; 4,679 filtered out

cargo test --features python-ext --lib \
  ir::high_variables::tests::recovered_direct_callee_parameter_refines_a_forwarded_argument \
  -- --exact
1 passed; 0 failed; 4,679 filtered out

uv run maturin develop --release
finished release profile; editable wheel installed
```

The nearest real forwarding-caller test remains red on the repaired shared
snapshot:

```text
uv run --no-sync pytest \
  python/tests/test_decompiler_fixture_harness.py::test_real_direct_callee_pointer_type_refines_forwarding_caller_parameter -q
FAILED: emitted `forward_pointer(long arg0)` and `read_first((int *)(arg0))`
```

That production path reaches the call boundary but does not install the
authoritative parameter identity required by the focused test. It is an open
WP3 identity-projection defect and is not reported as success or attributed to
this positive-only consumer repair. No broad fixture or test sweep was run.
