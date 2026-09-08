# WP3 call-contract consumer expression origins

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `6bb026a1` makes the three remaining direct call-contract consumers
transparent to expression-origin carriers:

- catalog application recognizes an attributed direct target before capping a
  fixed-arity argument list or removing an impossible result destination;
- recovered local-callee prototypes match their direct target VA through an
  origin carrier; and
- opaque nominal parameter refinement recognizes both attributed named callees
  and attributed register arguments.

The authority rules are unchanged. Catalog and recovered definition-site
evidence still outrank caller liveness guesses, opaque nominal types require one
unambiguous authoritative library use, and unknown or indirect targets still
decline.

## Focused TDD

The existing statement-origin test was strengthened with an independently
attributed `__stack_chk_fail` target. Before the repair, catalog application
missed that target and retained an impossible result destination. The exact
contract was observed red at:

```text
assertion failed: matches!(function.body[0].semantic(),
    Stmt::Call { dst: None, .. })
```

The recovered local-void test and typed opaque-parameter-role test were then
strengthened with target and argument origins as follow-on contracts. After the
batched repair:

```text
origin_wrapped_void_call_drops_its_impossible_destination: pass
recovered_void_callee_removes_the_impossible_result_destination: pass
opaque_parameter_refinement_uses_typed_parameter_roles: pass

cargo test --features python-ext --lib ir::call_contracts::tests -- --nocapture
25 passed; 0 failed; 4,652 filtered out; 0.27 s test execution
```

## Release evidence and scope

`uv run maturin develop --release` completed successfully. No broad fixture
matrix was run for these metadata consumers; their behavior is owned directly
by the focused catalog, local-callee, and identity-backed refinement tests.

This closes the remaining raw direct-target matches in `call_contracts.rs`.
It does not add new prototype evidence, weaken indirect-call refusals, or
complete universal WP3 expression attribution.
