# WP3 verification and pointer-reader origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `c6a42332` migrates two final-AST readers that directly protect emitted
source quality:

- `src/ir/verify_defs.rs` now sees attributed labels, gotos, reads,
  definitions, frame-pointer address uses, and explicit poison throughout its
  structured and goto-aware analyses;
- `src/ir/high_variables.rs` now sees attributed calls when refining a
  forwarded source argument from an authoritative callee parameter type.

The change does not weaken either proof. Goto-aware definedness still declines
malformed label graphs, and pointer refinement still requires its existing
trusted contract, exact-copy, compatible-width, and safe-use conditions.

## Focused evidence

Both new cases were observed red before repair:

```text
attributed_goto_flow_still_reports_an_unreachable_definition
attributed_authoritative_callee_refines_a_forwarded_argument
```

The complete touched modules pass:

```text
cargo test --features python-ext ir::verify_defs::tests --lib -- --nocapture
39 passed; 0 failed

cargo test --features python-ext ir::high_variables::tests --lib -- --nocapture
27 passed; 0 failed
```

After a release extension rebuild, the exact eight architecture/optimization
cells for the declaration/use invariant are green:

```text
uv run pytest -q \
  python/tests/test_decompiler_emission_invariants.py::test_every_local_used_is_also_declared
8 passed
```

No broad suite was started for this increment.

## Next action

Continue the enabled-reader audit with canonical local naming and the
architecture-specific prologue consumers. Keep each proof's existing refusal
boundary and validate only its module plus the directly affected fixture cells.
