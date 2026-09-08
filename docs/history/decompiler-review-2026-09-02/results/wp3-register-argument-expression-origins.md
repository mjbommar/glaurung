# WP3 register-argument expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `fb878925` adds per-argument expression attribution to the generic
register-ABI backward scan in `src/ir/call_args/fold_one_call.rs`.

When the scan consumes `arg_register = value` setup, the call argument now
owns that setup instruction. Distinct arguments retain distinct owners rather
than receiving the call statement's blanket union. When a captured argument
is resolved through an earlier scratch-register definition, that older owner
is composed into the argument expression as well.

Purity, alias, stack-coordinate phase, reassignment, liveness, contiguous-
prefix, and call-barrier decisions continue to inspect the original semantic
source. Attribution is attached only to the clone that the scan actually
captures or substitutes.

This is a bounded generic-register slice. Stack-argument stores, recovered
layout folds, cdecl32, AAPCS, hard-float, and table-call specializations remain
separate producer migrations. It does not complete call-argument attribution
or WP3.

## Observed-red evidence

The existing attributed setup test was strengthened from one argument and a
call-level union to two arguments with disjoint setup owners. It was observed
red because both argument expressions reported no origin. A second test proves
composition through an earlier scratch definition.

The complete parent call-argument module passes:

```text
cargo test --features python-ext 'ir::call_args::tests::' --lib
110 passed; 0 failed
```

The required release extension rebuild completed in 35.12 seconds. The
dedicated call-shapes fixture is exactly neutral before and after the change:

```text
uv run python tools/dectest.py 11_call_shapes --jobs 4 --full
4 lanes, 52 functions, all passed; no scoped regressions
```

The pre-change run used the deliberately stale prior release extension and was
labeled as such by the harness. The post-change run used a fresh extension with
SHA-256 `a823733968bf94862e621754a0d3ae8a664db320aebf84870e2375b1cdc89831`.

No full Rust, Python, architecture, fixture, or DecBench sweep was run at this
bounded iteration boundary.

## Next boundary

Add exact expression ownership for stack arguments captured by the generic
SysV/AAPCS area proofs, distinguishing the store that supplies the argument
value from stack-allocation, padding, and cleanup instructions that belong only
to the call statement. Then migrate recovered-layout and architecture-specific
folders without weakening their existing proofs.
