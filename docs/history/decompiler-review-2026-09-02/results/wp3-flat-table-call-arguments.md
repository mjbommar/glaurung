# WP3 flat-CFG function-table call arguments

Status: bounded production migration landed in `a9001bd1` and `af320048` on
`master`.

## Result

Relocation-proven function-table calls now retain exact argument uses before
SSA, dead-store elimination, and control-flow structuring. A forward LLIR
analysis carries table-base and table-entry identities across basic-block
edges, joins them by exact agreement, invalidates caller-saved carriers at
calls, and annotates only an indirect call reached through one proven table.
The call receives the same complete, nested ABI-prefix contract already used
by AST reconstruction. Incomplete entry layouts, conflicting predecessors,
unrelated indirect calls, wrong-width loads, and non-table values decline.

Exact indirect inputs travel through `CallEffects.args`, which already owns
call liveness and SSA renaming. Lowering materialises those arguments only when
`args_are_exact`; convention-wide may-use registers remain liveness evidence
and do not become source arguments.

The adjacent tail-call control exposed a separate identity invalidation bug.
`EnclosingSlots` treated an ordinary compiler temporary as malformed ABI
storage and cleared every previously proven reaching argument. It now leaves
an all-nonphysical temporary alone while retaining the existing fail-closed
behavior for mixed or malformed physical-storage identities. This restores
the two-argument `dispatch_operation` tail call.

## Focused evidence

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  python_bindings::ir::callee_contracts::tests::flat_loop_table_call
1 passed; 0 failed

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  python_bindings::ir::callee_contracts::tests::incomplete_table_contract
1 passed; 0 failed

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  python_bindings::ir::callee_contracts::tests::conflicting_predecessor
1 passed; 0 failed

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib ir::call_args::tests
130 passed; 0 failed; 4,662 filtered out; 0.20 s
```

The exact detached verifier at `af320048` used a release extension with
SHA-256
`44f3cd6c90ad7ee5702c166bb3324c8e840c4d37ebcf0abb6b97be1f315b311e`.
Its scoped command was:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  UV_PROJECT_ENVIRONMENT=/home/mjbommar/.cache/glaurung/verify-85afee69/.venv \
  uv run --no-sync python tools/dectest.py \
  95_function_pointer_table:gcc:O2:fold_operations \
  95_function_pointer_table:gcc:O2:dispatch_operation \
  95_function_pointer_table:gcc:O0:dispatch_operation \
  191_indirect_table_args:gcc:O2:t191_fold --show
```

The selected host lanes report no regressions and one improvement:
`95_function_pointer_table:gcc:O2:fold_operations` moves from fail to pass.
Its recovered call is now
`OPERATIONS[which](accumulator, index + 1)` in semantic terms and executes
equivalently under the round-trip harness. Both GCC dispatch controls remain
green.

## Remaining boundary

This is not universal indirect-call recovery. The larger
`191_indirect_table_args:gcc:O2:t191_fold` control remains red: it currently
recovers only the first of three table-call arguments. That fixture is the
next measured extension for compound table-base/value transport and
loop-carried multi-slot argument identity. No DecBench or Joern run was made.

The complete Python post-source-commit gate is recorded separately when it
terminates; it is not implied by the focused evidence above.
