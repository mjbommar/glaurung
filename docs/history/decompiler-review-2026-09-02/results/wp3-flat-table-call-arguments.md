# WP3 flat-CFG function-table call arguments

Status: bounded production migration landed in `a9001bd1`, `af320048`, and
`87dc4167` on `master`.

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

Finally, AST argument reconstruction now treats a nonempty argument list from
an earlier semantic stage as authoritative. Its local backward scan cannot
replace the exact three-argument LLIR contract with the one adjacent register
assignment it happens to see after structuring. This closes the larger fixture
191 loop without special-casing that fixture or its function names.

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
131 passed; 0 failed; 4,662 filtered out; 0.19 s
```

The final exact detached verifier at `87dc4167` used a release extension with
SHA-256
`0f00942078adaf229352e8e04542e0c32106bec75595d0c2d2e41675dbcc5b73`.
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

The first exact source revision reports no regressions and one improvement:
`95_function_pointer_table:gcc:O2:fold_operations` moves from fail to pass. Its
recovered call is now
`OPERATIONS[which](accumulator, index + 1)` in semantic terms and executes
equivalently under the round-trip harness. Both GCC dispatch controls remain
green. The final exact revision then reports the independent
`191_indirect_table_args:gcc:O2:t191_fold` cell improving from fail to pass,
with all three arguments `(scratch, accumulator, index + 1)` retained and no
regression in the same scoped controls.

After ratcheting both baseline entries, the same selection at documentation
commit `2411d01b` reports no regressions and no pending improvements against
the unchanged exact release extension.

## Remaining boundary

This is not universal indirect-call recovery. It covers relocation-proven local
tables whose complete entry layouts form a valid ABI prefix; writable,
incomplete, disagreeing, non-relocated, and unassociated indirect targets still
decline. The next table-call work is cross-architecture fixture coverage and a
corpus query for remaining zero/partial-argument table calls. No DecBench or
Joern run was made.

The complete Python post-source-commit gate was attempted at the preceding
`af320048` source revision. By 9% it had reproduced three unrelated existing
build-configuration failures: the static-executable stack-canary `local_10`
defect and the static/frame-pointer undefined-`rbp` defects. It was interrupted
after `87dc4167` made that run obsolete. No broad-green claim is made.
