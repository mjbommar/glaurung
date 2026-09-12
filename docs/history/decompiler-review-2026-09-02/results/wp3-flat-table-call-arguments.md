# WP3 flat-CFG function-table call arguments

Status: bounded production migration landed through `6bcff0c2` on `master`.

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

## Cross-architecture affine-address closure

Commits `0ff541e3` and `6bcff0c2` close the AArch64 address-materialisation
boundary exposed by the first cross-architecture slice. AArch64 commonly
forms the table address as `ADRP(page)` followed by `ADD(page_offset)`, and may
then use the same register as both load base and load destination. The original
proof recognized only a directly materialised final table VA and killed the
destination before reading that in-place load's base.

Demand discovery now follows checked `Addr/Const +/- constant` facts within a
straight-line block. The semantic pre-SSA proof carries the same checked facts
across CFG edges using exact-agreement joins, reads every instruction's inputs
before invalidating its output, and recognizes only pointer-width indexed or
aligned in-bounds fixed loads from one complete relocation-proven table.
Unknown arithmetic, overflow, conflicting predecessors, wrong scales and
sizes, segmented loads, and incomplete entry contracts still decline.

The focused Rust evidence was:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  python_bindings::ir::callee_contracts::tests
16 passed; 0 failed; 4,782 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib ir::function_tables::tests
16 passed; 0 failed; 4,781 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib ir::call_args::tests
131 passed; 0 failed; 4,666 filtered out
```

The exact detached verifier at `6bcff0c2` used a release extension with
SHA-256
`9827203abf7666182ad5904d5fb06c2cb7fdf8aaeb51c065eea8a11664e48b84`.
The bounded integration command was:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  UV_PROJECT_ENVIRONMENT=/home/mjbommar/.cache/glaurung/verify-85afee69/.venv \
  uv run --no-sync python tools/dectest.py \
  95_function_pointer_table 191_indirect_table_args \
  --arch i386 --arch armv7 --arch armv7_a32 --arch aarch64 \
  --arch x86_64 --arch x86_64_gcc15 --full --jobs 6
```

All 24 selected architecture/optimisation lanes completed with no attributable
regression. Seven function verdicts improve from fail to pass:

- AArch64 O2: `t191_dispatch`, `t191_fold`, and `fold_operations`;
- x86-64 O2: `t191_fold` and `fold_operations`;
- x86-64 GCC 15 O2: `t191_fold` and `fold_operations`.

The exact AArch64 dispatch now retains the complete three-input table contract,
equivalent to `T191_OPS[which](scratch, a, b)`. These seven
`arch_baseline.json` entries are ratcheted. Remaining failures in this bounded
fixture family are ARMv7/ARMv7-A32 O2 call/structure cells and i386 O2
`dispatch_operation`/`t191_fold`; they are not regressions from this increment.

## Remaining boundary

This is not universal indirect-call recovery. It covers relocation-proven local
tables whose complete entry layouts form a valid ABI prefix; writable,
incomplete, disagreeing, non-relocated, and unassociated indirect targets still
decline. The next table-call work is the corpus query for remaining
zero/partial-argument table calls, followed by the distinct ARMv7 and i386 O2
encodings found by the bounded matrix. No DecBench or Joern run was made.

The complete Python post-source-commit gate was attempted at the preceding
`af320048` source revision. By 9% it had reproduced three unrelated existing
build-configuration failures: the static-executable stack-canary `local_10`
defect and the static/frame-pointer undefined-`rbp` defects. It was interrupted
after `87dc4167` made that run obsolete. No broad-green claim is made.

A fresh post-source gate was also started from exact documentation revision
`070f2487`. It reached 19% before being stopped because it had already
reproduced 16 failures outside fixtures 95 and 191, including the same
stack-canary/frame-pointer defects and existing CLI, architecture, and
curriculum failures. The separately rerun baseline-integrity test fails only on
pre-existing control mismatches in fixtures 157, 172, and 81; none is one of
the seven entries ratcheted here. This run is partial evidence, not a complete
gate and not a broad-green claim.
