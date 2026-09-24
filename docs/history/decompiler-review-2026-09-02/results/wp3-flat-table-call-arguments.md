# WP3 flat-CFG function-table call arguments

> **Kind:** record · **Date:** 2026-09-12

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
decline. The fixture-corpus zero/partial-argument query is complete for the host
GCC/Clang O0/O2 population. A source census found six static function-table
families: fixtures 08, 95, 131, 148, 150, and 191. The bounded command was:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  UV_PROJECT_ENVIRONMENT=/home/mjbommar/.cache/glaurung/verify-85afee69/.venv \
  uv run --no-sync python tools/dectest.py \
  08_indirect_dispatch 95_function_pointer_table \
  131_obfuscated_composite 148_dispatch_obfuscation \
  150_obfuscation_composite 191_indirect_table_args \
  --full --show --jobs 8
```

All 24 selected compiler/optimisation lanes completed. Every table-call
function that passes execution necessarily consumes its behaviorally checked
inputs, including fixture 191's explicit argument-witness slots. Manual review
of every failing function that still emits a table call found the complete
source arity: one argument for fixture 131, two for fixtures 148 and 150, and
no zero/partial call. Fixture 150 Clang O0 emits no table call because its
surrounding state-machine switch remains an unrecovered indirect jump; that is
a WP5 control-recovery gap, not a partial-argument call.

The sweep reports one apparent regression,
`131_obfuscated_composite:clang:O0:obfuscated_pipeline`, and three apparent
improvements. An exact release A/B at parent `0c36651c` reproduces the same
fixture-131 failure and identical one-argument call, proving it is not
attributable to the affine-address increment. The other baseline movements are
likewise already present at the parent and are not ratcheted as evidence for
this work.

The next table-call work is therefore the distinct ARMv7 and i386 O2 encodings
found by the architecture matrix. No DecBench or Joern run was made.

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

## i386 cdecl closure

Commit `d06d2d59` closes the terminal i386 table-dispatch case. GCC O2 writes
its two outgoing cdecl arguments above one saved-register slot, restores that
slot and `esp`, and then jumps through `OPERATIONS[which]`. The cdecl scanner
now crosses only that exact balanced epilogue: one pointer-width restore,
`esp += 4`, a relocation-proven terminal table call, and the pass-owned
`return rax` sentinel. Unknown widths, non-table calls, and non-adjacent shapes
still decline. The release output changes from a zero-argument call to:

```c
return ((long (*)(long, long))(OPERATIONS[var3]))(var4, var5);
```

The observed-red positive test, two refusal tests, all 161 `call_args` tests,
and this exact i386 O0/O2 selection pass:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  UV_PROJECT_ENVIRONMENT=/home/mjbommar/.cache/glaurung/verify-85afee69/.venv \
  uv run --no-sync python tools/dectest.py \
  95_function_pointer_table:gcc:O0:dispatch_operation \
  95_function_pointer_table:gcc:O2:dispatch_operation \
  191_indirect_table_args:gcc:O0:t191_fold \
  191_indirect_table_args:gcc:O2:t191_fold --arch i386
```

The selection has no regression and moves only fixture 95 i386 O2 from fail
to pass; that one `arch_baseline.json` entry is ratcheted.

Commit `3e4c5242` closes the adjacent ordinary-call presentation defect. GCC
O2 fixture 191 pushes three arguments and then loads the indirect target from
an entry-frame slot. The backward scanner may now cross one memory load only
when its destination is the exact stable value consumed by the call target and
post-call cleanup independently proves the outgoing area. An unrelated load
still stops the scan. Removed pushes rebase the target load, so its frame slot
continues to name the same address. The release output removes the false
`local_3c[12]` object and renders the complete semantic call:

```c
var8 = ((long (*)(long, long, long))target)(var7, var8, var18);
```

Its positive and mismatched-target refusal tests, all seven owning cdecl tests,
all nine pre-existing cdecl integration tests, and the same four-cell i386
selection pass without regression. Fixture 191 i386 O2 remains an execution
failure because its indirect target and return type are still unrecovered; it
is an output-quality improvement, not a baseline movement. No DecBench or
Joern run was made.

The required post-source-commit Python gate was started from exact source
commit `3e4c5242` with a fresh release extension (SHA-256
`bb76986756adf5432ddaa1d20dd2f873b8860f8316100ab0601186ad39c4495e`).
It reached 11% and reproduced five existing failures: three static/frame stack
definedness failures and two CLI decompile-output failures. None exercises the
i386 fixture or cdecl call-argument path. The run was stopped once broadly red
instead of spending the remaining gate time on an unchanged decision; it is a
partial broad-gate attempt, not a full-green claim.

Commit `fded1081` closes fixture 191's remaining i386 O2 target boundary.
Stack promotion exposes the PIC table-base spill as an exact scalar store to a
promoted object, after the early table resolver has already run. A second
resolver stage now runs immediately after promotion and admits that reaching
value only when all of these facts agree:

- `ValueIdentities` marks the destination as a promoted stack object;
- `StackLocalFacts` supplies its authoritative extent;
- the store starts at that exact object and covers the complete extent; and
- no intervening unknown store, call, or indirect transfer invalidates it.

Partial stores and unknown intervening stores remain explicit. The exact
release output changes the raw input-image dereference into the declared table
entry while retaining the three already-recovered cdecl arguments:

```c
var8 = ((long (*)(long, long, long))(T191_OPS[var20]))(var7, var8, var18);
```

All 19 function-table tests, all 163 call-argument tests, the canonical AST
pass-order test, and the generated pass-reference tests pass. The exact i386
O0/O2 four-cell control selection reports no regressions and one improvement:
`191_indirect_table_args:i386:O2:t191_fold` moves from fail to pass, so that
single `arch_baseline.json` entry is ratcheted. The remaining table-call work
in this package is the distinct ARMv7/ARMv7-A32 O2 control and typing frontier;
the i386 target/argument execution gap is closed. No DecBench or Joern run was
made.

The repository-required Python gate was started from exact commit `fded1081`
with a fresh release extension (SHA-256
`7238be1fdc97e30fdbe51cefbeef680175524b65c7c50ba1ddc65949766ddde4`).
At 9% it had 603 passes and reproduced three known, unrelated
build-configuration failures: the static-executable canary `local_10` leak and
the static/frame-pointer undefined-local checks (`local_10` and `rbp`). It was
stopped after those failures made the broad gate decisively red; this is a
partial gate attempt, not a full-green claim.

Commit `61e26ad3` closes the remaining fixture-191 ARM table-call argument
cells. ARM PIC code forms the table base by adding a literal displacement to
the architectural PC value. Both demand discovery and the pre-SSA call-effect
proof now recognise that exact checked affine form, so all relocation-proven
table entries are analysed before dead-code elimination and their complete
AAPCS `r0`/`r1`/`r2` may-use set survives into argument reconstruction.
Unknown arithmetic continues to decline.

The observed-red demand and call-effect tests, all 20 function-table tests, all
17 direct-callee-contract tests, and all 163 call-argument tests pass. An exact
release sweep of the six previously failing Thumb/A32 cells reports six
improvements and no scoped regression. In particular, Thumb O2 now renders:

```c
ret = ((int (*)(int *, int, int))(T191_OPS[which]))(scratch, a, b);
```

The six `arch_baseline.json` entries are ratcheted. Together with `fded1081`,
fixture 191's relocation-proven table-call target and complete argument
contract now pass on every recorded architecture/optimisation cell. This does
not close unrelated ARM structuring, type, or indirect-transfer failures in
other fixture families.

The repository-wide Python gate was also started from a clean detached verifier
at exact source commit `61e26ad3`, after a fresh release extension build. It
reached 9% and reproduced the same three already-triaged failures: the
static-executable canary/interface leak for `local_10`, the corresponding
undefined `local_10`, and the frame-pointer undefined `rbp`. The run was stopped
once the broad gate was decisively red. This is a partial gate attempt, not a
full-green claim; no fixture-191 regression appeared before the stop.
