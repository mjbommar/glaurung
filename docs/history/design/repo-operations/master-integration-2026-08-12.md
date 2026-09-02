# Integrating `codex/primary-dirty-worktree-20260811` onto master

> **Kind:** record · **Date:** 2026-08-13

*Written 2026-08-12, when the branch was committed and pushed but deliberately
NOT merged. This says exactly what remains and why it is a port rather than a
merge.*

> **RESOLVED, later the same day.** The port below was carried out: master
> carries the work as `5e24383` (session decompiler work), `b4c7179` (150
> curriculum fixtures + the guarded-capture repair) and `781e62c` (the
> regenerated 186-fixture baseline). Step 5's acceptance test was run and the
> baseline delta contained only the listed improvements. The plan is kept
> because the three hand-ported conflicts in the table are the parts a future
> reader will otherwise re-derive, and because it records what the branches
> still lying around were for. Nothing here is outstanding.

## State

* The work is committed as one change and pushed:
  `origin/codex/primary-dirty-worktree-20260811`.
* It is **not** on master. Master is 155 commits ahead of the branch's base and
  has independently rewritten several of the same files.

## Why a textual merge is the wrong tool

Every file the session AUTHORED merges cleanly:

    src/ir/lift_x86.rs        src/ir/abi.rs           src/ir/got_fold.rs
    src/ir/pass_stats.rs      src/analysis/elf_got.rs src/debug/dwarf_signatures.rs
    src/python_bindings/debug.rs
    tools/{dectest,arch_roundtrip,diff_decompile}.py
    tests/decompiler_fixtures/{manifest.py,sets.toml}

All 46 conflicts are elsewhere. Most are stale uncommitted work that was already
in the tree when the session started and that master has since superseded — those
resolve by taking master. Three are NOT resolvable that way, because master
reworked the very functions this branch changed, using abstractions the branch
does not have:

| file | this branch | master |
| ---- | ----------- | ------ |
| `ir/value_number.rs` | `ssa_unifies_aliases`, so the keep-bare rule fires only for aliases SSA does not already unify | an `ins.op.returned_value()` guard, exempting the explicit-return edge |
| `ir/types_recover.rs` | `float_argument_bank_slot(cc, …)`, generalising the VFP live-in scan to x86-64 SSE | `use_is_proven_input(&op, use_index)`, a new proven-input model, still ARM-only |
| `ir/ast.rs`, `ir/call_args.rs`, `python_bindings/ir.rs` | float lowering, `NumericConvert`, the capture repair | ~6 400 added lines across the same regions |

`CallEffects` has also grown four fields on master (`result_is_source_value`,
`proven_args`, `args_are_exact`, `is_tail_call`), which the branch's ABI work
predates.

Both sides are addressing overlapping concerns by different routes. A textual
resolution would compile and would silently keep one side's fix and drop the
other's — the failure mode this project's baselines exist to catch, and which no
baseline can catch here, because the merged code's behaviour matches neither
side's recorded baseline.

## The port, in order

1. Branch from master.
2. Apply the clean-merging files as-is. That is most of the value: the whole x86
   scalar-float lifter, the GOT fold, the DWARF signature reader, the harness
   fixes, the six fixtures.
3. Re-express three changes against master's current model:
   * the keep-bare narrowing in terms of `returned_value()`;
   * the SSE parameter bank in terms of `use_is_proven_input`;
   * the ABI call-result selection against the wider `CallEffects`.
4. Re-apply the `ast.rs` float lowering and `NumericConvert` by hand — master
   rewrote the surrounding renderer.
5. Regenerate `baseline.json`, and diff the result against MASTER's committed
   baseline. That delta is the port's true effect and must contain only the
   improvements listed in the branch's commit message.
6. Run `arch_roundtrip.py --check` for the same reason.

Step 5 is the acceptance test. Refreshing a baseline without it would record the
port's mistakes as expected behaviour.
