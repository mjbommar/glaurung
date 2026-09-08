# WP3 SysV stack-argument expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `5f8dec01` extends expression attribution through both generic SysV
AMD64 stack-argument forms in `src/ir/call_args.rs` and
`src/ir/call_args/fold_one_call.rs`.

For a preallocated outgoing area, each recovered argument now owns the exact
store that supplied its value. For a lowered balanced push pair, the recovered
argument likewise owns only its value store. Stack allocation, alignment, call,
and cleanup instructions remain in the call statement's origin union; they are
not incorrectly assigned to the value expression.

This is intentionally provenance-only. It does not alter rendered or scored
pseudocode. AAPCS stack arguments and the specialized recovered-layout,
cdecl32, hard-float, and table-call producers remain separate expression-origin
migrations, so this increment does not complete call-argument attribution or
WP3.

## Focused verification

Both ownership assertions were observed red before the production change:

```text
sysv_folds_contiguous_preallocated_outgoing_stack_arguments
left: None; right: Some(OriginSet { addresses: [0x1020] })

sysv_balanced_stack_argument_keeps_only_its_value_store_owner
left: None; right: Some(OriginSet { addresses: [0x1104] })
```

After the change, the two exact tests pass and the touched module remains
green:

```text
cargo test --features python-ext 'ir::call_args::tests::' --lib
111 passed; 0 failed; 4,249 filtered out; 0.20 seconds
```

The real-binary canary is `call_into_spill`, the fixture-11 caller that passes
eight arguments and therefore exercises the SysV stack suffix. The clean
parent release extension and an isolated release build of exact commit
`5f8dec01` both report:

```text
uv run python tools/dectest.py '11_call_shapes:*:*:call_into_spill' \
  --jobs 4 --full
clang O0 pass; clang O2 pass; gcc O0 pass; gcc O2 pass
4 lanes; no scoped regressions
```

The tip build guard reports fresh with native SHA-256
`18dd2b43b395ced7a7e1e57894e383071a98677ca7dcbce5eb2754abdd016329`.
No full Rust, Python, fixture, architecture, or DecBench suite was run at this
bounded boundary.

## Next boundary

Migrate the generic AAPCS stack-area producer under the same ownership rule:
the value store belongs to the argument expression, while allocation and
cleanup remain call-statement provenance. Then continue through specialized
recovered-layout and architecture-specific producers without weakening their
existing ABI proofs.
