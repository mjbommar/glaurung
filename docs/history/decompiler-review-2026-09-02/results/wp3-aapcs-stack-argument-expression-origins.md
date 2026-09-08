# WP3 AAPCS stack-argument expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `76753c05` gives each expression recovered from the generic AAPCS
outgoing stack area the exact origin of its value store. The store owner
survives later scratch-register substitution and reaches the corresponding
source-ordered call argument. Other setup and call owners remain statement-level
provenance.

The recognition proof is unchanged: recovery still requires a locked integer
layout, one nearest four-byte store for every expected offset, no duplicates or
gaps, and no intervening call, control boundary, stack-pointer write, or
unproved memory effect.

This closes the generic SysV/AAPCS stack-area portion of call-argument
expression attribution. Specialized recovered-layout, cdecl32, hard-float,
and table-call producers remain open, so WP3 is not complete.

## Focused verification

The attributed helper test was observed red before the production change:

```text
attributed_aapcs_stack_area_is_recognized
left: [Const(5), Const(6)]
right: values owned by stores 0x1024 and 0x1020
```

After the change:

```text
cargo test --features python-ext attributed_aapcs_stack_area_is_recognized --lib
1 passed; 0 failed

cargo test --features python-ext 'ir::call_args::aapcs::tests::' --lib
4 passed; 0 failed

cargo test --features python-ext \
  recovered_aapcs_layout_folds_reused_core_registers_and_stack_suffix --lib
1 passed; 0 failed

cargo test --features python-ext 'ir::call_args::tests::' --lib
111 passed; 0 failed; 4,249 filtered out; 0.21 seconds
```

The end-to-end test proves all four stack suffix expressions keep their
distinct store owners after scratch-register substitution.

The exact real-binary comparison used the eight-argument `call_into_spill`
canary across legacy and current ARM32 lifters. Parent and isolated tip report
the identical verdict map:

```text
uv run python tools/dectest.py '11_call_shapes:*:*:call_into_spill' \
  --arch armv7 --arch armv7_a32 --jobs 4 --full
armv7 O0 fail; armv7 O2 pass; armv7_a32 O0 pass; armv7_a32 O2 pass
```

The `armv7:O0` baseline regression predates this change and remains open; this
increment neither introduces nor repairs it. The tip build guard reports fresh
with native SHA-256
`692c84ee6f809afd2fb1255904ecbaf5cf3c97c2b76de434c4b8dd4ccb2081c6`.
No full Rust, Python, fixture, architecture, or DecBench suite was run.

## Next boundary

Audit the specialized recovered-layout producer next. Attach exact setup
owners to each synthesized argument expression while preserving its existing
layout, purity, live-in, and ambiguity refusals. Keep cdecl32, hard-float, and
table-call producers as separately proved increments.
