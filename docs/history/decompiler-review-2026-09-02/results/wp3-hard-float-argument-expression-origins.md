# WP3 hard-float argument expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `a756a6d5` gives each argument captured by the pure-VFP AAPCS32
hard-float producer the exact origin of its setup assignment. Distinct VFP
slots retain distinct owners, while the call statement continues to receive
the complete consumed-setup union.

The allocation proof is unchanged: the producer still requires a contiguous
VFP prefix, rejects mixed core/VFP setup without a recovered prototype, and
does not weaken any call or control boundary. This is provenance-only and does
not alter rendered or scored pseudocode.

The convention-generic recovered-layout path already owns prototype-proved
mixed-bank calls. The remaining call-argument expression producer is the
table-call reaching-value fallback, so WP3 remains open.

## Focused verification

The existing two-slot ownership case was strengthened and observed red before
repair: both recovered float expressions reported no origin instead of their
distinct `0x1010` and `0x1014` setup owners.

After repair:

```text
cargo test --features python-ext \
  attributed_pure_vfp_setup_folds_into_the_call_owner --lib
1 passed; 0 failed

cargo test --features python-ext 'ir::call_args::aapcs::tests::' --lib
4 passed; 0 failed

cargo test --features python-ext 'ir::call_args::tests::' --lib
111 passed; 0 failed; 4,249 filtered out; 0.20 seconds
```

A fresh isolated release build of exact commit `a756a6d5` passes the two
dedicated real ARM mixed hard-float tests:

```text
python/tests/test_cli_decompile.py::test_real_arm_mixed_hard_float_call_round_trip
python/tests/test_cli_decompile.py::test_real_arm_mixed_hard_float_spills_preserve_source_parameter_order
2 passed
```

The exact A32 `complex_float_multiply` O0/O2 canaries remain the same two known
fixture failures on parent and tip, with no scoped regression. The tip build
guard reports fresh with native SHA-256
`a3e9d409004bbff32e8e5e0cd9bdc84cc3ac351026b1dfdff5b4235ae5b942af`.
No full Rust, Python, fixture, architecture, or DecBench suite was run.

An earlier command created the isolated worktree but accidentally invoked
Maturin from `master`; that build was rejected before testing. All evidence
above comes from the subsequent build whose crate path and build guard identify
the detached `a756a6d5` worktree.

## Next boundary

Migrate the table-call fallback that synthesizes arguments from proven
enclosing reaching values. Preserve existing origin-bearing reaching
expressions, and prove that locally captured table-call setup continues through
the already-migrated recovered-layout path without duplicated ownership.
