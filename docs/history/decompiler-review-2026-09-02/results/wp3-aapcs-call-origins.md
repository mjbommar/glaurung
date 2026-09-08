# WP3 AAPCS call-argument origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `e403de27` completes the architecture-specific AAPCS portion of the WP3
call-argument origin audit. Attributed direct calls retain locked core and
hard-float prototype layouts; attributed pure-VFP setup folds into the call
with exact owner union; attributed outgoing stack stores participate in the
existing exact-area proof; and phase-sensitive stack reads still see
attributed stack adjustments and remain statement-rooted.

This migration changes real output because origin carriers previously hid
semantic call and setup statements. Two ARM32 `rb_validate` variants now retain
the three arguments to `memset`, and stripped Clang O2
`mv203_by_value_narrow` recovers the by-value narrow aggregate arguments instead
of inventing `arg6` and `arg7`.

The ABI and safety policies are unchanged: mixed hard-float ordering still
requires a prototype, stack suffixes still require an exact locked layout and
contiguous four-byte area, control or memory boundaries still reject the
candidate, and stack-coordinate phase changes still prevent unsafe hoisting.

## Evidence

Three focused ownership/visibility tests were observed red before the
production change. They cover attributed locked contracts, pure VFP setup and
call ownership, and an attributed AAPCS stack area. The focused and complete
call-argument modules pass:

```text
cargo test --features python-ext ir::call_args::aapcs::tests:: -- --nocapture
4 passed; 0 failed

cargo test --features python-ext ir::call_args:: -- --nocapture
120 passed; 0 failed
```

All release-built real ARM checks pass:

```text
uv run maturin develop --release
uv run pytest -q \
  python/tests/test_cli_decompile.py::test_real_arm_mixed_hard_float_call_round_trip \
  python/tests/test_cli_decompile.py::test_real_arm_mixed_hard_float_spills_preserve_source_parameter_order \
  python/tests/test_decompiler_emission_invariants.py::test_every_local_used_is_also_declared
10 passed
```

The complete stripped/debug differential adds one improvement with no
regression or infrastructure problem:

```text
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 18 improvements; 0 infrastructure problems
```

The added improvement is
`203_string_move_copies:clang:O2strip:mv203_by_value_narrow`.

The complete Rust gate is green:

```text
cargo test --features python-ext
library: 4,287 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The mandatory whole Python suite improves the preceding accepted boundary by
two exact normalized nodes with no addition:

```text
211 failed; 4,594 passed; 77 skipped; 128 deselected; 876 xfailed
0 added failure nodes; 2 removed failure nodes
```

Both removed nodes are the native-executed ARM32 O2 `rb_validate` round trip,
for `armv7` and `armv7_a32`. A controlled release A/B reversed only
`e403de27`: both Python nodes failed at the parent because `memset` had no
recovered arguments, and the stripped fixture emitted
`mv203_consume_narrow(arg6, arg7)`. The exact source hashes were restored and
the rebuilt tip passed both Python nodes and changed the fixture from fail to
pass.

## Next ordered increment

The convention-generic, cdecl32, and AAPCS call-argument surfaces are now
migrated. Re-run the enabled semantic-consumer audit and take the next bounded
raw-statement consumer before expression ownership. Do not infer WP3 completion:
multi-output SSA identity, expression origins, structured line mappings, and
remaining AST consumers are still open.
