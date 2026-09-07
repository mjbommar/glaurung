# WP3 recovered call-layout origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commits `b6172031` and `a0917da5` make the convention-generic recovered-callee
layout folds transparent to statement origins without letting a specialized
layout proof degrade established argument recovery. Attributed ABI setup
assignments and proven live-in slots now participate in the fold, and every
removed setup owner is unioned into the surviving call.

The first implementation exposed a real ordering defect: once origin wrappers
became transparent, the specialized fold began consuming ARM hard-float frame
loads before the general backward argument scan could retain their source
parameter identity. The release output regressed from
`arm_hf_mixed_callee(7, measured, negate)` to a call through `local_c` and
`local_10`. The hardened boundary now enforces the helper's documented
contract: only pure setup expressions may be moved into the call. Load-valued
setups remain statement-rooted for the general fold. Pure promoted-local
definition chains may still be followed, but architectural VFP scratch is not
mistaken for a source spill.

This is a bounded WP3 consumer migration. It does not migrate cdecl32 or AAPCS
stack setup/removal, add expression origins, or complete authoritative SSA
identity through the AST.

## Evidence

The new tests were observed red before their production changes. They cover
origin-wrapped recovered layouts, an attributed mixed layout with a proven
live-in, a pure promoted-local definition chain, and refusal to consume an
attributed frame load. The complete call-argument module is green:

```text
cargo test --features python-ext ir::call_args:: -- --nocapture
114 passed; 0 failed
```

The release-built runtime checks cover both sides of the discovered trade:

```text
uv run maturin develop --release
uv run pytest -q \
  python/tests/test_cli_decompile.py::test_real_arm_mixed_hard_float_call_round_trip \
  python/tests/test_decompiler_guarded_call.py::test_guarded_call_select_retains_both_value_edges \
  python/tests/test_decompiler_emission_invariants.py::test_every_local_used_is_also_declared
10 passed
```

The complete stripped/debug differential remains byte-for-byte identical to
the preceding accepted tail-call boundary:

```text
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 17 improvements; 0 infrastructure problems
```

The complete Rust gate is green:

```text
cargo test --features python-ext
library: 4,282 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The mandatory whole Python suite improves the preceding accepted boundary by
one exact normalized node with no addition:

```text
215 failed; 4,590 passed; 77 skipped; 128 deselected; 876 xfailed
0 added failure nodes; 1 removed failure node
```

The removed node is
`test_guarded_call_select_retains_both_value_edges`. Relative to the initial
`b6172031` run, hardening removes the sole added ARM hard-float failure while
retaining that guarded-call improvement. A controlled release A/B reversing
only `b6172031` had already proved the original trade: the parent passed ARM
and failed guarded-call recovery, while the unhardened tip did the reverse.

## Next ordered increment

Continue the call-argument origin audit through the architecture-specific
setup/removal paths in `src/ir/call_args/cdecl32.rs` and
`src/ir/call_args/aapcs.rs`. Preserve exact consumed-origin unions and keep
memory-valued or phase-sensitive setup rooted unless the existing alias and
cleanup proofs authorize movement.
