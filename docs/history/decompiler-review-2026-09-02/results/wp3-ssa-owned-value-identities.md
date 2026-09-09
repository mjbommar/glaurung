# WP3 SSA-owned value identities

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `3961771e` makes the authoritative `SsaInfo` snapshot own every opaque
`ValueId`. It deterministically allocates IDs from the sorted set of all SSA
definitions, uses, phi results, and phi inputs. Value numbering now carries
those exact IDs into `ValueIdentities`; it no longer allocates IDs according to
the order in which its LLIR traversal happens to encounter values.

This closes an authority seam in WP3 and prepares the remaining type-fact
migration. It does not complete WP3: most `TypeMapV` facts still use semantic
`SsaValue` keys, display-tag compatibility remains, and expression origins are
still incomplete.

## Focused Rust validation

Only tests owned by this change ran:

```text
cargo test --features python-ext --lib \
  ssa_value_ids_are_deterministic_and_cover_phi_graph --quiet
1 passed; 0 failed

cargo test --features python-ext --lib \
  opaque_ssa_identity_survives_llir_to_ast_lowering --quiet
1 passed; 0 failed

cargo test --features python-ext --lib opaque_value_ids_ --quiet
2 passed; 0 failed
```

The new SSA test independently recomputes a diamond CFG, checks deterministic
ID assignment, and proves coverage of ordinary definitions and uses plus the
phi result and both incoming values. The lowering test additionally proves
that `ValueIdentities` carries the exact ID assigned by the originating SSA
snapshot.

## Exact release and output checks

A detached clean worktree at `3961771e` produced a fresh release extension.
The build guard reported `fresh`, the import resolved inside that exact
worktree, and the native extension SHA-256 was
`00a43fb911bd8dbb42cc3a9cba8404d1e8ca8ea1f20d758afe07adf4594a92d4`.

Three symbols/PIE GCC-O2 canonical Hello cells passed across x86-64, AArch64,
and ARMv7. The directly adjacent
`174_float_compare_classify:gcc:O2:sign_bit_of_binary32` lane also passed. This
was a targeted cross-architecture checkpoint, not the complete Hello matrix.
No broad Rust suite, whole Python suite, fixture corpus, DecBench, or Joern ran.
The detached worktree was removed and `uv sync --locked` restored the main
checkout as the editable Python package.
