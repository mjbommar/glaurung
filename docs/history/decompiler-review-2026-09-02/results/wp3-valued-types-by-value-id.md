# WP3 valued types keyed by stable identity

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `1e43c1b9`, followed by shipped-build helper cleanup at `0d9e54ae`,
migrates every persisted `TypeMapV` fact to the opaque `ValueId` owned by its
originating `SsaInfo` snapshot. This includes ordinary recovered type facts,
parameter refinements, and the strong-refinement set. `TypeMapV` retains a
snapshot-derived reverse map only where ABI projection must recover the
semantic live-in value.

The production numbered-type merge now reads `TypeMapV` by the exact
`ValueId` carried through `ValueIdentities`. It no longer performs that join
through a display-shaped value or a separately allocated identity. Temporary
maps used while walking the SSA graph remain keyed by `SsaValue`; those are
local algorithms rather than persistent cross-pass fact stores.

This materially advances WP3 and gives WP6 type recovery a stable fact key. It
does not complete either package: expression-origin coverage, compatibility
display tags, and the general constraint type solver remain open.

## Focused validation

```text
cargo test --features python-ext --lib \
  valued_type_facts_use_snapshot_owned_value_ids --quiet
1 passed; 0 failed

cargo test --features python-ext --lib definition_width --quiet
8 passed; 0 failed

cargo test --features python-ext --lib ir::types_recover::tests --quiet
88 passed; 0 failed

cargo test --features python-ext --lib \
  ir::types_recover::result_hint::tests --quiet
4 passed; 0 failed
```

The new test inspects the store directly, proves that its key is the exact ID
assigned by `SsaInfo`, and verifies that both semantic and ID lookup reach the
same fact. The owning type rules cover pointer, scalar, parameter, return, and
architecture-specific recovery behavior.

## Exact release and output checks

A detached clean worktree at `0d9e54ae` produced a fresh release extension.
The build guard reported `fresh`, import resolved inside that exact worktree,
and the native extension SHA-256 was
`cf6d57214f4cbf2e8e3a028199f5e1b3620506b9594f88ce4d0eb0059abfed44`.

Three symbols/PIE GCC-O2 canonical Hello cells passed across x86-64, AArch64,
and ARMv7. The adjacent
`174_float_compare_classify:gcc:O2:sign_bit_of_binary32` lane also passed. This
was a narrow cross-architecture checkpoint, not the complete Hello matrix.
No broad Rust suite, whole Python suite, fixture corpus, DecBench, or Joern ran.
The detached worktree was removed and `uv sync --locked` restored the main
checkout as the editable Python package.
