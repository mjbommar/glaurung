# WP3 stable definition widths

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `d1eec606` makes machine definition width the first production type fact
keyed by the opaque `ValueId` introduced in `e633ca41`. Value numbering attaches
each proved operation or intrinsic-output width to its stable identity. The
DecBench declaration merge now reads that identity-owned fact rather than
trusting the width stored under a rendered `VReg` name.

The join is conservative. A coalesced value retains a width when every stable
ID agrees; missing evidence or conflicting widths state nothing. The existing
name-keyed width map remains temporarily as a compatibility and pipeline
transport bridge, but it is no longer the production authority for this merge.

This advances both WP3 stable identity and WP6's requirement to key type facts
by stable values. It does not complete the general constraint solver or remove
`tag_phys`.

## Focused Rust validation

```text
cargo test --features python-ext --lib definition_width --quiet
8 passed; 0 failed

cargo test --features python-ext --lib opaque_value_ids_ --quiet
2 passed; 0 failed

cargo test --features python-ext --lib ir::value_number::tests --quiet
63 passed; 0 failed

cargo test --features python-ext --lib python_bindings::ir::type_maps::tests --quiet
25 passed; 0 failed
```

The new adversarial contract supplies an incorrect eight-byte compatibility
width under an opaque display name while its stable identity owns the proved
four-byte width. Production-style merging chooses four bytes. Coalesced IDs
with equal widths retain the fact, while a conflicting width makes the query
decline.

## Exact release and output checks

A detached clean worktree at `d1eec606` built the release extension. Its build
guard reported `fresh`, package import resolved inside that exact worktree, and
the native extension SHA-256 was
`f5102b4881b8959ea7431684e86b9d6706946040f28719da89d6eac1f82051bc`.

Six canonical dynamic Hello cells passed: symbols/PIE at O0 and O2 for GCC
x86-64, GCC AArch64, and GCC ARMv7. This was a targeted cross-architecture
checkpoint, not the complete 72-cell grid. The directly affected
`174_float_compare_classify:gcc:O2:sign_bit_of_binary32` fixture also passed.
The fixture command used `--allow-stale` only because its mtime check compared
the exact detached extension with the shared main checkout; the clean-worktree
build guard and printed import path independently established the tested build.

No broad Rust suite, whole Python suite, fixture corpus, DecBench, or Joern run
was performed. The detached worktree was removed and `uv sync --locked`
restored the main checkout as the editable Python package.
