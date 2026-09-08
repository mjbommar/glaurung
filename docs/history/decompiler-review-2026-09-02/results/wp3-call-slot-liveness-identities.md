# WP3 call-slot liveness identities

Status: bounded production consumer migration landed at `541a6e5b` on
`agent/wp5-next-switch`.

## Result

Call-argument read/write liveness, enclosing-scope clobber tracking, reaching
definitions, loop-entry constancy, table-call backfill, and mixed-layout
backfill now classify ABI slots from `ValueIdentities`. An opaque value can
name its exact integer argument slot without ABI-like display spelling, while
a value merely spelled `rdi#version` cannot impersonate that slot.

The storage-class decision uses every SSA candidate. Multiple versions that
all agree on one ABI slot or on known non-argument storage remain usable;
candidates that disagree between slots fail closed. Values with no SSA
candidate are synthesized AST locals and remain known non-machine storage.
No-sidecar compatibility entry points retain the prior spelling-based path.

## Focused evidence

```text
cargo test --features python-ext --lib \
  ir::call_args::tests::argument_slot_liveness_uses_exact_identity_not_display_spelling \
  -- --exact
1 passed; 0 failed; 4,473 filtered out

cargo test --features python-ext --lib ir::call_args -- --nocapture
133 passed; 0 failed; 4,341 filtered out
elapsed 11.8 s including incremental compilation

uv run maturin develop
completed

uv run python tools/dectest.py \
  189_effectful_select:gcc:O2:se189_select_call --show
1 of 838 lanes selected; no regression in scope
```

Build fingerprint: commit `541a6e5b`, debug Cargo/maturin profile, CPython
3.14, and `python-ext` enabled.

The first exact fixture run exposed a real regression: treating multi-version
`rsp` as unknown blocked every argument slot and erased one branch call's
arguments. The candidate-set storage classification repaired it; the same
fixture then returned to its passing baseline. This rejected intermediate was
not committed.

## Measurement boundary

The owning Rust module and one directly related effectful-call C fixture lane
passed. No broad Rust/Python suite, fixture matrix, DecBench, Joern, GED,
performance, or corpus-wide execution measurement ran.

## Remaining scope

This removes slot liveness and enclosing reaching-state from the production
semantic-name surface. Stack-area recovery, loop-carried slot discovery, and
the remaining AAPCS/cdecl layout readers remain separate WP3 migrations. WP3
remains open.
