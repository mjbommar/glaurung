# WP3 vector-address origins

Date: 2026-09-09

Source commit: `e709c0a0`

## Change

Wide-vector copy recovery now compares lane addresses through expression-origin
wrappers. Four exact adjacent dword loads and stores can therefore still be
rejoined into one readable 16-byte load/store pair after instruction origins
have been attached.

The fold also unions expression origins from every consumed lane into the two
surviving statements. Previously it merged statement owners only, so accepting
attributed addresses without this second change would have silently discarded
the owners of lanes one through three.

This closes one bounded WP3 expression-consumer omission. Universal expression
attribution remains open.

## Focused validation

All commands used `TMPDIR=/home/mjbommar/.cache/glaurung/tmp`.

The new contract was observed red first: the eight attributed lane operations
remained unrecovered because `adjacent_address` matched the raw wrapper rather
than its semantic `Lea`.

```text
cargo test --features python-ext --lib \
  ir::vector_copy::tests::attributed_lane_addresses_rejoin_and_union_every_consumed_owner \
  -- --exact
1 passed; 0 failed; 4,729 filtered out

cargo test --features python-ext --lib ir::vector_copy::tests::
10 passed; 0 failed; 4,720 filtered out
```

A detached clean worktree at `e709c0a0` built the release extension. Its build
guard reported `fresh` with native SHA-256
`26041bd3edac08524686f32f66455d51c4e8abb7edea743cfcea810a9abb5b6a`.
The directly affected transport canary passed:

```text
uv run python tools/dectest.py \
  188_vector_transport:clang:O2:vt188_copy_forward --full --show
188_vector_transport:clang:O2:vt188_copy_forward  pass
SCOPED: 1 lane of 838; no regressions in scope
```

The three O2 symbols/PIE Hello cells on x86-64, AArch64, and ARMv7 passed on
the recent exact release checkpoint at `d68b005f`; this vector-only increment
did not redundantly rerun them.

No broad Rust suite, Python suite, fixture corpus, DecBench run, or Joern run
was performed.

## Follow-on: attributed lane values

Commit `6490fc7d` closes the two adjacent expression shapes. Origin wrappers
around the complete lane dereference and around the lane register stored no
longer hide an otherwise exact four-lane transport. As with attributed
addresses, the surviving wide statements receive the union of all consumed
expression owners.

The new contract was observed red first with all eight lane operations left
unrecovered. Focused validation:

```text
cargo test --features python-ext --lib \
  ir::vector_copy::tests::attributed_lane_values_rejoin_and_union_every_consumed_owner \
  -- --exact
1 passed; 0 failed; 4,730 filtered out

cargo test --features python-ext --lib ir::vector_copy::tests::
11 passed; 0 failed; 4,720 filtered out
```

A detached clean worktree at `6490fc7d` built the release extension. Its build
guard reported `fresh` with native SHA-256
`0966d1e2352bd1940aa6487675a017e2cbbdfd5635c60c2e6a4204dbacccc419`.
The exact `188_vector_transport:clang:O2:vt188_copy_forward` canary passed.
No broad suite or corpus ran.
