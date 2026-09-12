# WP3 loop-entry coalescing accepts same-storage identities

Status: bounded WP3 semantic-reader migration landed at `7e97c4c8` on
`master`.

## Result

Loop-entry copy coalescing now accepts a pipeline-owned value that represents
multiple SSA versions of one unambiguous physical carrier. The structural
proof can therefore remove a dead entry copy even when prior legal phi/copy
coalescing has already made the loop carrier non-exact.

Mixed physical storage remains a refusal, as do missing identity metadata,
protected source locals, incompatible types, surviving source uses, gotos, and
control-flow shapes that can bypass the copy. Successful mutation continues to
publish its rename map so the identity sidecar unions the removed seed into the
surviving carrier.

## Focused evidence

The same-`rbx` two-version regression was observed red before implementation:

```text
coalesced_same_storage_identity_authorizes_loop_entry_coalescing ... FAILED
left: None
right: Some(Phys("opaque-carrier"))
```

After implementation:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext ir::latch_predicate::tests --lib
17 passed; 0 failed; 4,756 filtered out; finished in 0.00s
```

This includes the existing mixed-`rbx`/`rcx` refusal. An exact detached
release build of `7e97c4c8` produced native SHA-256
`16f3e6a082c7357d4083ab61fab91774a76f92b5ff3c74d6a5e55dd4f8356303`.
The build guard reported it fresh. All 12 lanes in `@loops` passed without a
scoped regression, and the periodic symbols/PIE Hello checkpoint passed
x86-64, AArch64, and ARMv7 at O0 and O2.

## Intentional exact boundaries

The adjacent audit retained three exact-identity readers:

- callee-save deletion requires one version-zero entry value;
- packed-vector reconstruction requires one concrete whole-register version;
- DWARF register-local attribution requires one value over the declared live
  range.

Broadening any of these to same-storage membership would delete source state,
invent a vector lifetime, or merge distinct optimized local lifetimes.

## Measurement boundary

Only the 17 latch-predicate tests, 12 loop fixture lanes, and six Hello cells
ran. No broad Rust or Python suite, complete fixture matrix, cross-corpus
sweep, DecBench, Joern, GED, or performance run was used. This closes one
identity consumer; WP3 remains open.
