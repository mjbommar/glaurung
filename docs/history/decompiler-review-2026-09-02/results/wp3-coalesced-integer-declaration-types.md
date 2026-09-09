# WP3 coalesced integer declaration types

Status: bounded WP3 output consumer migration landed at `20364f46` on
`master`.

## Result

The shared integer-declaration query now recognizes a pipeline-owned value
whose coalesced SSA candidates all retain one canonical physical storage base.
That value may use its recovered integer signedness and width instead of
falling back to a machine-word `long` merely because phi-copy coalescing made
its exact SSA identity unavailable.

The proof remains storage-specific. Candidates spanning different physical
bases still decline and keep the conservative machine-word declaration. This
does not merge SSA versions, infer a type from a display name, or relax the
separate parameter and promoted-stack-object role checks.

The query is shared by final declaration spelling, contextual widening,
constant folding, and typed simplification, so the change also keeps those
representation-boundary decisions aligned with the emitted C type.

## Focused evidence

The positive behavior contract was observed red before the implementation:
the coalesced same-`rax` value returned `Some((true, 8))` instead of its
recovered `Some((false, 4))`. After replacing only the identity-ownership gate,
the positive contract and a mixed-`rax`/`rbx` refusal pass.

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  ir::ast::return_ctype::tests:: -- --test-threads=4
8 passed; 0 failed; 4,752 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib ir::widen::tests:: -- --test-threads=4
25 passed; 0 failed; 4,735 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib ir::const_fold::tests:: -- --test-threads=4
82 passed; 0 failed; 4,678 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  ir::typed_simplify::tests:: -- --test-threads=4
7 passed; 0 failed; 4,753 filtered out
```

An exact release build was produced from detached commit `20364f46`. The
imported native module was
`/home/mjbommar/.cache/glaurung/verify-20364f46/python/glaurung/_native.cpython-312-x86_64-linux-gnu.so`
with SHA-256
`f6ed2679922247c22f3d1c4dee11f69930cb3df0a4f4dec8931d11f6afe102a7`.
Six symbols/PIE Hello controls passed against that artifact: x86-64 GCC,
AArch64, and ARMv7 at O0 and O2.

The attempted fixture-194 narrow-return check is not counted as evidence. Its
isolated worker loaded a mismatched Python/native package context and stopped
with `AttributeError: module 'glaurung._native' has no attribute 'similarity'`.
The detached artifact itself exposes `similarity`, and the six direct pytest
controls imported it successfully, so this was a harness-environment failure,
not a decompiler verdict.

## Measurement boundary

Only the four directly affected Rust modules and six Hello cells ran. No broad
Rust or Python suite, fixture matrix, DecBench, Joern, GED, performance, or
corpus-wide measurement ran. This closes one declaration/type consumer, not
WP3: remaining identity consumers still require individual semantic
classification, and origin/identity lifecycle exit criteria remain open.
