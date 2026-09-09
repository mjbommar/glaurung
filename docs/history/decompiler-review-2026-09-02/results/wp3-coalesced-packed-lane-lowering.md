# WP3 coalesced packed-lane lowering

Status: bounded WP3 output consumer migration landed at `27910f65` on
`master`.

## Result

Packed-dword concat lowering now classifies an operand through its one
unambiguous physical storage base rather than requiring one exact SSA version.
When phi-copy coalescing combines multiple non-interfering versions of the same
`xmmN_dM` or `vN_dM` lane, the lowering still emits the required 32-bit payload
cast followed by a 64-bit widening before shifting the high half.

This prevents C's 32-bit shift semantics from discarding the high payload.
Candidates spanning different lanes still decline and retain the conservative
unshifted form. The change does not reconstruct or merge lane values; the
separate vector-copy logic remains exact-version-sensitive.

## Focused evidence

The same-lane behavior contract was observed red before implementation: the
coalesced operands took the conservative path and lacked the required 64-bit
casts. After changing only the storage classifier:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  ir::ast::lower_ops::tests:: -- --test-threads=4
5 passed; 0 failed; 4,761 filtered out
```

That module includes the same-lane positive contract, a mixed-lane refusal,
the legacy spelling path, unknown-width refusal, and multi-output preservation.

An exact release build from detached commit `27910f65` imported
`/home/mjbommar/.cache/glaurung/verify-20364f46/python/glaurung/_native.cpython-312-x86_64-linux-gnu.so`
with SHA-256
`6f1b78bac66bbeb6209098a4f5b5b2f92e3e578cc51b78e0e11961d5c9f5efbd`.
The GCC-O2 and Clang-O2 fixture-197 lanes, each scoped to
`hfa197_make_pair2d` and `hfa197_make_tagged`, reported no regression. Six
symbols/PIE Hello controls also passed: x86-64 GCC, AArch64, and ARMv7 at O0
and O2.

## Measurement boundary

Only five Rust tests, two narrowly selected fixture lanes, and six Hello cells
ran. No broad Rust or Python suite, complete fixture matrix, DecBench, Joern,
GED, performance, or corpus-wide measurement ran. This closes one lowering
consumer, not WP3's identity lifecycle, `tag_phys` removal, or universal origin
attribution.
