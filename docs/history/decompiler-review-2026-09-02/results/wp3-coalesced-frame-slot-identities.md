# WP3 frame-slot typing matches complete identity sets

Status: bounded WP3 semantic-reader migration landed at `31f8c3a6` on
`master`.

## Result

Spill-slot pointer propagation now represents an attributed frame coordinate
with its complete nonempty SSA candidate set. A store and reload whose frame
bases carry the same coalesced set can therefore be recognized as the same
slot, allowing pointer evidence from the reload to reach the spilled source
parameter.

This does not collapse frame coordinates merely because they share `rbp`,
`rsp`, or another architectural spelling. Different SSA versions remain
different keys, mixed physical bases decline, and the spelling-only behavior
is confined to the explicit compatibility path without identity metadata.

## Focused evidence

The equal-coalesced-set regression was observed red before implementation:

```text
spill_pointer_crosses_equal_coalesced_frame_identities ... FAILED
expected the spilled rdi value to recover a pointer type
```

After implementation, both the positive case and the existing different-SSA-
version refusal pass. The complete focused type-recovery module also passes:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext ir::types_recover::tests --lib
91 passed; 0 failed; 4,680 filtered out; finished in 0.21s
```

An exact detached release build of `31f8c3a6` produced native SHA-256
`0d417d49aa7aee7a9c4b37ef7235cb3ca357a34c55ddb95de6384e6e9d133b1b`.
The build guard reported it fresh. All four GCC/Clang O0/O2 lanes of fixture
`09_memory_effects` retained their baselined verdicts without regression, and
the periodic symbols/PIE Hello checkpoint passed x86-64, AArch64, and ARMv7 at
O0 and O2.

## Measurement boundary

Only the 91 type-recovery tests, four memory-effect fixture lanes, and six
Hello cells ran. No broad Rust or Python suite, complete fixture matrix,
cross-corpus sweep, DecBench, Joern, GED, or performance run was used. This
closes one identity consumer; WP3 remains open.
