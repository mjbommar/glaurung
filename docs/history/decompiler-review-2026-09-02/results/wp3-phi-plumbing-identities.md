# WP3 phi-plumbing identities

Status: bounded WP3 semantic-reader migration landed at `a957c94c` on
`master`.

## Result

Live-in parameter discovery no longer decides whether an assignment is an
out-of-SSA phi copy by parsing `reg#version` display text when authoritative
identities are available. `architecturally_read_names` and
`phi_copy_operands` now receive the same `ValueIdentities` snapshot as the
parameter-slot consumer. A copy is plumbing only when both operands have exact,
canonical physical bases and those bases agree.

This matters because call annotations conservatively list every ABI argument
register as a may-use. A phi copy retained only by such a may-use is not a real
read by the current function and must not invent a source parameter. Opaque
presentation names previously hid that plumbing shape and incorrectly inferred
argument slot 3. The explicit no-sidecar API retains its compatibility parser.

The related phi-coalescing read classifier consumes the same identity-aware
walk, so both users continue to share one definition of an architectural read.

## Focused evidence

The new opaque-name regression was observed red before implementation:

```text
opaque_phi_copy_uses_identity_instead_of_display_spelling ... FAILED
opaque SSA phi plumbing is not an architectural read: {3}
```

After implementation:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  opaque_phi_copy_uses_identity_instead_of_display_spelling -- --test-threads=1
1 passed; 4,766 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib a_phi_copy_ -- --test-threads=2
2 passed; 4,765 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib coalesc -- --test-threads=4
49 passed; 4,718 filtered out
```

An exact detached release build of `a957c94c` produced native SHA-256
`adcfc4c55299b0b02d7c577d7781c8a1cf05cd72f5c8754d573fea1781925722`.
The loaded module path was the detached worktree's
`python/glaurung/_native.cpython-312-x86_64-linux-gnu.so`. Main and detached
`src/ir/value_number.rs` both had SHA-256
`d8574d5b5ae48c40903a5554470d1c1644425a4ec882541a77605d7e97e5ee6f`.
The harness's main-checkout timestamp guard therefore required its documented
stale-build override even though the detached source bytes and commit were
verified exactly.

One scoped `11_call_shapes:aarch64:O2` lane reported no regression. The
periodic symbols/PIE GCC Hello checkpoint also passed all six selected cells:
x86-64, AArch64, and ARMv7 at O0 and O2.

## Measurement boundary

Only the new regression, two nearest parameter controls, the 49-test named
coalescing filter, one AArch64 fixture lane, and six Hello cells ran. No broad
Rust or Python suite, fixture matrix, 419-pair identity sweep, DecBench, Joern,
GED, performance, or corpus-wide measurement ran. This closes one semantic
display-name reader; it does not complete WP3 or remove `tag_phys`.
