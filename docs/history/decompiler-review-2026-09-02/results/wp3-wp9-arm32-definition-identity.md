# WP3/WP9 ARM32 definition identity

Date: 2026-09-05

Behavioral commits: `a8ba1b87`, hardened by `dcdc99cc`

## Defect

The target-aware SSA model canonicalized ARM32 `fp` and `r11` to one storage
identity, but value numbering consumed the canonical SSA base only for uses.
Definitions were reconstructed from their original spelling plus the numeric
SSA version. An A32 frame establishment therefore remained `fp = sp` while
every later frame-relative access became `r11#1`; the rendered function read a
value that no statement defined.

On the real GCC A32 O0 `03_loop_shapes::while_prefix` fixture this prevented
stack promotion and source-local recovery. The output declared `p`, `i`, and
`s`, but used an undefined `var0` as a raw frame base throughout the body.

## Change

The first implementation made `src/ir/value_number/tagging.rs` apply the exact
target-qualified `SsaValue` base and version to every definition. The required
def-use census showed that this was too broad: definition spelling is also a
compatibility boundary for non-ARM targets and synthetic definitions.

The hardened implementation in `dcdc99cc` keeps the established version-only
tagger and adopts the SSA side-car base only for ARM32 calling conventions and
only when the architecture-blind parent cannot express the target alias. This
is the narrow seam needed by `fp`/`r11`; x86, AArch64, synthetic, and missing
definition identities retain their prior behavior.

The focused unit reproduces the mixed ARM spelling directly: an `fp = sp`
definition and an `r11`-relative load must both become the same `r11#1` value.
This is a bounded WP3 identity handoff and WP9 machine-model consumer repair;
it does not complete general SSA invalidation, origin tracking, or migration of
all architecture facts.

## Real output

The repaired real fixture renders:

```c
int while_prefix(const int *p) {
    int i = 0;
    int s = 0;
    while (i <= 7) {
        if (0 <= p[i]) {
            break;
        }
        s += p[i];
        i += 1;
    }
    return ((10 * s) + i);
}
```

The undefined frame base and all raw frame dereferences are gone.

## Validation

- `cargo test --features python-ext ir::value_number::tests::`: 44 passed.
- `cargo test --features python-ext ir::ssa::`: 12 passed.
- `cargo test --features python-ext ir::stack_locals::tests::`: 85 passed.
- `uv run --no-sync pytest -q python/tests/test_decompiler_arm32_semantics.py`:
  12 passed, including the source-to-QEMU execution differential.
- `uv run maturin develop --release`: completed before Python validation.
- `cargo test --features python-ext`: 4,200 library tests passed, zero failed,
  and five ignored; all integration and documentation targets passed. The long
  identity-retrieval target independently reports 44 passed and ten ignored.
- The complete six-test def-use census reports four passed and two ratchets
  red. The same 27 required-function regression list reproduces at both
  `4fa0b12f` and its parent `ce3fd28a`, before the ARM32 repair. The second red
  ratchet records large pre-existing improvements (for example aggregate lane
  totals fall from 140 to 77 for Clang O0 and from 7,898 to 6,613 for Rust O0).
  The baseline was not rewritten because the remaining renamed/new findings
  require their own reconciliation.

The whole Python release gate remains separate WP10 evidence and is not claimed
by this focused increment.
