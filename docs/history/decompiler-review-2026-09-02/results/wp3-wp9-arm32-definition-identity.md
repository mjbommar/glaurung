# WP3/WP9 ARM32 definition identity

Date: 2026-09-05

Behavioral commit: `a8ba1b87`

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

`src/ir/value_number/tagging.rs` now applies the exact target-qualified
`SsaValue` base and version to definitions, matching the existing use-side
contract. `src/ir/value_number.rs` passes that identity directly from the SSA
side car instead of passing only its version.

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

The complete Rust and Python release gates remain separate WP10 evidence and
are not claimed by this focused increment.
