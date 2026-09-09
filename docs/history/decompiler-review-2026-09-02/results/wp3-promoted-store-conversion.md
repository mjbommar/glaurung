# WP3 promoted-store conversion preservation

Commit `57a6b936` removes a one-use promoted scalar temporary without deleting
the assignment conversion that gave the value its source-language width. The
typed adjacent-value proof now carries an explicit integer `Cast` when a store
source is wider than, or has no exact width relative to, the authoritative
destination declaration. This turns the assignment into an expression at the
sole consumer while preserving truncation and signedness.

The transform remains fail-closed. It requires pipeline-owned promoted-object
identity, a scalar integer declaration whose width fits the store, one adjacent
use, no later use, and a deferable source without memory reads or unknown
effects. Boolean-like storage still requires an already bounded source because
an integer cast does not model `_Bool` normalization. The same proof now walks
recovered try and catch bodies.

On the direct GCC-O2 `cpp_exception` specimen, the handler improves from:

```c
int stack_0;
stack_0 = (0x2328 - exception_0);
return (unsigned long)((unsigned int)(stack_0));
```

to:

```c
return (unsigned long)((unsigned int)((0x2328 - exception_0)));
```

The rendered unsigned view is the existing return-ABI interpretation; the
four-byte assignment conversion is still represented by the inner AST cast and
therefore is not silently discarded.

## Focused evidence

The recovered-catch contract was observed red before the implementation:

```text
cargo test --features python-ext --lib \
  typed_scalar_store_preserves_truncation_when_folded_inside_a_catch
1 passed; 4,750 filtered out

cargo test --features python-ext --lib \
  typed_scalar_store_does_not_erase_a_wider_source_truncation
1 passed; 4,750 filtered out

cargo test --features python-ext --lib ir::copy_prop::adjacent::tests::
28 passed; 4,723 filtered out
```

An exact detached release build of `57a6b936` produced native SHA-256
`402864957b37a139705a086ac369178c51cad74e1a6c43468823b636d89bcca8`.
All four GCC/Clang O0/O2 `cpp_exception` execution cells pass, and the periodic
six-cell GCC symbols/PIE Hello checkpoint passes at O0 and O2 on x86-64,
AArch64, and ARMv7. No broad Rust, Python, fixture, architecture, DecBench, or
Joern suite ran.
