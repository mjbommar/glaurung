# WP3 recovered throw values

Commit `716ccce5` extends the width-preserving promoted-value proof to recovered
throws. Exception recovery creates `Throw` after the ordinary typed
promoted-value pass has already run, so the renderer now reapplies that exact
proof at a named post-recovery boundary. A scalar storage assignment feeding
only the adjacent throw moves its declaration-proven conversion into the throw
expression and the fake local disappears.

This is not a throw-specific spelling heuristic. The existing transform still
requires pipeline-owned promoted-object identity, an authoritative integer
type compatible with the store width, adjacent single use, no later use, and a
source whose evaluation is safe to move. The store's integer conversion moves
with the expression, so removing the temporary cannot remove truncation or
signedness.

The exact GCC-O2 `cpp_exception` specimen now contains no artificial locals:

```c
int cpp_exception(int x) {
    try {
        if ((long)((int)(x)) < 0) {
            throw (int)(x);
        }
        return (unsigned long)((unsigned int)((x + 3005)));
    } catch (int exception_0) {
        return (unsigned long)((unsigned int)((0x2328 - exception_0)));
    }
}
```

## Focused evidence

The new throw contract was observed red before the implementation:

```text
cargo test --features python-ext --lib \
  typed_scalar_store_preserves_conversion_when_folded_into_throw
1 passed; 4,751 filtered out

cargo test --features python-ext --lib ir::copy_prop::adjacent::tests::
29 passed; 4,723 filtered out

pytest -q python/tests/test_pipeline_profile_report.py::\
test_real_profile_is_output_transparent_and_counts_all_object_parses
1 passed
```

An exact detached release build of `716ccce5` produced native SHA-256
`b519b8b8282412447a032fa4c8dd794fcaeb150cc522cbbfc955490bc11c1410`.
All four GCC/Clang O0/O2 `cpp_exception` execution cells pass. The periodic
six-cell x86-64/AArch64/ARMv7 O0/O2 Hello checkpoint passed on the immediately
preceding exact release increment and was not repeated for this exception-only
schedule change. No broad Rust, Python, fixture, architecture, DecBench, or
Joern suite ran.
