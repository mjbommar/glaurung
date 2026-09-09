# WP3 exception read census

Commit `29b202a9` closes two omissions in copy propagation's authoritative read
census. The structured walker treated both `TryCatch` and `Throw` as read-free
statements even though the propagation walkers already entered their values and
bodies. A single-use arithmetic result created inside a recovered catch was
therefore not eligible for the existing counted-expression proof, and a value
consumed by `throw` could be classified inconsistently by later cleanup.

The repair makes the shared read walker enter the try body, every catch body,
and a throw value. It adds no exception-name heuristic and weakens no alias or
side-effect gate. The direct GCC-O2 `cpp_exception` output loses the redundant
`rax_5` declaration and copy:

```c
catch (int exception_0) {
    stack_0 = (0x2328 - exception_0);
    return (unsigned long)((unsigned int)(stack_0));
}
```

At this commit, the remaining `stack_0` assignment is deliberate: its four-byte
store is the only explicit truncation fact on an otherwise widthless arithmetic
AST. Commit `57a6b936` subsequently closes that follow-up by materialising the
assignment conversion before removing the temporary; see
`wp3-promoted-store-conversion.md`.

## Focused evidence

```text
cargo test --features python-ext --lib \
  recovered_catch_reads_enable_single_use_expression_propagation
1 passed; 4,749 filtered out

cargo test --features python-ext --lib \
  throw_values_participate_in_the_copy_read_census
1 passed; 4,749 filtered out

cargo test --features python-ext --lib ir::copy_prop::tests::
38 passed; 4,712 filtered out
```

An exact detached release build of `29b202a9` produced native SHA-256
`2d6660e5b309636f93ba4f11a6a91d2c37aaf53e869a53e392bc3fa6410601a6`.
All four GCC/Clang O0/O2 `cpp_exception` execution cells pass. The periodic
six-cell GCC symbols/PIE Hello checkpoint also passes at O0 and O2 on x86-64,
AArch64, and ARMv7. No broad Rust, Python, fixture, architecture, DecBench, or
Joern suite ran.
